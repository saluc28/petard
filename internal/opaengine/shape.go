package opaengine

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
)

// This file recognizes the shape of the request: which part of input is the
// subject, which the action, which the resource.
//
// Nothing here imposes a convention. Rego lets an author write the request any
// way they like, and that freedom is the reason to use Rego instead of a
// language that fixes the shape and gives formal verification in exchange. So
// the recognizers read what is there, in order of how much the evidence is
// worth, and whatever they conclude carries the level it was concluded at.

// Confidence is how much a shape is worth, on a scale of A to E.
//
// It travels with the shape and into the exported graph, because an edge
// derived from a guess about names must not look, to whoever reads the graph,
// like one derived from a declaration.
type Confidence int

const (
	// ConfidenceNone is level E: nothing recognized the request, so only the
	// syntactic level of the analysis holds.
	ConfidenceNone Confidence = iota

	// ConfidenceNames is level D: the names of the fields look like a subject
	// or an action. It is a guess, and it says so.
	ConfidenceNames

	// ConfidenceDomain is level C: a known convention of a specific domain,
	// such as a Kubernetes admission review.
	ConfidenceDomain

	// ConfidenceAuthZEN is level B: the request has the shape the AuthZEN
	// Authorization API standardizes, subject, action, resource and context.
	ConfidenceAuthZEN

	// ConfidenceDeclared is level A: the request is declared rather than
	// recognized, by the policy author with a METADATA schemas annotation or by
	// whoever deploys the policy, who builds the request and knows which part of
	// it names the requester. OPA takes a declaration of the input from either
	// place, an annotation or the command line (opa eval --schema,
	// cmd/eval.go:289 at v1.20.2).
	ConfidenceDeclared
)

// ErrBadSubject is returned when a declared subject is not a path into the
// request.
var ErrBadSubject = errors.New("opaengine: the subject is not a path into input")

// ErrSubjectNotRead is returned when no decision reads the declared subject.
//
// A declaration that matches nothing is a typo worth stopping for, the same way
// an entrypoint that names no rule is: a request that fixes a field nobody reads
// asks every question about nobody in particular, and would report the answer
// as one about a principal.
var ErrSubjectNotRead = errors.New("opaengine: no decision reads the declared subject")

// String returns the level as A to E, because that is what ends up in a report
// and in the graph.
func (c Confidence) String() string {
	switch c {
	case ConfidenceDeclared:
		return "A"
	case ConfidenceAuthZEN:
		return "B"
	case ConfidenceDomain:
		return "C"
	case ConfidenceNames:
		return "D"
	default:
		return "E"
	}
}

// Shape is what a recognizer made of the request.
//
// The three fields are paths into input, or empty when nothing was recognized:
// a shape that names the subject and not the resource is a normal outcome, and
// better than one that guesses to look complete.
type Shape struct {
	Subject  string
	Action   string
	Resource string

	Confidence Confidence

	// Recognizer names what produced the shape, so that a reader can judge it
	// without reading this code.
	Recognizer string
}

// listSuffix is how a subject that holds several principals is written: the
// list, followed by the index that ranges over it, the way Rego writes any
// element of a collection.
const listSuffix = "[_]"

// SubjectList returns the path of the list when the subject is a list of
// principals rather than one, as input.subjects is in Chef Automate, where a
// request carries the user and every team the user is in.
//
// A subject that is not a list comes back unchanged, so the first value is
// always the part of the request that naming one principal fixes.
func (s Shape) SubjectList() (string, bool) {
	return strings.CutSuffix(s.Subject, listSuffix)
}

// IsSubject reports whether a term of the request is the subject.
//
// The term is compared in the form a path is reported in, so that
// input.subjects[i] and input.subjects[_] are the same element of the list.
func (s Shape) IsSubject(term string) bool {
	return s.Subject != "" && term != "" && normalizeTerm(term) == s.Subject
}

// IndexedBySubject reports whether a read picks its document by the subject of
// the request.
//
// This is the difference between a policy reading somebody's profile and a
// policy reading the profile of whoever is asking, and the second is the one
// worth looking at: the requester is on both ends of the decision.
func (s Shape) IndexedBySubject(read Read) bool {
	if s.Subject == "" {
		return false
	}
	if read.Trace != nil && s.IsSubject(read.Trace.Term) {
		return true
	}
	for _, index := range read.Indexes {
		if s.IsSubject(index.Term) {
			return true
		}
	}
	// The index sits inside the reference as it stands in the rule, between
	// the brackets: data.users[input.user].profile.department.
	return strings.Contains(read.Ref, "["+s.Subject+"]")
}

// MatchedBySubject returns the match through which a read finds the subject
// by value, and reports whether there is one.
//
// It is the same question IndexedBySubject asks, reached the other way: not
// the profile of whoever is asking, but the policies whose members include
// whoever is asking.
func (s Shape) MatchedBySubject(read Read) (Match, bool) {
	for _, match := range read.Matches {
		if s.IsSubject(match.Term) {
			return match, true
		}
	}
	return Match{}, false
}

// RecognizeShape asks each recognizer in turn, best evidence first, and
// returns the first shape somebody could stand behind.
//
// Order is the whole design: a declaration beats a standard, a standard beats
// a domain convention, and a domain convention beats a guess about names. What
// none of them beats is honesty about which one answered.
func RecognizeShape(reads *ReadSet) Shape {
	for _, recognize := range []func([]string) (Shape, bool){
		recognizeAuthZEN,
		recognizeAdmissionReview,
		recognizeByName,
	} {
		if shape, ok := recognize(reads.InputPaths); ok {
			shape.Subject = asList(shape.Subject, reads.InputPaths)
			return shape
		}
	}
	return Shape{Confidence: ConfidenceNone, Recognizer: "none"}
}

// ShapeOf returns the shape of the request: the subject declared from outside
// when there is one, and what the recognizers make of the request otherwise.
//
// A declaration replaces recognition rather than joining it, since it is the
// better evidence of the two: which part of the request names who is asking is
// decided where the request is built, and the policy only reads it. AWX builds
// the request of a job with the launching user under created_by, next to the
// teams and the superuser flag (awx/main/tasks/policy.py:49 and :194 at
// bbda905), a place none of the recognizers here looks.
//
// The subject is written the way a report prints one, input.created_by.username,
// and a list of principals the decisions range over comes back as one, the way
// a recognized subject does.
func ShapeOf(reads *ReadSet, subject string) (Shape, error) {
	if subject == "" {
		return RecognizeShape(reads), nil
	}

	ref, err := ast.ParseRef(subject)
	if err != nil || !isInputRooted(ref) {
		return Shape{}, fmt.Errorf("%w: %s", ErrBadSubject, subject)
	}
	path := normalize(ref)
	if !touched(reads.InputPaths, path) {
		return Shape{}, fmt.Errorf("%w: %s", ErrSubjectNotRead, subject)
	}
	return Shape{
		Subject:    asList(path, reads.InputPaths),
		Confidence: ConfidenceDeclared,
		Recognizer: "declared",
	}, nil
}

// touched reports whether the decisions read a path, a part of it, or
// something that holds it.
func touched(paths []string, path string) bool {
	if _, below := underPrefix(paths, path); below {
		return true
	}
	for _, read := range paths {
		if strings.HasPrefix(path, read+".") || strings.HasPrefix(path, read+"[") {
			return true
		}
	}
	return false
}

// asList writes the subject as a list when the decisions range over it.
//
// Which of the two it is decides how a request naming one principal is built,
// a string or a list holding one, and the recognizers that found the field
// cannot tell: a name like subjects is a hint, and ranging over it is the fact.
// A list the policy only hands whole to a function that ranges over it is not
// seen here, and is taken for one principal.
func asList(subject string, paths []string) string {
	if element, ranged := underPrefix(paths, subject+listSuffix); ranged {
		return element
	}
	return subject
}

// recognizeAuthZEN recognizes the shape the AuthZEN Authorization API fixes:
// subject, action, resource, context.
//
// It is a standard of the OpenID Foundation, which is what makes it worth more
// than a naming habit. Adoption is thin today, so it cannot be the only way in,
// but the cost of understanding it is this function.
func recognizeAuthZEN(paths []string) (Shape, bool) {
	subject, hasSubject := underInput(paths, "subject")
	action, hasAction := underInput(paths, "action")
	resource, hasResource := underInput(paths, "resource")

	// Two out of three would be an ordinary policy that happens to call a
	// field "action". All three together is the shape.
	if !hasSubject || !hasAction || !hasResource {
		return Shape{}, false
	}

	// The standard makes the subject an object and names its identity: id is
	// required, and is the unique identifier of the subject scoped to its type
	// (api/authorization-api-1_0.md at v0.1.22 of openid/authzen). A document
	// picked by the subject is picked by that field, so it is the subject when
	// the policy reads it. Type and properties name no principal, so a policy
	// that reads only those keeps the object.
	if id, readsID := underPrefix(paths, subject+".id"); readsID {
		subject = id
	}
	return Shape{
		Subject:    subject,
		Action:     action,
		Resource:   resource,
		Confidence: ConfidenceAuthZEN,
		Recognizer: "authzen",
	}, true
}

// admissionReviewRoot is the part of the request a Gatekeeper constraint
// template is handed the admission request in.
//
// Verified in the source of the framework Gatekeeper v3.21.0 vendors
// (frameworks/constraint/pkg/client/drivers/rego/rego.go:29, at the revision
// pinned there): the hook module builds the input of every template as
// {"review": input.review, "parameters": ...} before calling it. The name is
// Gatekeeper's own, which is what makes reading it a convention rather than a
// guess about words.
const admissionReviewRoot = "input.review"

// recognizeAdmissionReview recognizes a Kubernetes admission review, the
// request shape every Gatekeeper constraint template is written against.
//
// It is level C, a convention of one domain: weaker than a standard because it
// holds only where that domain does, stronger than reading field names because
// the fields are fixed by an API and by a policy engine rather than by habit.
// The three below are spelled as k8s.io/api/admission/v1 declares them
// (types.go:94, 96 and 99 in the copy gatekeeper v3.21.0 vendors).
//
// Only the roles the policy actually reads are filled in, and on the corpus
// this was written against that usually means the resource alone. The requester
// is read by one file of the gatekeeper-library out of a hundred and forty two:
// an admission decision is about the object being admitted and not about who is
// asking, and a shape that named a subject nobody reads would be inventing the
// part that matters most.
func recognizeAdmissionReview(paths []string) (Shape, bool) {
	if _, isReview := underPrefix(paths, admissionReviewRoot); !isReview {
		return Shape{}, false
	}

	shape := Shape{Confidence: ConfidenceDomain, Recognizer: "kubernetes admission review"}
	shape.Resource, _ = underPrefix(paths, admissionReviewRoot+".object")
	shape.Action, _ = underPrefix(paths, admissionReviewRoot+".operation")
	shape.Subject, _ = underPrefix(paths, admissionReviewRoot+".userInfo")

	return shape, true
}

// Field names that a request commonly uses for each role. Recognizing them is
// a guess, and the level it produces says as much.
var (
	subjectNames  = []string{"subject", "subjects", "user", "principal", "sub", "actor", "caller", "identity", "username", "user_id"}
	actionNames   = []string{"action", "verb", "operation", "method", "op"}
	resourceNames = []string{"resource", "object", "target", "document", "doc", "asset", "path"}
)

// recognizeByName reads the field names of the request.
//
// It answers as soon as it finds a subject, because that is the field the
// analysis needs most, and leaves the others empty rather than reaching for
// the least bad candidate.
func recognizeByName(paths []string) (Shape, bool) {
	shape := Shape{Confidence: ConfidenceNames, Recognizer: "field names"}
	shape.Subject, _ = firstNamed(paths, subjectNames)
	shape.Action, _ = firstNamed(paths, actionNames)
	shape.Resource, _ = firstNamed(paths, resourceNames)

	return shape, shape.Subject != ""
}

// underInput returns the path input.<field> when the decisions read anything
// under it.
func underInput(paths []string, field string) (string, bool) {
	return underPrefix(paths, "input."+field)
}

// underPrefix returns prefix when the decisions read it, or anything below it.
//
// Reading the whole of input.subject and reading one field of it are the same
// answer to the question being asked, which is where the subject lives, so both
// count.
func underPrefix(paths []string, prefix string) (string, bool) {
	for _, path := range paths {
		if path == prefix || strings.HasPrefix(path, prefix+".") || strings.HasPrefix(path, prefix+"[") {
			return prefix, true
		}
	}
	return "", false
}

// firstNamed returns the first of the given field names the decisions read,
// keeping the order of the names rather than the order of the paths: the list
// is written most telling first, and "user" should win over "path".
func firstNamed(paths []string, names []string) (string, bool) {
	for _, name := range names {
		if path, ok := underInput(paths, name); ok {
			return path, true
		}
	}
	return "", false
}

// SubjectCollections returns the collections the subject of the request picks a
// document from, as paths ending at the segment the subject stands at.
//
// data.users[input.user].profile.department comes back as data.users[_], and
// the keys of that collection are the principals the policy knows about. It is
// the only way the analysis has of naming who exists: a policy never lists its
// users, it reads them, and where it reads them by whoever is asking is where
// that list can be found.
func SubjectCollections(shape Shape, reads *ReadSet) []string {
	var collections []string
	for _, read := range SubjectIndexedReads(shape, reads) {
		ref, err := ast.ParseRef(read.Path)
		if err != nil {
			continue
		}
		for _, index := range read.Indexes {
			if shape.IsSubject(index.Term) && index.Position < len(ref) {
				collections = append(collections, ref[:index.Position+1].String())
			}
		}
	}
	return sortedUnique(collections)
}

// SubjectValues returns the paths whose values are compared with the subject of
// the request: the read itself for an equality, and its elements for a search
// with in.
//
// It is SubjectCollections for a policy that looks its requesters up instead of
// indexing by them. Chef Automate keeps no collection of users at all, only
// policies with members, and the members are who the policy knows about.
func SubjectValues(shape Shape, reads *ReadSet) []string {
	var paths []string
	for _, read := range reads.Reads {
		for _, match := range read.Matches {
			if shape.IsSubject(match.Term) {
				paths = append(paths, ElementPath(read, match))
			}
		}
	}
	return sortedUnique(paths)
}

// SubjectIndexedReads returns the reads that pick their document by the
// subject of the request.
func SubjectIndexedReads(shape Shape, reads *ReadSet) []Read {
	var indexed []Read
	for _, read := range reads.Reads {
		if shape.IndexedBySubject(read) {
			indexed = append(indexed, read)
		}
	}
	return slices.Clip(indexed)
}

// SubjectMatchedReads returns the reads that find the subject of the request
// by value.
func SubjectMatchedReads(shape Shape, reads *ReadSet) []Read {
	var matched []Read
	for _, read := range reads.Reads {
		if _, found := shape.MatchedBySubject(read); found {
			matched = append(matched, read)
		}
	}
	return slices.Clip(matched)
}
