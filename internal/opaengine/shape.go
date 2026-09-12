package opaengine

import (
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

// Confidence is how much a shape is worth, on the scale of the design.
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

	// ConfidenceDeclared is level A: the policy author declared the types with
	// a METADATA schemas annotation.
	ConfidenceDeclared
)

// String returns the level as the design names it, A to E, because that is
// what ends up in a report and in the graph.
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
	if read.Trace != nil && read.Trace.Term == s.Subject {
		return true
	}
	// The index sits inside the reference as it stands in the rule, between
	// the brackets: data.users[input.user].profile.department.
	return strings.Contains(read.Ref, "["+s.Subject+"]")
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
			return shape
		}
	}
	return Shape{Confidence: ConfidenceNone, Recognizer: "none"}
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
	subjectNames  = []string{"subject", "user", "principal", "sub", "actor", "caller", "identity", "username", "user_id"}
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
			if index.Term == shape.Subject && index.Position < len(ref) {
				collections = append(collections, ref[:index.Position+1].String())
			}
		}
	}
	return sortedUnique(collections)
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
