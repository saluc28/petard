package taxonomy

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/saluc28/petard/internal/opaengine"
	"github.com/saluc28/petard/internal/writemodel"
)

// SiblingGrant finds the escalations where a principal rewrites a non-identity
// attribute of their own record in a list, and that attribute is what a decision
// reads to grant.
//
// It is a third shape of PTD-OPA-006, not a pattern of its own: the cause is the
// same split grant, one decision governing a write another decision grants on,
// and the registry keeps a second instance for a disjoint cause, not a new shape
// of the same one. The value form writes a field of a record the subject keys,
// data.users[subject].roles, and the join form adds the subject to a collection;
// here the record is an element of a list that names the subject in one of its
// fields, and the grant reads a different field of the same element. A list of
// team members, each with a user and a role, where the owner check reads the
// role of the element whose user is the requester, is the value form reached by
// a matched field rather than by a key, so its findings come out under 006.
//
// The five signals are the value form's, with the record located by a matched
// field:
//
//  1. a granting decision reads a field of a list element, and the same rule
//     matches the subject by value on a different field of the same element: the
//     subject's record, found by its identity field;
//  2. the write model covers the granting field with a writer that is not the
//     subject and names the decision the writing endpoint consumes;
//  3. against the concrete data, the subject's element is resolved by its
//     identity field, and the values the granting field takes elsewhere in the
//     list are the values a write could set it to, each held by the principal it
//     would reach;
//  4. the authorizing decision is asked whether the subject may make that write;
//  5. the granting decision is evaluated again with the value written into the
//     subject's element, and the subject is reported when it grants them a
//     request none of theirs covered before, reaching the principal who holds
//     the value.
//
// The fourth signal is what keeps the write a lower privilege than the grant.
// When a member who may assign roles can set their own to the one the same
// decision rewards, and the assigning threshold sits below the rewarded one, the
// member writes their way up to it.
//
// Like PTD-OPA-006 it emits a PTD_CanEscalateTo between two principals, and it
// reads what the decision grants before and after by content, so a value that
// widens what the subject already holds without reaching anything new is not a
// finding.
func SiblingGrant(ctx context.Context, a Analysis) ([]Finding, error) {
	if a.Data == nil {
		return nil, fmt.Errorf("%w: %s", ErrNeedsData, WriteAllowedByAnotherDecision)
	}
	if a.Model == nil {
		// The write is what a lower privilege changes, and nothing in the policy
		// says who may. Without the model there is no decision behind the write to
		// ask, the same as for PTD-OPA-006.
		return nil, nil
	}

	fields, named := subjectFieldsOf(a.Shape)
	if !named {
		return nil, nil
	}
	unknowns := unknownsBesides(a.Shape, a.Reads.InputPaths)
	if len(unknowns) == 0 {
		return nil, nil
	}

	principals, err := principalsOf(ctx, a.Shape, a.Reads, a.Data)
	if err != nil || len(principals) == 0 {
		return nil, err
	}

	var findings []Finding
	for _, start := range siblingStarts(a.Reads, a.Shape, a.Model) {
		made, err := siblingGrantsOf(ctx, a, start, principals, fields, unknowns)
		if err != nil {
			return nil, err
		}
		findings = append(findings, made...)
	}
	return sortedFindings(findings), nil
}

// siblingStart is one place the pattern can begin: a granting decision that
// reads a field of a list element the subject is matched to by a different field
// of the same element, with the granting field declared writable by a decision.
type siblingStart struct {
	Decision string

	// Collection is the list, MatchField the field that names the subject, and
	// GrantField the field the grant reads. Path is the granting read normalized.
	Collection string
	MatchField string
	GrantField string
	Path       string

	Entry  writemodel.Entry
	Writer writemodel.Writer
	Auth   writemodel.Authorization
	Sites  []ReadSite
}

// siblingStarts collects the starts, folding the several rules that read the
// same granting field of the same list under one decision into one start, so the
// pattern measures a field once and reports every line to look at.
func siblingStarts(reads *opaengine.ReadSet, shape opaengine.Shape, model *writemodel.Model) []siblingStart {
	byKey := map[string]int{}
	var starts []siblingStart

	for _, grant := range reads.Reads {
		collection, grantField, ok := opaengine.ListElementField(grant.Path)
		if !ok {
			continue
		}
		matchField, matched := siblingMatch(reads, shape, grant.Rule, collection, grantField)
		if !matched {
			continue
		}
		path, err := writemodel.ParsePath(grant.Path)
		if err != nil {
			continue
		}
		site := ReadSite{Ref: grant.Ref, Rule: grant.Rule, File: grant.File, Line: grant.Line}

		for _, entry := range model.Covering(path) {
			for _, writer := range entry.WritableBy {
				if writer.AuthorizedBy == nil {
					continue
				}
				if _, isCapture := writer.IsCapture(); isCapture {
					// A capture is the subject writing their own field, which is
					// the self write of PTD-OPA-001. Here the writer is a lower
					// privilege that the decision behind the endpoint bounds.
					continue
				}
				for _, decision := range grant.Decisions {
					if !grantingSide(reads, decision) {
						// A field read only to deny is one whose write takes access
						// away, and a decision declared to deny reports who is
						// refused, not who gains.
						continue
					}
					key := decision.Name + "\x00" + collection + "\x00" + grantField + "\x00" + writer.AuthorizedBy.Decision
					if at, seen := byKey[key]; seen {
						starts[at].Sites = append(starts[at].Sites, site)
						continue
					}
					byKey[key] = len(starts)
					starts = append(starts, siblingStart{
						Decision:   decision.Name,
						Collection: collection,
						MatchField: matchField,
						GrantField: grantField,
						Path:       grant.Path,
						Entry:      entry,
						Writer:     writer,
						Auth:       *writer.AuthorizedBy,
						Sites:      []ReadSite{site},
					})
				}
			}
		}
	}
	return starts
}

// siblingMatch reports the field the subject is matched on when a rule matches
// the subject by value on one field of a list element and reads another field of
// the same element to grant.
//
// The two reads share a rule, so they range over the same element: a variable is
// scoped to the rule that binds it, so collaborators[i].user_id and
// collaborators[i].role in one body are the same i. The match is an equality on
// a field and not a membership, since a membership is the join of PTD-OPA-006.
func siblingMatch(reads *opaengine.ReadSet, shape opaengine.Shape, rule, collection, grantField string) (string, bool) {
	for _, read := range reads.Reads {
		if read.Rule != rule {
			continue
		}
		match, matched := shape.MatchedBySubject(read)
		if !matched || match.Member {
			continue
		}
		matchCollection, matchField, ok := opaengine.ListElementField(read.Path)
		if !ok || matchCollection != collection || matchField == grantField {
			continue
		}
		return matchField, true
	}
	return "", false
}

// siblingGrantsOf measures one start against every principal, resolving each
// one's record in the list and the values a write could set the granting field
// to.
func siblingGrantsOf(ctx context.Context, a Analysis, start siblingStart, principals []string, fields subjectFields, unknowns []string) ([]Finding, error) {
	list, found, err := a.Data.Value(ctx, start.Collection)
	if err != nil || !found {
		return nil, err
	}
	elements, isList := list.([]any)
	if !isList {
		return nil, nil
	}

	// What the decision grants each principal as the data stands, measured once: a
	// write is worth reporting when it grants more than this.
	now := make(map[string]reach, len(principals))
	for _, principal := range principals {
		if now[principal], err = reachOf(ctx, a.Bundle, a.Data, start.Decision, requestNaming(fields, principal), unknowns, a.Limits); err != nil {
			return nil, err
		}
	}

	var findings []Finding
	seen := map[string]bool{}
	for _, subject := range principals {
		for index, element := range elements {
			holder, isHolder := fieldValue(element, start.MatchField)
			if !isHolder || holder != subject {
				continue
			}
			made, err := siblingWritesOf(ctx, a, start, elements, index, subject, fields, unknowns, now[subject], seen)
			if err != nil {
				return nil, err
			}
			findings = append(findings, made...)
		}
	}
	return findings, nil
}

// siblingWritesOf measures the values the subject could write into one of their
// records, and returns the escalations each opens.
func siblingWritesOf(ctx context.Context, a Analysis, start siblingStart, elements []any, index int,
	subject string, fields subjectFields, unknowns []string, now reach, seen map[string]bool) ([]Finding, error) {

	document := elementFieldPath(start.Collection, index, start.GrantField)
	current, _ := fieldValue(elements[index], start.GrantField)
	holdersByValue := valueHolders(elements, start.MatchField, start.GrantField, subject, current)

	var findings []Finding
	for _, value := range slices.Sorted(maps.Keys(holdersByValue)) {
		holders := holdersByValue[value]
		opened, certain, err := siblingWriteOpens(ctx, a, start, fields, unknowns, subject, document, value, now)
		if err != nil {
			return nil, err
		}
		if !opened {
			continue
		}
		verdict := VerdictFinding
		if !certain {
			verdict = VerdictCandidate
		}
		for _, target := range holders {
			key := subject + "\x00" + target + "\x00" + value
			if seen[key] {
				continue
			}
			seen[key] = true
			findings = append(findings, siblingFinding(a, start, subject, target, value, verdict))
		}
	}
	return findings, nil
}

// siblingWriteOpens answers signals 4 and 5 for one value: the authorizing
// decision lets the subject write it, and writing it into their record grants
// them a request none of theirs covered before.
func siblingWriteOpens(ctx context.Context, a Analysis, start siblingStart, fields subjectFields, unknowns []string,
	subject, document, value string, now reach) (opened, certain bool, err error) {

	allowed, err := siblingWriteAllowed(ctx, a, start, fields, subject, document, value)
	if err != nil {
		return false, false, err
	}
	if !allowed {
		return false, true, nil
	}

	written, err := a.Data.With(ctx, document, value)
	if err != nil {
		return false, false, err
	}
	after, err := reachOf(ctx, a.Bundle, written, start.Decision, requestNaming(fields, subject), unknowns, a.Limits)
	if err != nil {
		return false, false, err
	}
	beyond, sure := after.beyond(now)
	return beyond || !sure, sure, nil
}

// siblingWriteAllowed asks the decision the endpoint consumes whether the subject
// may write one value into their record.
//
// The parts the endpoint fills in keep the question about a write, as they do for
// the join of PTD-OPA-006: without them the answer is "this principal can make
// some request about that resource", which a reader answers yes to.
func siblingWriteAllowed(ctx context.Context, a Analysis, start siblingStart, fields subjectFields, subject, document, value string) (bool, error) {
	segments, err := opaengine.Segments(document)
	if err != nil {
		return false, err
	}

	request := requestNaming(fields, subject)
	fixed := []string{subjectRoot(a.Shape)}
	for field, sent := range start.Auth.Request {
		filled, err := start.Entry.Path.Fill(sent, segments)
		if err != nil {
			return false, err
		}
		setInput(request, field, filled)
		fixed = append(fixed, field)
	}
	if start.Auth.Value != "" {
		setInput(request, start.Auth.Value, value)
		fixed = append(fixed, start.Auth.Value)
	}
	if start.Auth.Target != "" {
		setInput(request, start.Auth.Target, subject)
		fixed = append(fixed, start.Auth.Target)
	}

	unknowns := unknownsExcept(a.Reads.InputPaths, fixed...)
	if len(unknowns) == 0 {
		// Every request part the decision reads is fixed, so there is no request
		// to search over: the question is whether it holds for this one, which
		// Residuals cannot answer, since it reads an empty set of unknowns as the
		// whole request being unknown.
		return opaengine.Holds(ctx, a.Bundle, a.Data, start.Auth.Decision, request)
	}
	allowed, err := reachOf(ctx, a.Bundle, a.Data, start.Auth.Decision, request, unknowns, a.Limits)
	if err != nil {
		return false, err
	}
	return !allowed.nothing(), nil
}

// valueHolders returns the values the granting field takes elsewhere in the list
// and, for each, the principals who hold it, dropping the subject's own current
// value, which a write would not change, and the subject themselves as a target.
func valueHolders(elements []any, matchField, grantField, subject, current string) map[string][]string {
	holders := map[string][]string{}
	for _, element := range elements {
		value, hasValue := fieldValue(element, grantField)
		holder, hasHolder := fieldValue(element, matchField)
		if !hasValue || !hasHolder || value == current || holder == subject {
			continue
		}
		if !slices.Contains(holders[value], holder) {
			holders[value] = append(holders[value], holder)
		}
	}
	return holders
}

// siblingFinding says what was measured: who can set which value into their
// record, the decision that allows the write, the decision that grants on the
// value, and the principal whose position that reaches.
func siblingFinding(a Analysis, start siblingStart, subject, target, value string, verdict Verdict) Finding {
	return Finding{
		PatternID: WriteAllowedByAnotherDecision,
		Verdict:   verdict,
		Summary: fmt.Sprintf("%s can set their %s in %s to %s, which %s allows, and %s then grants the position %s holds",
			subject, start.GrantField, start.Collection, value, start.Auth.Decision, start.Decision, target),
		Principal:    subject,
		Target:       target,
		Decision:     start.Decision,
		Path:         start.Path,
		ViaWritePath: start.Entry.RawPath,
		Via:          start.Writer.Via,
		AuthorizedBy: start.Auth.Decision,
		Value:        value,
		Reads:        slices.Clone(start.Sites),
		Subject:      a.Shape.Subject,
		Confidence:   a.Shape.Confidence.String(),
	}
}

// elementFieldPath writes the path of one field of one element of a list:
// data.x.y at index 3 with field role is data.x.y[3].role.
func elementFieldPath(collection string, index int, field string) string {
	return fmt.Sprintf("%s[%d].%s", collection, index, field)
}

// fieldValue reads a string field of a list element, following a dotted path
// into the element, and reports whether it found a string there.
func fieldValue(element any, field string) (string, bool) {
	at := element
	for _, segment := range strings.Split(field, ".") {
		object, isObject := at.(map[string]any)
		if !isObject {
			return "", false
		}
		next, present := object[segment]
		if !present {
			return "", false
		}
		at = next
	}
	value, isString := at.(string)
	return value, isString
}
