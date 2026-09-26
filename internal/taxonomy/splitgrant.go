package taxonomy

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	"strings"

	"github.com/saluc28/petard/internal/opaengine"
	"github.com/saluc28/petard/internal/writemodel"
)

// WriteAllowedByAnotherDecision is the id of the OPA instance of the split
// grant category.
const WriteAllowedByAnotherDecision = "PTD-OPA-006"

// SplitGrant finds the writes one decision allows into a field another decision
// grants on: each decision is sound alone, and together they hand a principal a
// grant neither one gives.
//
// The five signals of the pattern, in order:
//
//  1. a granting decision reads a field the subject indexes, the first three
//     signals of PTD-OPA-001, unchanged;
//  2. the write model covers that field with a writer that is not a capture,
//     and names the decision the writing endpoint consumes;
//  3. the granting decision is partially evaluated with the subject's document
//     left unknown, and the constants its residual conditions compare that
//     document against are collected: the values that would grant;
//  4. the first decision is asked, for the same principal, whether writing each
//     of those values is allowed, which is what separates the case from the
//     counter case: support may write editor and not admin;
//  5. the granting decision is evaluated again with the document holding an
//     allowed value, and a principal is reported when it grants then and did
//     not before, reaching the position a principal who holds the value already
//     stands in.
//
// The fourth signal is the one that keeps the pattern honest. Without it every
// branch that reads a field somebody can write would be reported, the withdraw
// branch on admin included, and the finding would claim a grant the first
// decision never allows.
//
// A decision that finds the subject by value is measured the other way round,
// and the same five signals read like this: the value written is the subject
// themselves, so what varies is which collection they are added to. The
// principals who are not in a collection are asked, document by document,
// whether the authorizing decision lets them add an element there, and the
// granting decision is evaluated again with them in it. The parts of the
// request the endpoint fills in itself are what keeps that question about a
// write rather than about a read.
//
// It emits a finding and a PTD_CanEscalateTo, the same edge the 001 to 003
// chain emits, because it is the same claim: a principal can write their way to
// where another principal stands. What differs is the route, a value or a
// membership one decision authorizes rather than a position in a hierarchy.
func SplitGrant(ctx context.Context, a Analysis) ([]Finding, error) {
	if a.Data == nil {
		return nil, fmt.Errorf("%w: %s", ErrNeedsData, WriteAllowedByAnotherDecision)
	}
	if a.Model == nil {
		// The whole pattern rests on the write model naming the authorizing
		// decision. Without one there is nothing to ask, and the reads of signal
		// 1 are what 001 already reports.
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
	for _, grant := range authorizedGrants(a.Reads, a.Shape, a.Model) {
		made, err := splitGrantsOf(ctx, a, grant, principals, fields, unknowns)
		if err != nil {
			return nil, err
		}
		findings = append(findings, made...)
	}
	for _, join := range authorizedJoins(a.Reads, a.Shape, a.Model) {
		made, err := joinsOpenedBy(ctx, a, join, principals, fields, unknowns)
		if err != nil {
			return nil, err
		}
		findings = append(findings, made...)
	}
	return sortedFindings(findings), nil
}

// authorizedGrant is one place the pattern can start: a decision that reads a
// subject indexed field, and a write model writer that is not a capture and
// declares which decision governs the write.
type authorizedGrant struct {
	Decision        string
	Path            string
	SubjectPosition int
	Entry           writemodel.Entry
	Writer          writemodel.Writer
	Auth            writemodel.Authorization
	Sites           []ReadSite
}

// authorizedGrants collects the starts, one per decision and field, folding the
// several reads of the same field into one so that the pattern measures a field
// once and reports every line to look at.
func authorizedGrants(reads *opaengine.ReadSet, shape opaengine.Shape, model *writemodel.Model) []authorizedGrant {
	byKey := map[string]int{}
	var grants []authorizedGrant

	for _, read := range reads.Reads {
		if !signalsHold(read, shape) {
			continue
		}
		position, located := subjectPosition(read, shape)
		if !located {
			// Either the subject indexes this read through a function parameter,
			// so which segment is its own document is not on this reference, or
			// the read finds the subject by value, and then the write that
			// grants adds the subject rather than a value to a document of
			// theirs. The pattern names a document and writes a value into it,
			// so it leaves both to a later refinement rather than guessing.
			continue
		}
		path, err := writemodel.ParsePath(read.Path)
		if err != nil {
			continue
		}
		site := ReadSite{Ref: read.Ref, Rule: read.Rule, File: read.File, Line: read.Line}

		for _, entry := range model.Covering(path) {
			for _, writer := range entry.WritableBy {
				if writer.AuthorizedBy == nil {
					continue
				}
				if _, isCapture := writer.IsCapture(); isCapture {
					// A capture is the subject writing their own field, which is
					// PTD-OPA-001. This pattern is about a writer who is not the
					// subject, with the rule that bounds the write in the bundle.
					continue
				}
				for _, decision := range read.Decisions {
					if !grantingSide(reads, decision) {
						// Not because the side makes the write harmless: the
						// values collected later are the ones the decision
						// compares with, and here those are the values that
						// deny, the same as for any value of a decision
						// declared to deny. Lifting the denial takes another
						// value, which nothing names, so this is a declared
						// false negative.
						continue
					}
					key := decision.Name + "\x00" + read.Path + "\x00" + writer.AuthorizedBy.Decision + "\x00" + writer.AuthorizedBy.Value
					if at, seen := byKey[key]; seen {
						grants[at].Sites = append(grants[at].Sites, site)
						continue
					}
					byKey[key] = len(grants)
					grants = append(grants, authorizedGrant{
						Decision:        decision.Name,
						Path:            read.Path,
						SubjectPosition: position,
						Entry:           entry,
						Writer:          writer,
						Auth:            *writer.AuthorizedBy,
						Sites:           []ReadSite{site},
					})
				}
			}
		}
	}
	return grants
}

// splitGrantsOf measures one start against every principal, and returns the
// escalations it opens.
func splitGrantsOf(ctx context.Context, a Analysis, grant authorizedGrant, principals []string, fields subjectFields, unknowns []string) ([]Finding, error) {
	// Who the decision grants as the data stands. The subject has to gain, so it
	// must get nothing now; the target has to hold the position, so it must get
	// something now. Both readings come from the same measurement.
	grantsNow := make(map[string]bool, len(principals))
	for _, principal := range principals {
		reach, err := reachOf(ctx, a.Bundle, a.Data, grant.Decision, requestNaming(fields, principal), unknowns, a.Limits)
		if err != nil {
			return nil, err
		}
		grantsNow[principal] = !reach.nothing()
	}

	var findings []Finding
	for _, subject := range principals {
		if grantsNow[subject] {
			// Already gets something out of the decision, so a write would widen
			// what it holds rather than let it in. That is the open question the
			// transitive pattern declares, and this pattern leaves it there.
			continue
		}

		document, err := opaengine.DocumentPath(grant.Path, grant.SubjectPosition, subject)
		if err != nil {
			return nil, err
		}
		values, err := opaengine.ValuesComparedWith(ctx, a.Bundle, a.Data, opaengine.Request{
			Decision: grant.Decision,
			Unknowns: unknowns,
			Input:    requestNaming(fields, subject),
		}, document)
		if err != nil {
			return nil, err
		}

		for _, value := range values {
			opens, err := valueOpensTheGrant(ctx, a, grant, fields, unknowns, subject, document, value)
			if err != nil {
				return nil, err
			}
			if !opens {
				continue
			}
			for _, target := range principals {
				if target == subject || !grantsNow[target] {
					continue
				}
				holds, err := holdsValue(ctx, a.Data, grant.Path, grant.SubjectPosition, target, value.Value)
				if err != nil {
					return nil, err
				}
				if holds {
					findings = append(findings, splitGrantFinding(a, grant, subject, target, value))
				}
			}
		}
	}
	return findings, nil
}

// valueOpensTheGrant answers signals 4 and 5 for one value: the first decision
// allows the subject to write it, and writing it turns the grant on.
func valueOpensTheGrant(ctx context.Context, a Analysis, grant authorizedGrant, fields subjectFields, unknowns []string,
	subject, document string, value opaengine.GrantingValue) (bool, error) {

	// Signal 4: does the first decision allow this principal to write this
	// value? The value and the target are fixed, the rest of the request is
	// open, so the answer is "there is a request under which the write is
	// allowed" rather than one hand written call.
	request := requestNaming(fields, subject)
	setInput(request, grant.Auth.Value, value.Value)
	if grant.Auth.Target != "" {
		setInput(request, grant.Auth.Target, subject)
	}
	authUnknowns := unknownsExcept(a.Reads.InputPaths, subjectRoot(a.Shape), grant.Auth.Value, grant.Auth.Target)

	allowed, err := reachOf(ctx, a.Bundle, a.Data, grant.Auth.Decision, request, authUnknowns, a.Limits)
	if err != nil {
		return false, err
	}
	if allowed.nothing() {
		return false, nil
	}

	// Signal 5: evaluate the whole granting decision with the document holding
	// the value, so any other condition it imposes still applies. A principal
	// the write does not actually let through is not reported.
	current, _, err := a.Data.Value(ctx, document)
	if err != nil {
		return false, err
	}
	written, err := a.Data.With(ctx, document, held(current, value))
	if err != nil {
		return false, err
	}
	granted, err := reachOf(ctx, a.Bundle, written, grant.Decision, requestNaming(fields, subject), unknowns, a.Limits)
	if err != nil {
		return false, err
	}
	return !granted.nothing(), nil
}

// held is the document once the value is written: appended to the collection
// the membership reads, or set in place of a scalar the equality compares. The
// existing content is kept, which is the write an endpoint really performs and
// keeps any other condition of the decision measurable against real data.
func held(current any, value opaengine.GrantingValue) any {
	if !value.Membership {
		return value.Value
	}
	if list, isList := current.([]any); isList {
		return append(slices.Clone(list), value.Value)
	}
	return []any{value.Value}
}

// holdsValue reports whether a principal's document already holds the value: the
// principal who does is the position the write reaches, the one BloodHound draws
// the edge to.
func holdsValue(ctx context.Context, data *opaengine.Data, path string, position int, principal string, value any) (bool, error) {
	document, err := opaengine.DocumentPath(path, position, principal)
	if err != nil {
		return false, err
	}
	current, found, err := data.Value(ctx, document)
	if err != nil || !found {
		return false, err
	}
	if list, isList := current.([]any); isList {
		for _, element := range list {
			if reflect.DeepEqual(element, value) {
				return true, nil
			}
		}
		return false, nil
	}
	return reflect.DeepEqual(current, value), nil
}

// splitGrantFinding says what was measured: who can write which value, the
// decision that allows the write, the decision that grants on it, and the
// principal whose position that reaches.
func splitGrantFinding(a Analysis, grant authorizedGrant, subject, target string, value opaengine.GrantingValue) Finding {
	return Finding{
		PatternID: WriteAllowedByAnotherDecision,
		Verdict:   VerdictFinding,
		Summary: fmt.Sprintf("%s can write %s into %s, which %s allows, and %s then grants the position %s holds",
			subject, value.Text, grant.Path, grant.Auth.Decision, grant.Decision, target),
		Principal:    subject,
		Target:       target,
		Decision:     grant.Decision,
		Path:         grant.Path,
		ViaWritePath: grant.Entry.RawPath,
		Via:          grant.Writer.Via,
		AuthorizedBy: grant.Auth.Decision,
		Value:        value.Text,
		Reads:        slices.Clone(grant.Sites),
		Subject:      a.Shape.Subject,
		Confidence:   a.Shape.Confidence.String(),
	}
}

// authorizedJoin is the other place the pattern can start: a decision that
// finds the subject among the elements of a collection, and a write model
// writer who is not the subject and adds an element with a decision of the
// bundle behind them.
type authorizedJoin struct {
	Decision string

	// Path is the read, and List the collection an element is added to. For a
	// search with in the two are the same path.
	Path string
	List string

	Entry  writemodel.Entry
	Writer writemodel.Writer
	Auth   writemodel.Authorization
	Sites  []ReadSite
}

// authorizedJoins collects the starts where the decision finds the subject by
// value, one per decision and collection.
func authorizedJoins(reads *opaengine.ReadSet, shape opaengine.Shape, model *writemodel.Model) []authorizedJoin {
	byKey := map[string]int{}
	var joins []authorizedJoin

	for _, read := range reads.Reads {
		match, matched := shape.MatchedBySubject(read)
		if !matched {
			continue
		}
		list, err := opaengine.CollectionPath(read, match)
		if err != nil {
			continue
		}
		element, err := writemodel.ParsePath(opaengine.ElementPath(read, match))
		if err != nil {
			continue
		}
		site := ReadSite{Ref: read.Ref, Rule: read.Rule, File: read.File, Line: read.Line}

		for _, entry := range model.Covering(element) {
			for _, writer := range entry.WritableBy {
				if writer.AuthorizedBy == nil {
					continue
				}
				if _, isCapture := writer.IsCapture(); isCapture {
					// A capture is the subject adding themselves with nothing
					// to ask, which is the join PTD-OPA-001 reports. Here the
					// write goes through a decision of the bundle, and that
					// decision is what says who may make it.
					continue
				}
				for _, decision := range read.Decisions {
					if !grantingSide(reads, decision) {
						// The membership only ever denies there, so adding an
						// element takes access away rather than granting it;
						// or the decision denies, and what its residuals say is
						// who gets refused.
						continue
					}
					key := decision.Name + "\x00" + list + "\x00" + writer.AuthorizedBy.Decision
					if at, seen := byKey[key]; seen {
						joins[at].Sites = append(joins[at].Sites, site)
						continue
					}
					byKey[key] = len(joins)
					joins = append(joins, authorizedJoin{
						Decision: decision.Name,
						Path:     read.Path,
						List:     list,
						Entry:    entry,
						Writer:   writer,
						Auth:     *writer.AuthorizedBy,
						Sites:    []ReadSite{site},
					})
				}
			}
		}
	}
	return joins
}

// joinsOpenedBy measures one start against every document of the collection and
// every principal, and returns the escalations joining opens.
//
// The question is not the one the value side asks. There the subject has a
// document of their own and the pattern looks for a value to put in it; here
// the subject is an element, so what varies is which collection they add
// themselves to, and the value is always themselves.
func joinsOpenedBy(ctx context.Context, a Analysis, join authorizedJoin, principals []string, fields subjectFields, unknowns []string) ([]Finding, error) {
	documents, err := a.Data.Documents(ctx, join.List)
	if err != nil {
		return nil, err
	}

	// What the decision grants each principal as the data stands, measured once:
	// a join is worth reporting when it grants more than that.
	now := make(map[string]reach, len(principals))
	for _, principal := range principals {
		if now[principal], err = reachOf(ctx, a.Bundle, a.Data, join.Decision, requestNaming(fields, principal), unknowns, a.Limits); err != nil {
			return nil, err
		}
	}

	var findings []Finding
	for _, document := range documents {
		members, err := elementsOf(ctx, a.Data, document)
		if err != nil {
			return nil, err
		}

		for _, subject := range principals {
			opened, certain, err := joinOpens(ctx, a, join, document, members, fields, unknowns, subject, now[subject])
			if err != nil {
				return nil, err
			}
			if !opened {
				continue
			}
			verdict := VerdictFinding
			if !certain {
				// The join grants more ways, but whether any of them is a
				// request the principal could not already make could not be
				// read from the conditions. A gain that cannot be proven is a
				// candidate, not a finding.
				verdict = VerdictCandidate
			}
			for _, target := range members {
				if name, isName := target.(string); isName && name != subject {
					findings = append(findings, joinFinding(a, join, document, subject, name, verdict))
				}
			}
		}
	}
	return findings, nil
}

// joinOpens answers the two signals a join turns on: the decision behind the
// endpoint lets this principal add an element to this document, and the
// granting decision gives them more once they are in it.
func joinOpens(ctx context.Context, a Analysis, join authorizedJoin, document string, members []any,
	fields subjectFields, unknowns []string, subject string, now reach) (opened, certain bool, err error) {

	if slices.Contains(members, any(subject)) {
		// Already an element: there is no join to make, and what it grants
		// they hold already.
		return false, true, nil
	}

	allowed, err := writeAllowed(ctx, a, join, document, fields, subject)
	if err != nil {
		return false, false, err
	}
	if !allowed {
		return false, true, nil
	}

	written, err := a.Data.With(ctx, document, append(slices.Clone(members), subject))
	if err != nil {
		return false, false, err
	}
	after, err := reachOf(ctx, a.Bundle, written, join.Decision, requestNaming(fields, subject), unknowns, a.Limits)
	if err != nil {
		return false, false, err
	}
	beyond, sure := after.beyond(now)
	// Report a proven gain as a finding and an unproven one as a candidate; a
	// join that grants nothing new is not reported at all.
	return beyond || !sure, sure, nil
}

// writeAllowed asks the decision the endpoint consumes whether one principal
// may add an element to one document.
//
// The parts of the request the endpoint fills in itself are what keeps the
// question narrow. Without them the answer would be "this principal can make
// some request about that resource", which anybody allowed to read it answers
// yes to, and the finding would claim a write on the strength of a read.
func writeAllowed(ctx context.Context, a Analysis, join authorizedJoin, document string, fields subjectFields, subject string) (bool, error) {
	segments, err := opaengine.Segments(document)
	if err != nil {
		return false, err
	}

	request := requestNaming(fields, subject)
	fixed := []string{subjectRoot(a.Shape)}
	for field, sent := range join.Auth.Request {
		filled, err := join.Entry.Path.Fill(sent, segments)
		if err != nil {
			return false, err
		}
		setInput(request, field, filled)
		fixed = append(fixed, field)
	}
	if join.Auth.Value != "" {
		// A decision that reads what is written reads who is being added, and
		// that is the subject.
		setInput(request, join.Auth.Value, subject)
		fixed = append(fixed, join.Auth.Value)
	}

	allowed, err := reachOf(ctx, a.Bundle, a.Data, join.Auth.Decision, request,
		unknownsExcept(a.Reads.InputPaths, fixed...), a.Limits)
	if err != nil {
		return false, err
	}
	return !allowed.nothing(), nil
}

// elementsOf returns what a collection holds, and nothing when it holds no
// collection: a document that is not there is one an endpoint creates with the
// first element.
func elementsOf(ctx context.Context, data *opaengine.Data, document string) ([]any, error) {
	current, found, err := data.Value(ctx, document)
	if err != nil || !found {
		return nil, err
	}
	if list, isList := current.([]any); isList {
		return list, nil
	}
	return nil, nil
}

// joinFinding says what was measured: who can add themselves where, the
// decision that allows it, the decision that grants on the membership, and the
// principal whose position that reaches.
func joinFinding(a Analysis, join authorizedJoin, document, subject, target string, verdict Verdict) Finding {
	return Finding{
		PatternID: WriteAllowedByAnotherDecision,
		Verdict:   verdict,
		Summary: fmt.Sprintf("%s can add themselves to %s, which %s allows, and %s then grants the position %s holds",
			subject, document, join.Auth.Decision, join.Decision, target),
		Principal:    subject,
		Target:       target,
		Decision:     join.Decision,
		Path:         join.Path,
		ViaWritePath: join.Entry.RawPath,
		Via:          join.Writer.Via,
		AuthorizedBy: join.Auth.Decision,
		Value:        subject,
		Reads:        slices.Clone(join.Sites),
		Subject:      a.Shape.Subject,
		Confidence:   a.Shape.Confidence.String(),
	}
}

// subjectPosition returns the segment of a read the subject stands at, when it
// stands there directly rather than through a function parameter.
func subjectPosition(read opaengine.Read, shape opaengine.Shape) (int, bool) {
	for _, index := range read.Indexes {
		if shape.IsSubject(index.Term) {
			return index.Position, true
		}
	}
	return 0, false
}

// setInput writes a value at a path into input, extending a request that
// already names the subject.
func setInput(request map[string]any, path string, value any) {
	fields := strings.Split(strings.TrimPrefix(path, "input."), ".")
	at := request
	for _, field := range fields[:len(fields)-1] {
		next, isObject := at[field].(map[string]any)
		if !isObject {
			next = map[string]any{}
			at[field] = next
		}
		at = next
	}
	at[fields[len(fields)-1]] = value
}

// unknownsExcept returns the request paths to leave open, dropping the ones the
// question fixes: the subject and, for the authorizing decision, the value and
// the target it is asked about.
//
// What is left open is a document: a request is unknown by the part of it that
// is not there, and input.projects[_] is that list left open, not an element of
// it on its own. A policy that only ever reads the elements would otherwise
// leave the list itself known, and known means absent, so every condition on it
// would fail and the decision would grant nobody anything.
func unknownsExcept(paths []string, fixed ...string) []string {
	var unknowns []string
	for _, path := range paths {
		if !underAny(path, fixed) {
			unknowns = append(unknowns, documentOf(path))
		}
	}
	return sortedUnique(unknowns)
}

// documentOf cuts a path at the first segment it ranges over.
func documentOf(path string) string {
	if at := strings.Index(path, "["); at >= 0 {
		return path[:at]
	}
	return path
}

// underAny reports whether a path is one of the prefixes or sits under it.
func underAny(path string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if prefix == "" {
			continue
		}
		if path == prefix || strings.HasPrefix(path, prefix+".") || strings.HasPrefix(path, prefix+"[") {
			return true
		}
	}
	return false
}
