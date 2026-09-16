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
// It emits a finding and a PTD_CanEscalateTo, the same edge the 001 to 003
// chain emits, because it is the same claim: a principal who holds nothing can
// write their way to where another principal stands. What differs is the route,
// a value one decision authorizes rather than a position in a hierarchy.
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

	fields, named := subjectFields(a.Shape.Subject)
	if !named {
		return nil, nil
	}
	unknowns := unknownsBesides(a.Shape.Subject, a.Reads.InputPaths)
	if len(unknowns) == 0 {
		return nil, nil
	}

	principals, err := principalsOf(ctx, a.Shape, a.Reads, a.Data)
	if err != nil || len(principals) == 0 {
		return nil, err
	}

	grants := authorizedGrants(a.Reads, a.Shape, a.Model)

	var findings []Finding
	for _, grant := range grants {
		made, err := splitGrantsOf(ctx, a, grant, principals, fields, unknowns)
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
			// The subject indexes this read through a function parameter, so
			// which segment is its own document is not on this reference. The
			// pattern needs that segment to name the document, and leaves the
			// read to a later refinement rather than guessing it.
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
					if decision.UnderNegation {
						// Not because the side makes the write harmless: the
						// values collected later are the ones the decision
						// compares with, and here those are the values that
						// deny. Lifting the denial takes another value, which
						// nothing names, so this is a declared false negative.
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
func splitGrantsOf(ctx context.Context, a Analysis, grant authorizedGrant, principals, fields, unknowns []string) ([]Finding, error) {
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
func valueOpensTheGrant(ctx context.Context, a Analysis, grant authorizedGrant, fields, unknowns []string,
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
	authUnknowns := unknownsExcept(a.Reads.InputPaths, a.Shape.Subject, grant.Auth.Value, grant.Auth.Target)

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

// subjectPosition returns the segment of a read the subject stands at, when it
// stands there directly rather than through a function parameter.
func subjectPosition(read opaengine.Read, shape opaengine.Shape) (int, bool) {
	for _, index := range read.Indexes {
		if index.Term == shape.Subject {
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
func unknownsExcept(paths []string, fixed ...string) []string {
	var unknowns []string
	for _, path := range paths {
		if !underAny(path, fixed) {
			unknowns = append(unknowns, path)
		}
	}
	return unknowns
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
