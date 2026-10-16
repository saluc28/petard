package taxonomy

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/saluc28/petard/internal/opaengine"
	"github.com/saluc28/petard/internal/pep"
)

// GrantBeyondDelegatedScope is the id of the OPA instance of the delegation not
// narrowed category.
const GrantBeyondDelegatedScope = "PTD-OPA-013"

// delegationElement is the one element a request built here asks for, which
// every ceiling of it also holds. delegationBeyond is one no request asks for:
// a ceiling that holds it alone holds none of what is asked. They are
// synthetic, so the test rests on the shape of the authority and not on any
// value a policy writes.
const (
	delegationElement = "petard-scope"
	delegationBeyond  = "petard-scope-beyond"
)

// GrantsBeyondDelegatedScope finds the decisions that grant a delegated
// principal the authority it asks for without bounding that authority by the
// delegator's, so an agent whose own grant is broad mints scopes the delegating
// user never held.
//
// The defect is an absence: no check relates the requested authority to the
// ceiling the delegator set. The pattern does not look for that check. It reads
// the question the enforcement point declares, a requested-authority field and
// the ceilings it must sit under, and asks the decision itself:
//
//  1. it starts from a request the decision grants: one given as granted (see
//     GrantedRequest), or one built with the requested authority reduced to a
//     single synthetic element every ceiling also holds;
//  2. the same request is asked again with the ceiling under test holding
//     none of what the request asks for, and every other ceiling as it was;
//  3. granting it too means that ceiling makes no difference to the grant, so
//     it does not bound the authority, and the grant reaches past it.
//
// Reading the grant rather than the check makes the verdict independent of how
// the policy writes the bound: an every, object.subset, a set difference or a
// comprehension all refuse the second request, and a bound a later branch leaves
// open grants it, which a reading of the every form alone would miss. A ceiling
// that holds none of what is asked for bounds none of it, whether the decision
// matches the two by element, by prefix or by wildcard.
//
// A ceiling is a part of the request or a document in the data. One in the
// data is changed in every document its path names, since the request may pick
// any of them, and one the data holds no document for cannot be asked about.
//
// The enforcement point says which field is the requested authority and what
// bounds it, because neither is in the policy: a decision that bounds the
// request by the agent's own role but never by the delegator's grant looks, to
// the policy, like a decision that bounds the request. With a requested
// authority declared and no ceiling it is a candidate, asking what bounds the
// authority; with no declaration at all there is nothing to ask, as in
// PTD-OPA-009 to PTD-OPA-011. A decision no request was given or could be built
// for is a candidate as well, saying it could not be asked: one that grants
// named scopes alone refuses the synthetic element, and a request it grants,
// given from outside, is what it takes to ask it.
//
// It reads only the grant side: a loose delegation on a decision that refuses is
// a deny that under-blocks, a different concern.
//
// The decisions are evaluated against the documents they read. Where the ones
// that read a requested authority read none, there is nothing to load, and an
// analysis with no data asks them all the same: see DelegationNeedsData.
func GrantsBeyondDelegatedScope(ctx context.Context, a Analysis) ([]Finding, error) {
	if a.EnforcementPoint == nil {
		return nil, nil
	}
	requested := requestedAuthorities(a.EnforcementPoint)
	if len(requested) == 0 {
		return nil, nil
	}
	if a.Data == nil {
		if DelegationNeedsData(a) {
			return nil, fmt.Errorf("%w: %s", ErrNeedsData, GrantBeyondDelegatedScope)
		}
		a.Data = opaengine.NoData()
	}

	var findings []Finding
	for _, decision := range grantingDecisions(a.Reads) {
		for _, field := range requested {
			finding, err := delegationFinding(ctx, a, decision, field)
			if err != nil {
				return nil, err
			}
			if finding != nil {
				findings = append(findings, *finding)
			}
		}
	}
	return sortedFindings(findings), nil
}

// DelegationNeedsData reports whether PTD-OPA-013 has a decision to ask that
// reads a document: a granting decision that reads an authority the enforcement
// point declares requested, and reads the data too. A token service that
// decides on the request alone reads none, and is asked with no data given.
func DelegationNeedsData(a Analysis) bool {
	if a.EnforcementPoint == nil {
		return false
	}
	for _, field := range requestedAuthorities(a.EnforcementPoint) {
		for _, decision := range grantingDecisions(a.Reads) {
			if len(delegationSites(a.Reads, decision, field.Path)) > 0 && decisionReadsData(a.Reads, decision) {
				return true
			}
		}
	}
	return false
}

// requestedAuthorities returns the fields the enforcement point declares a
// requested authority.
func requestedAuthorities(point *pep.EnforcementPoint) []pep.Field {
	var fields []pep.Field
	for _, field := range point.Fields {
		if field.Authority == pep.AuthorityRequested {
			fields = append(fields, field)
		}
	}
	return fields
}

// grantingDecisions returns the decisions whose holding lets the request
// through, the ones a delegation can be too wide on.
func grantingDecisions(reads *opaengine.ReadSet) []string {
	var grants []string
	for _, decision := range reads.Decisions {
		if !reads.Denies(decision) {
			grants = append(grants, decision)
		}
	}
	slices.Sort(grants)
	return grants
}

// delegationFinding measures one decision against one requested authority, and
// returns the finding or candidate it makes, or nil when the decision does not
// grant on that authority or bounds it.
func delegationFinding(ctx context.Context, a Analysis, decision string, field pep.Field) (*Finding, error) {
	sites := delegationSites(a.Reads, decision, field.Path)
	if len(sites) == 0 {
		// The decision does not read the requested authority, so it does not
		// grant on it.
		return nil, nil
	}
	// The claim rests on the declaration of the enforcement point, which names
	// the requested authority, and a declaration of the request is the first of
	// the levels, as for PTD-OPA-009 to PTD-OPA-011. Who the subject is plays
	// no part in it.
	finding := Finding{
		PatternID:  GrantBeyondDelegatedScope,
		Decision:   decision,
		Path:       field.Path,
		Reads:      sites,
		Subject:    a.Shape.Subject,
		Confidence: opaengine.ConfidenceDeclared.String(),
	}
	if len(field.BoundedBy) == 0 {
		finding.Verdict = VerdictCandidate
		finding.Summary = fmt.Sprintf("%s grants the authority requested in %s, and no enforcement point says what bounds it",
			decision, field.Path)
		return &finding, nil
	}

	starts, err := delegationStarts(ctx, a, decision, field)
	if err != nil {
		return nil, err
	}
	if len(starts) == 0 {
		// Nothing the decision grants was given, and none could be built with the
		// authority inside every ceiling: a decision that grants named scopes
		// alone refuses the one the pattern makes up. Whether a ceiling bounds
		// the authority is then not known, and that is what is reported.
		finding.Verdict = VerdictCandidate
		finding.Summary = fmt.Sprintf("%s reads the authority requested in %s, and could not be asked whether %s bounds it: "+
			"no request it grants could be built to start from, and none was given",
			decision, field.Path, strings.Join(field.BoundedBy, " or "))
		return &finding, nil
	}

	var past, proofs []string
	for _, ceiling := range field.BoundedBy {
		for _, start := range starts {
			proof, err := grantedPast(ctx, a, decision, start, ceiling)
			if err != nil {
				return nil, err
			}
			if proof != "" {
				past = append(past, ceiling)
				proofs = append(proofs, proof)
				break
			}
		}
	}
	if len(past) == 0 {
		return nil, nil
	}
	finding.Verdict = VerdictFinding
	finding.Summary = fmt.Sprintf("%s grants the authority requested in %s without bounding it by %s",
		decision, field.Path, strings.Join(past, " or by "))
	finding.Note = strings.Join(proofs, "; and ")
	return &finding, nil
}

// delegationStart is a request the decision grants and the data it grants it
// against: where the question whether a ceiling bounds the requested authority
// starts.
type delegationStart struct {
	request map[string]any
	data    *opaengine.Data
}

// delegationStarts returns the requests a question about one decision starts
// from: the ones given as granted that ask for some of the authority, and then
// one built with the authority reduced to a synthetic element every ceiling
// holds.
func delegationStarts(ctx context.Context, a Analysis, decision string, field pep.Field) ([]delegationStart, error) {
	var starts []delegationStart
	for _, request := range a.grantedBy(decision) {
		if asked, found := inputValue(request, field.Path); found && holdsSomething(asked) {
			starts = append(starts, delegationStart{request: request, data: a.Data})
		}
	}
	built, err := boundedBaseline(ctx, a, decision, field.Path, field.BoundedBy)
	if err != nil {
		return nil, err
	}
	if built != nil {
		starts = append(starts, *built)
	}
	return starts, nil
}

// holdsSomething reports whether a requested authority asks for anything: a
// list or an object with an element in it, or a string that is not empty.
func holdsSomething(authority any) bool {
	switch authority := authority.(type) {
	case []any:
		return len(authority) > 0
	case map[string]any:
		return len(authority) > 0
	case string:
		return authority != ""
	default:
		return false
	}
}

// boundedBaseline returns a request the decision grants with the requested
// authority reduced to a single synthetic element every ceiling also holds, or
// nil when the decision grants nothing even so. The authority and the ceilings
// in the request are pinned and the rest of the request is left open, so
// partial evaluation solves the other conditions a grant needs, an action or a
// flag. A ceiling in the data holds the element in every document it names,
// since the request may pick any of them.
func boundedBaseline(ctx context.Context, a Analysis, decision, requested string, ceilings []string) (*delegationStart, error) {
	request := map[string]any{}
	setInput(request, requested, []any{delegationElement})
	data := a.Data
	fixed := []string{requested}
	for _, ceiling := range ceilings {
		if strings.HasPrefix(ceiling, "input.") {
			setInput(request, ceiling, []any{delegationElement})
			fixed = append(fixed, ceiling)
			continue
		}
		var err error
		if data, _, err = data.Replaced(ctx, ceiling, func(any) any { return []any{delegationElement} }); err != nil {
			return nil, err
		}
	}

	measured, err := reachOf(ctx, a.Bundle, data, decision, request, unknownsExcept(a.Reads.InputPaths, fixed...), a.Limits)
	if err != nil {
		return nil, err
	}
	if measured.nothing() {
		return nil, nil
	}
	example, err := measured.example(ctx)
	if err != nil {
		return nil, err
	}
	if example != nil {
		return &delegationStart{request: example, data: data}, nil
	}
	// Partial evaluation found no other condition to solve, so the pinned
	// request grants on its own, or the decision does not grant it at all.
	holds, err := opaengine.Holds(ctx, a.Bundle, data, decision, request)
	if err != nil || !holds {
		return nil, err
	}
	return &delegationStart{request: request, data: data}, nil
}

// grantedPast asks the decision about a request it grants once one ceiling
// holds none of what the request asks for, and returns what proves the grant
// reaches past that ceiling, or the empty string when the decision refuses.
//
// A ceiling that holds nothing asked for bounds nothing asked for, whatever the
// decision matches the two with: an element, a prefix, a wildcard. Nor is it
// empty, which some decisions read as no ceiling at all: it holds one element
// no request asks for. A ceiling in the request is set in it; one in the data is
// set in every document it names. A ceiling in the data with no document there
// cannot be asked about, and is left out.
func grantedPast(ctx context.Context, a Analysis, decision string, start delegationStart, ceiling string) (string, error) {
	if strings.HasPrefix(ceiling, "input.") {
		current, _ := inputValue(start.request, ceiling)
		over := copyInput(start.request)
		setInput(over, ceiling, holdingNothingAsked(current))
		granted, err := opaengine.Holds(ctx, a.Bundle, start.data, decision, over)
		if err != nil || !granted {
			return "", err
		}
		return fmt.Sprintf("proven by %s, where %s holds none of what it asks for", JSON(over), ceiling), nil
	}

	data, documents, err := start.data.Replaced(ctx, ceiling, holdingNothingAsked)
	if err != nil || documents == 0 {
		return "", err
	}
	granted, err := opaengine.Holds(ctx, a.Bundle, data, decision, start.request)
	if err != nil || !granted {
		return "", err
	}
	return fmt.Sprintf("proven by %s, with every document at %s holding none of what it asks for",
		JSON(start.request), ceiling), nil
}

// holdingNothingAsked returns a ceiling of the same shape as the one it is
// given, holding one element no request asks for: a list of it, an object keyed
// by it, or the element itself in place of a string.
func holdingNothingAsked(ceiling any) any {
	switch ceiling := ceiling.(type) {
	case string:
		return delegationBeyond
	case map[string]any:
		// The value under the key is shaped like the ones the ceiling holds, so
		// a decision that reads it reads what it expects.
		var value any = true
		if keys := slices.Sorted(maps.Keys(ceiling)); len(keys) > 0 {
			value = copyValue(ceiling[keys[0]])
		}
		return map[string]any{delegationBeyond: value}
	default:
		return []any{delegationBeyond}
	}
}

// delegationSites returns the places the decision reads the requested
// authority, or anything inside it. A field read nowhere the decision reaches is
// not one it grants on.
//
// How the decision reads it is not asked. A bound is as often an object.subset,
// a set difference or a count of the offenders as it is an every, and a decision
// with no bound at all reads the authority to count it or to hand it on: each of
// them reads it, and the witness is what tells the bounded from the others.
func delegationSites(reads *opaengine.ReadSet, decision, path string) []ReadSite {
	var sites []ReadSite
	for _, read := range reads.RequestReads {
		if !partUnder(read.Path, path) || !reachesDecision(read.Decisions, decision) {
			continue
		}
		sites = append(sites, ReadSite{Ref: read.Path, Rule: read.Rule, File: read.File, Line: read.Line})
	}
	return sites
}

// reachesDecision reports whether a decision is among the ones a construct is
// reached by.
func reachesDecision(decisions []opaengine.ReachedDecision, decision string) bool {
	for _, reached := range decisions {
		if reached.Name == decision {
			return true
		}
	}
	return false
}

// copyInput copies a request so that writing the authority fields into the copy
// leaves the baseline alone.
func copyInput(request map[string]any) map[string]any {
	copied, _ := copyValue(request).(map[string]any)
	if copied == nil {
		return map[string]any{}
	}
	return copied
}

// copyValue copies a value of a request as JSON would.
func copyValue(value any) any {
	switch value := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(value))
		for key, child := range value {
			out[key] = copyValue(child)
		}
		return out
	case []any:
		out := make([]any, len(value))
		for i, child := range value {
			out[i] = copyValue(child)
		}
		return out
	default:
		return value
	}
}
