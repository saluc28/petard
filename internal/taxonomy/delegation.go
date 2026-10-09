package taxonomy

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/saluc28/petard/internal/opaengine"
	"github.com/saluc28/petard/internal/pep"
)

// GrantBeyondDelegatedScope is the id of the OPA instance of the delegation not
// narrowed category.
const GrantBeyondDelegatedScope = "PTD-OPA-013"

// delegationElement is one element every ceiling holds, and delegationBeyond one
// no ceiling does. A request asking for the first alone is bounded; one asking
// for the second as well reaches past a ceiling. They are synthetic, so the test
// rests on the shape of the authority and not on any value a policy writes.
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
//  1. a request the decision grants is built, with the requested authority
//     reduced to a single synthetic element every ceiling also holds;
//  2. the same request is asked again with one more element in the requested
//     authority, one the ceiling under test does not hold while every other
//     ceiling does;
//  3. granting the second request too means the extra element made no
//     difference, so that ceiling does not bound the authority, and the grant
//     reaches past it.
//
// Reading the grant rather than the check makes the verdict independent of how
// the policy writes the bound: an every, object.subset, a set difference or a
// comprehension all refuse the second request, and a bound a later branch leaves
// open grants it, which a reading of the every form alone would miss.
//
// The enforcement point says which field is the requested authority and what
// bounds it, because neither is in the policy: a decision that bounds the
// request by the agent's own role but never by the delegator's grant looks, to
// the policy, like a decision that bounds the request. With a requested
// authority declared and no ceiling it is a candidate, asking what bounds the
// authority; with no declaration at all there is nothing to ask, as in
// PTD-OPA-009 to PTD-OPA-011.
//
// It reads only the grant side: a loose delegation on a decision that refuses is
// a deny that under-blocks, a different concern. Declared false negatives: a
// ceiling that lives in the data rather than in the request, which the witness
// cannot vary; and a decision that grants only specific named scopes, for which
// a synthetic element builds no request the decision grants, so the bound cannot
// be isolated.
func GrantsBeyondDelegatedScope(ctx context.Context, a Analysis) ([]Finding, error) {
	if a.EnforcementPoint == nil || a.Data == nil {
		return nil, nil
	}
	requested := requestedAuthorities(a.EnforcementPoint)
	if len(requested) == 0 {
		return nil, nil
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
	finding := Finding{
		PatternID:  GrantBeyondDelegatedScope,
		Decision:   decision,
		Path:       field.Path,
		Reads:      sites,
		Subject:    a.Shape.Subject,
		Confidence: a.Shape.Confidence.String(),
	}
	if len(field.BoundedBy) == 0 {
		finding.Verdict = VerdictCandidate
		finding.Summary = fmt.Sprintf("%s grants the authority requested in %s, and no enforcement point says what bounds it",
			decision, field.Path)
		return &finding, nil
	}

	ceilings := inputCeilings(field.BoundedBy)
	if len(ceilings) == 0 {
		// Every ceiling lives in the data, which the witness cannot vary: a
		// declared false negative rather than a guess.
		return nil, nil
	}
	base, err := boundedBaseline(ctx, a, decision, field.Path, ceilings)
	if err != nil {
		return nil, err
	}
	if base == nil {
		// Nothing the decision grants even with the authority within every
		// ceiling, so the bound cannot be isolated.
		return nil, nil
	}

	for _, ceiling := range ceilings {
		over, err := reachesPast(ctx, a, decision, base, field.Path, ceiling, ceilings)
		if err != nil {
			return nil, err
		}
		if over {
			finding.Verdict = VerdictFinding
			finding.Summary = fmt.Sprintf("%s grants the authority requested in %s without bounding it by %s",
				decision, field.Path, ceiling)
			finding.Note = "a request asking for one element outside " + ceiling + " is granted all the same"
			return &finding, nil
		}
	}
	return nil, nil
}

// inputCeilings keeps the ceilings that live in the request, the ones a witness
// can set. A ceiling in the data is a declared false negative.
func inputCeilings(bounded []string) []string {
	var ceilings []string
	for _, ceiling := range bounded {
		if strings.HasPrefix(ceiling, "input.") {
			ceilings = append(ceilings, ceiling)
		}
	}
	return ceilings
}

// boundedBaseline returns a request the decision grants with the requested
// authority reduced to a single synthetic element every ceiling also holds, or
// nil when the decision grants nothing even so. The authority fields are pinned
// and the rest of the request is left open, so partial evaluation solves the
// other conditions a grant needs, an action or a flag, and the only thing a
// later request changes is an element of the authority.
func boundedBaseline(ctx context.Context, a Analysis, decision, requested string, ceilings []string) (map[string]any, error) {
	request := map[string]any{}
	setInput(request, requested, []any{delegationElement})
	for _, ceiling := range ceilings {
		setInput(request, ceiling, []any{delegationElement})
	}
	fixed := append([]string{requested}, ceilings...)

	measured, err := reachOf(ctx, a.Bundle, a.Data, decision, request, unknownsExcept(a.Reads.InputPaths, fixed...), a.Limits)
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
		return example, nil
	}
	// Partial evaluation found no other condition to solve, so the pinned
	// request grants on its own, or the decision does not grant it at all.
	holds, err := opaengine.Holds(ctx, a.Bundle, a.Data, decision, request)
	if err != nil {
		return nil, err
	}
	if holds {
		return request, nil
	}
	return nil, nil
}

// reachesPast reports whether the decision still grants once the requested
// authority reaches one element past the ceiling under test, while staying
// within every other ceiling. Granting it means that ceiling makes no
// difference to the grant, so the authority reaches past it.
func reachesPast(ctx context.Context, a Analysis, decision string, base map[string]any, requested, ceiling string, ceilings []string) (bool, error) {
	over := copyInput(base)
	setInput(over, requested, []any{delegationElement, delegationBeyond})
	for _, each := range ceilings {
		if each == ceiling {
			continue
		}
		setInput(over, each, []any{delegationElement, delegationBeyond})
	}
	return opaengine.Holds(ctx, a.Bundle, a.Data, decision, over)
}

// delegationSites returns the places the decision reads the requested
// authority: the every expressions that iterate it. A field read nowhere the
// decision reaches is not one it grants on.
func delegationSites(reads *opaengine.ReadSet, decision, path string) []ReadSite {
	var sites []ReadSite
	for _, quantifier := range reads.Quantifiers {
		if quantifier.Domain != path || !reachesDecision(quantifier.Decisions, decision) {
			continue
		}
		sites = append(sites, ReadSite{Ref: quantifier.Domain, Rule: quantifier.Rule, File: quantifier.File, Line: quantifier.Line})
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
