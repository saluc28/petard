package taxonomy

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/saluc28/petard/internal/opaengine"
)

// EveryOverEmptyDomain is the id of the OPA instance of the fail-open category
// that rests on a quantifier rather than on a missing document.
const EveryOverEmptyDomain = "PTD-OPA-007"

// everyConfidence is the level this pattern reaches: the same B as the other
// two fail-open instances. The signal that decides whether a vacuous truth
// grants or denies is the side the check applies on, and that depends on the
// PEP, which is the shared weak point of the family.
const everyConfidence = "B"

// GrantsOnEmptyEvery finds the checks written with `every` that stop applying
// when their domain is empty, and leaves out the ones the decision refuses with
// the domain empty.
//
// FailOpenOnEmptyEvery reads the body, and recognizes one guard: a count of the
// domain next to the every. A guard is as often an iteration of the domain, a
// `some` that binds one of its elements, or a count in another rule the
// decision also asks for, and no list of shapes covers them. So each match is
// put to the decision: with the domain an empty list, then an empty object, and
// every other part of the request left open, partial evaluation says whether
// anything can still make the decision hold. When nothing can, something
// guards the every, wherever it is written, and the match is dropped.
//
// A match the question cannot be asked about stays as the body reads: a domain
// in the data or under an element of a list, a decision declared to deny, a
// decision that reads documents when none were given, and a decision OPA
// panics on.
func GrantsOnEmptyEvery(ctx context.Context, a Analysis) ([]Finding, error) {
	var kept []Finding
	for _, finding := range FailOpenOnEmptyEvery(a.Reads) {
		refused, err := refusesTheEmptyDomain(ctx, a, finding.Decision, finding.Path)
		if err != nil {
			return nil, err
		}
		if !refused {
			kept = append(kept, finding)
		}
	}
	return kept, nil
}

// refusesTheEmptyDomain reports whether a decision holds for no request that
// carries the domain empty, and false when that cannot be asked.
func refusesTheEmptyDomain(ctx context.Context, a Analysis, decision, domain string) (bool, error) {
	if !strings.HasPrefix(domain, "input.") || strings.Contains(domain, "[") || a.Reads.Denies(decision) {
		return false, nil
	}
	data := a.Data
	if data == nil {
		for _, read := range a.Reads.Reads {
			if reachesDecision(read.Decisions, decision) {
				return false, nil
			}
		}
		data = opaengine.NoData()
	}

	unknowns := unknownsExcept(a.Reads.InputPaths, domain)
	for _, empty := range []any{[]any{}, map[string]any{}} {
		request := map[string]any{}
		setInput(request, domain, empty)

		measured, err := reachOf(ctx, a.Bundle, data, decision, request, unknowns, a.Limits)
		var panicked *opaengine.EvaluatorPanicError
		if errors.As(err, &panicked) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if !measured.nothing() {
			return false, nil
		}
	}
	return true, nil
}

// FailOpenOnEmptyEvery finds the checks written with `every` that stop applying
// when their domain is empty.
//
// `every x in xs { cond }` holds when nothing in `xs` breaks `cond`, and an
// empty `xs` breaks nothing, so the quantifier is vacuously true. On the side
// that grants, that is a check whose domain of application shrinks to nothing
// exactly when the request brings an empty collection.
//
// The signals, in order:
//
//  1. an entrypoint reaches an every expression, which the walk collects as a
//     quantifier with the decisions that depend on it;
//  2. the every is on the granting side: a decision reaches it with an even
//     number of negations, or an odd one when it is declared to deny, so its
//     vacuous truth lets the request through rather than stopping it;
//  3. the domain derives from input or data, so the request or the documents
//     can make it empty, rather than being a literal that never is;
//  4. no guard in the body forces the domain non-empty first, which is the
//     counter case the fixture pairs it with.
//
// It emits a finding, not an escalation: like the other fail-open patterns it
// reports a check that does not apply, not a principal reaching another. No
// write model is needed, because nothing is written; the defect is that a
// collection can be empty.
func FailOpenOnEmptyEvery(reads *opaengine.ReadSet) []Finding {
	var findings []Finding
	seen := map[string]bool{}

	for _, quantifier := range reads.Quantifiers {
		if quantifier.Domain == "" || quantifier.Guarded {
			// A literal domain cannot be emptied by the request, and a guarded
			// one is the counter case: neither leaves a vacuous grant.
			continue
		}
		for _, decision := range quantifier.Decisions {
			if decision.UnderNegation {
				// A vacuous truth reached through a negation denies, which is
				// fail-closed and not a defect.
				continue
			}
			key := decision.Name + "\x00" + quantifier.Domain
			if seen[key] {
				continue
			}
			seen[key] = true

			findings = append(findings, Finding{
				PatternID: EveryOverEmptyDomain,
				Verdict:   VerdictFinding,
				Summary: fmt.Sprintf("%s lets the request through when %s is empty, because the every over it is vacuously true",
					decision.Name, quantifier.Domain),
				Decision:   decision.Name,
				Path:       quantifier.Domain,
				Reads:      []ReadSite{{Ref: quantifier.Domain, Rule: quantifier.Rule, File: quantifier.File, Line: quantifier.Line}},
				Confidence: everyConfidence,
			})
		}
	}
	return sortedFindings(findings)
}
