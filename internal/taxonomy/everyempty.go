package taxonomy

import (
	"fmt"

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
				Reads:      []ReadSite{{Rule: quantifier.Rule, File: quantifier.File, Line: quantifier.Line}},
				Confidence: everyConfidence,
			})
		}
	}
	return sortedFindings(findings)
}
