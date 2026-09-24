package taxonomy

import (
	"fmt"

	"github.com/saluc28/petard/internal/opaengine"
	"github.com/saluc28/petard/internal/pep"
)

// SelfAssertedExemption is the id of the OPA instance of the self-asserted
// exemption category.
const SelfAssertedExemption = "PTD-OPA-009"

// SelfAssertedExemptions finds the refusals a request can lift by saying it is
// exempt.
//
// The two signals of the pattern, in order:
//
//  1. a check on a part of the request lifts a refusal of a decision: it lands
//     on the side that grants after crossing a negation, as not
//     input.emergency does in a rule the decision asks not to hold;
//  2. the enforcement point says whoever sends the request sets that part.
//
// The first is structure and the engine reads it off the policy. The second is
// not in the policy at all: the same not input.mfa is an exemption the caller
// grants themselves when the body carries it, and a second factor the gateway
// proved when the session does. A part the declaration puts elsewhere is left
// alone, and a part it does not cover is a candidate, since whoever sets it may
// be the caller.
//
// With no declaration at all it finds nothing, on purpose. The first signal is
// also how every condition of a policy on a request the caller writes whole
// reads: in an admission review a container that sets its limits lifts the
// violation about limits, and complying looks exactly like claiming an
// exemption. Which parts of the request are the caller's to assert is what the
// declaration says, so without one there is no question to ask.
func SelfAssertedExemptions(a Analysis) []Finding {
	if a.EnforcementPoint == nil {
		return nil
	}
	type key struct{ decision, request string }
	byKey := map[key]int{}
	var findings []Finding

	for _, check := range a.Reads.Checks {
		field, declared := fieldOfCheck(a.EnforcementPoint, check)
		if declared && field.SetBy != pep.SetByCaller {
			continue
		}
		site := ReadSite{Ref: check.Expression(), Rule: check.Rule, File: check.File, Line: check.Line}

		for _, decision := range check.Decisions {
			if !decision.Exception {
				continue
			}
			k := key{decision.Name, check.Request}
			if at, seen := byKey[k]; seen {
				findings[at].Reads = append(findings[at].Reads, site)
				continue
			}
			byKey[k] = len(findings)
			findings = append(findings, exemptionFinding(a, check, decision.Name, site, declared))
		}
	}
	return sortedFindings(findings)
}

// fieldOfCheck returns what an enforcement point says about the part of the
// request a check reads. A value searched in a collection of the request is
// one of its elements, and the declaration may speak about the elements
// rather than about the collection.
func fieldOfCheck(point *pep.EnforcementPoint, check opaengine.Check) (pep.Field, bool) {
	if check.Operator == opaengine.CheckContains {
		if field, found := point.FieldFor(check.Request + "[_]"); found {
			return field, true
		}
	}
	return point.FieldFor(check.Request)
}

// exemptionFinding says what was found: the part of the request, the decision
// whose refusal it lifts, and who sets it.
func exemptionFinding(a Analysis, check opaengine.Check, decision string, site ReadSite, declared bool) Finding {
	finding := Finding{
		PatternID:  SelfAssertedExemption,
		Verdict:    VerdictCandidate,
		Decision:   decision,
		Path:       check.Request,
		Reads:      []ReadSite{site},
		Subject:    a.Shape.Subject,
		Confidence: a.Shape.Confidence.String(),
	}
	if !declared {
		finding.Summary = fmt.Sprintf("%s lifts a refusal in %s, and no enforcement point says who sets it",
			check.Request, decision)
		return finding
	}

	// The claim rests on the declaration of the enforcement point, which is a
	// declaration of the request, the first of the levels.
	finding.Verdict = VerdictFinding
	finding.Confidence = opaengine.ConfidenceDeclared.String()
	finding.Summary = fmt.Sprintf("%s lifts a refusal in %s, and whoever sends the request sets it (%s)",
		check.Request, decision, a.EnforcementPoint.File)
	return finding
}
