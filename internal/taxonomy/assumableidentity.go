package taxonomy

import (
	"fmt"
	"strings"

	"github.com/saluc28/petard/internal/opaengine"
	"github.com/saluc28/petard/internal/pep"
)

// GrantOnAssumableIdentity is the id of the OPA instance of the assumable
// identity category.
const GrantOnAssumableIdentity = "PTD-OPA-011"

// GrantsOnAssumableIdentities finds the decisions that grant on a runtime
// identity somebody can assume in another layer.
//
// The three signals of the pattern, in order:
//
//  1. a check holds a part of the request against a value the policy writes,
//     input.caller.spiffe == "spiffe://.../sa/sync", and holding moves a
//     decision towards granting;
//  2. the enforcement point says that part is a runtime identity it asserts, a
//     workload the mesh proves and not a value the caller writes, so it is not
//     the grant on a forged name PTD-OPA-010 reports;
//  3. the enforcement point says who can assume that identity, in an
//     assumable_by entry. With one the match is a finding, without one a
//     candidate, and an identity it pins to a verified credential is neither.
//
// The first is structure and the engine reads it off the policy. The second and
// the third are not in the policy at all: the SPIFFE id of a service account and
// an agent identity bound to a verified credential are compared the same way,
// and only the declaration says that the first is assumable by whoever can
// deploy the service account while the second is pinned. Who can assume an
// identity lives in another layer, a deployment or a credential issuance, which
// the policy that trusts the identity cannot see.
//
// With no declaration at all it finds nothing, as PTD-OPA-009 and PTD-OPA-010
// do: which part of the request is an identity, and who can become it, is what
// the declaration says, so without one there is no question to ask.
func GrantsOnAssumableIdentities(a Analysis) []Finding {
	if a.EnforcementPoint == nil {
		return nil
	}
	type key struct{ decision, request string }
	byKey := map[key]int{}
	var findings []Finding

	for _, check := range a.Reads.Checks {
		if check.Operator == opaengine.CheckTrue {
			// A part of the request asked to be true is held against no identity.
			continue
		}
		field, answered, declared := fieldOfCheck(a.EnforcementPoint, check)
		if !declared || !field.Identity || field.Pinned {
			// Not an identity, or one the declaration pins to a verified
			// credential, which nobody below the grant can assume.
			continue
		}
		site := ReadSite{Ref: check.Expression(), Rule: check.Rule, File: check.File, Line: check.Line}

		for _, decision := range check.Decisions {
			if !decision.Grants {
				continue
			}
			k := key{decision.Name, answered}
			if at, seen := byKey[k]; seen {
				findings[at].Reads = append(findings[at].Reads, site)
				continue
			}
			byKey[k] = len(findings)
			findings = append(findings, identityFinding(a, decision.Name, answered, field, site))
		}
	}
	return sortedFindings(findings)
}

// identityFinding says what was found: the decision, the part of the request
// that carries the identity, and who can assume it when the declaration names
// anybody.
func identityFinding(a Analysis, decision, request string, field pep.Field, site ReadSite) Finding {
	finding := Finding{
		PatternID:  GrantOnAssumableIdentity,
		Verdict:    VerdictCandidate,
		Decision:   decision,
		Path:       request,
		Reads:      []ReadSite{site},
		Subject:    a.Shape.Subject,
		Confidence: a.Shape.Confidence.String(),
	}
	if len(field.AssumableBy) == 0 {
		finding.Summary = fmt.Sprintf("%s grants on the identity in %s, and no enforcement point says who can assume it",
			decision, request)
		return finding
	}

	// Both halves of the claim are declarations, of the identity and of who can
	// assume it, the first of the levels.
	var who []string
	for _, assumption := range field.AssumableBy {
		who = append(who, assumption.Principal)
	}
	finding.Verdict = VerdictFinding
	finding.Confidence = opaengine.ConfidenceDeclared.String()
	if via := field.AssumableBy[0].Via; via != "" {
		finding.Note = "assumed by " + via
	}
	finding.Summary = fmt.Sprintf("%s grants on the identity in %s, and %s can assume it",
		decision, request, strings.Join(who, ", "))
	return finding
}
