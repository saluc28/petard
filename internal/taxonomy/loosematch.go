package taxonomy

import (
	"fmt"
	"strings"

	"github.com/saluc28/petard/internal/opaengine"
)

// GrantOnLooseMatch is the id of the OPA instance of the loose enforcement
// match category.
const GrantOnLooseMatch = "PTD-OPA-012"

// GrantsOnLooseMatches finds the decisions that grant on a resource or an action
// matched more loosely than the enforcement point acts on it.
//
// The signal, in two parts:
//
//  1. a decision grants on a check that holds a part of the request against a
//     value the policy writes with an operator wider than equality: a substring,
//     a prefix or suffix, a glob, or an unanchored regex;
//  2. that part of the request is the resource or the action the shape
//     recognizer names, the thing the decision authorizes.
//
// A substring and an unanchored regex match the written value embedded anywhere,
// so a crafted value slips through: `/app/.admin-preview` embeds `.admin`, and
// the router serves a resource the policy never meant to allow. That is the
// confused deputy, a finding. A prefix, a suffix or a glob is often an intended
// route wildcard, so it is reported as a candidate: a loose grant to weigh
// against what the enforcement point does, not a defect on its own.
//
// It reports only the grant side. A loose match on the side that refuses is a
// deny that under-blocks, an admission policy validating the object it is handed,
// which is a different concern: the confused deputy here is a grant on more than
// the value it names.
//
// It needs no enforcement point and no data: the looseness is in the policy, and
// the shape says which part of the request is the resource or the action. Where
// neither is recognized there is nothing to call the enforced value, so it
// stays quiet.
func GrantsOnLooseMatches(a Analysis) []Finding {
	resource, action := a.Shape.Resource, a.Shape.Action
	if resource == "" && action == "" {
		return nil
	}
	type key struct{ decision, request string }
	byKey := map[key]int{}
	var findings []Finding

	for _, check := range a.Reads.Checks {
		if !check.Operator.Loose() {
			continue
		}
		if !partUnder(check.Request, resource) && !partUnder(check.Request, action) {
			// The loose match is on neither the resource nor the action, so it is
			// not this pattern's concern: a name matched loosely is PTD-OPA-010.
			continue
		}
		site := ReadSite{Ref: check.Expression(), Rule: check.Rule, File: check.File, Line: check.Line}

		for _, decision := range check.Decisions {
			if !decision.Grants {
				continue
			}
			if a.Reads.Denies(decision.Name) {
				// A loose match on the side that refuses is a deny that
				// under-blocks, an admission policy validating the object it is
				// handed, which is not the confused deputy this pattern reports.
				continue
			}
			k := key{decision.Name, check.Request}
			if at, seen := byKey[k]; seen {
				findings[at].Reads = append(findings[at].Reads, site)
				continue
			}
			byKey[k] = len(findings)
			findings = append(findings, looseMatchFinding(a, check, decision.Name, site))
		}
	}
	return sortedFindings(findings)
}

// looseMatchFinding says what was found: the decision, the part of the request,
// and how loosely it is matched. A mid-string match is a finding, since a value
// embedding the written one passes; an affix or a glob is a candidate, since the
// looseness may be the intended wildcard.
func looseMatchFinding(a Analysis, check opaengine.Check, decision string, site ReadSite) Finding {
	finding := Finding{
		PatternID:  GrantOnLooseMatch,
		Decision:   decision,
		Path:       check.Request,
		Value:      check.Value,
		Reads:      []ReadSite{site},
		Subject:    a.Shape.Subject,
		Confidence: a.Shape.Confidence.String(),
	}
	if check.Operator.MidString() {
		finding.Verdict = VerdictFinding
		finding.Summary = fmt.Sprintf("%s grants on %s matched as %s, so a value that embeds %s passes",
			decision, check.Request, looseness(check.Operator), check.Value)
		return finding
	}
	finding.Verdict = VerdictCandidate
	finding.Summary = fmt.Sprintf("%s grants on %s matched by %s, wider than the value it names",
		decision, check.Request, looseness(check.Operator))
	return finding
}

// looseness names a loose operator the way a report reads it.
func looseness(operator opaengine.CheckOperator) string {
	switch operator {
	case opaengine.CheckSubstring:
		return "a substring"
	case opaengine.CheckPrefix:
		return "a prefix"
	case opaengine.CheckSuffix:
		return "a suffix"
	case opaengine.CheckGlob:
		return "a glob"
	case opaengine.CheckRegex:
		return "an unanchored regex"
	default:
		return "a loose match"
	}
}

// partUnder reports whether a part of the request is the named part or a field
// of it, so a match on input.doc or on input.doc.name both count as the resource
// input.doc.
func partUnder(request, part string) bool {
	if part == "" {
		return false
	}
	return request == part || strings.HasPrefix(request, part+".") || strings.HasPrefix(request, part+"[")
}
