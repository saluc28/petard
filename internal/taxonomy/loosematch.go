package taxonomy

import (
	"fmt"
	"strconv"
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
//
// The resource and the action are recognized on their own, whoever is asking:
// a router that grants on input.path and input.method reads no subject, and a
// subject declared from outside says nothing about the rest of the request. A
// finding carries the level they were recognized at.
func GrantsOnLooseMatches(a Analysis) []Finding {
	target := opaengine.RecognizeTarget(a.Reads)
	resource, action := target.Resource, target.Action
	if resource == "" && action == "" {
		return nil
	}
	type key struct {
		decision, request string
		onData            bool
	}
	byKey := map[key]int{}
	var findings []Finding

	judge := func(check opaengine.Check, onData bool) {
		if !check.Operator.Loose() {
			return
		}
		if !partUnder(check.Request, resource) && !partUnder(check.Request, action) {
			// The loose match is on neither the resource nor the action, so it is
			// not this pattern's concern: a name matched loosely is PTD-OPA-010.
			return
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
			k := key{decision.Name, check.Request, onData}
			if at, seen := byKey[k]; seen {
				findings[at].Reads = append(findings[at].Reads, site)
				continue
			}
			byKey[k] = len(findings)
			finding := looseMatchFinding(check, decision.Name, site)
			if onData {
				finding = looseMatchOnDataFinding(check, decision.Name, site)
			}
			finding.Subject = a.Shape.Subject
			finding.Confidence = target.Confidence.String()
			findings = append(findings, finding)
		}
	}
	for _, check := range a.Reads.Checks {
		judge(check, false)
	}
	// The same matches against a value the decision reads from the data: the
	// marker a path is searched for is as often a list in a configuration
	// document as a string in the policy.
	for _, match := range a.Reads.DataMatches {
		judge(match, true)
	}
	return sortedFindings(findings)
}

// looseMatchFinding says what was found: the decision, the part of the request,
// and how loosely it is matched. A mid-string match is a finding, since a value
// embedding the written one passes; an affix or a glob is a candidate, since the
// looseness may be the intended wildcard.
func looseMatchFinding(check opaengine.Check, decision string, site ReadSite) Finding {
	finding := Finding{
		PatternID: GrantOnLooseMatch,
		Decision:  decision,
		Path:      check.Request,
		Value:     check.Value,
		Reads:     []ReadSite{site},
	}
	if check.Operator.MidString() {
		finding.Verdict = VerdictFinding
		finding.Summary = fmt.Sprintf("%s grants on %s matched as %s, so a value that embeds %s passes",
			decision, check.Request, looseness(check.Operator), embedded(check))
		return finding
	}
	finding.Verdict = VerdictCandidate
	finding.Summary = fmt.Sprintf("%s grants on %s matched by %s, wider than the value it names",
		decision, check.Request, looseness(check.Operator))
	return finding
}

// looseMatchOnDataFinding is looseMatchFinding for a match against a value read
// from the data. A substring is a finding whatever the document holds: a value
// that embeds one of its entries passes. A prefix or a suffix is a candidate as
// it is when the policy writes it, and so is a glob or a regex, whose pattern is
// in the document and not in the policy to be read.
func looseMatchOnDataFinding(check opaengine.Check, decision string, site ReadSite) Finding {
	finding := Finding{
		PatternID: GrantOnLooseMatch,
		Decision:  decision,
		Path:      check.Request,
		Value:     check.Value,
		Reads:     []ReadSite{site},
	}
	if check.Operator == opaengine.CheckSubstring {
		finding.Verdict = VerdictFinding
		finding.Summary = fmt.Sprintf("%s grants on %s matched as a substring of a value read from %s, so a value that embeds one passes",
			decision, check.Request, check.Value)
		return finding
	}
	form := "a pattern"
	switch check.Operator {
	case opaengine.CheckPrefix:
		form = "a prefix"
	case opaengine.CheckSuffix:
		form = "a suffix"
	}
	finding.Verdict = VerdictCandidate
	finding.Summary = fmt.Sprintf("%s grants on %s matched by %s read from %s, wider than the value it names",
		decision, check.Request, form, check.Value)
	return finding
}

// embedded is what a value has to hold for a mid-string match to pass, as Rego:
// the value the policy writes, less the wildcards at the ends of a glob, which
// are the match and not what is matched.
func embedded(check opaengine.Check) string {
	if check.Operator != opaengine.CheckGlobEmbedded {
		return check.Value
	}
	pattern, err := strconv.Unquote(check.Value)
	if err != nil {
		return check.Value
	}
	return strconv.Quote(strings.Trim(pattern, "*"))
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
	case opaengine.CheckGlobEmbedded:
		return "a glob with a wildcard at each end"
	case opaengine.CheckRegex:
		return "an unanchored regex"
	case opaengine.CheckRegexAnchored:
		return "a regex anchored at one end"
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
