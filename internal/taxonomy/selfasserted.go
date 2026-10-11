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
// be the caller. So is a part that stands for several, input.flags[_], when the
// declaration gives some of them to the caller and others to somebody else:
// which one the policy reads is in a key, and the key is not the caller's by
// that.
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
		setBy := whoSets(a.EnforcementPoint, check)
		if setBy == setBySomebodyElse {
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
			findings = append(findings, exemptionFinding(a, check, decision.Name, site, setBy))
		}
	}
	return sortedFindings(findings)
}

// setter is what an enforcement point says about who sets the part of the
// request a check reads.
type setter int

const (
	// setByNobodyDeclared is a part no declaration speaks for.
	setByNobodyDeclared setter = iota

	// setByCaller is a part whoever sends the request sets, all of it.
	setByCaller

	// setBySomebodyElse is a part the enforcement point or an issuer sets, all
	// of it.
	setBySomebodyElse

	// setByCallerInPart is a part that stands for several, of which the caller
	// sets some, or of which only some are declared at all.
	setByCallerInPart
)

// whoSets asks the enforcement point about the part of the request a check
// reads, over every path that part stands for.
func whoSets(point *pep.EnforcementPoint, check opaengine.Check) setter {
	fields, whole := point.FieldsFor(check.Request)
	if check.Operator == opaengine.CheckContains {
		// A value searched in a collection of the request is one of its
		// elements, and the declaration may speak about the elements.
		if ofElements, wholeElements := point.FieldsFor(check.Request + "[_]"); len(ofElements) > 0 {
			fields, whole = ofElements, wholeElements
		}
	}
	if len(fields) == 0 {
		return setByNobodyDeclared
	}
	callers := 0
	for _, field := range fields {
		if field.SetBy == pep.SetByCaller {
			callers++
		}
	}
	switch {
	case whole && callers == len(fields):
		return setByCaller
	case whole && callers == 0:
		return setBySomebodyElse
	default:
		return setByCallerInPart
	}
}

// fieldOfCheck returns what an enforcement point says about the part of the
// request a check reads, and the path of the part it answered for. A value
// searched in a collection of the request is one of its elements, and the
// declaration may speak about the elements rather than about the collection.
func fieldOfCheck(point *pep.EnforcementPoint, check opaengine.Check) (pep.Field, string, bool) {
	if check.Operator == opaengine.CheckContains {
		element := check.Request + "[_]"
		if field, found := point.FieldFor(element); found {
			return field, element, true
		}
	}
	field, found := point.FieldFor(check.Request)
	return field, check.Request, found
}

// exemptionFinding says what was found: the part of the request, the decision
// whose refusal it lifts, and who sets it.
func exemptionFinding(a Analysis, check opaengine.Check, decision string, site ReadSite, setBy setter) Finding {
	finding := Finding{
		PatternID:  SelfAssertedExemption,
		Verdict:    VerdictCandidate,
		Decision:   decision,
		Path:       check.Request,
		Reads:      []ReadSite{site},
		Subject:    a.Shape.Subject,
		Confidence: a.Shape.Confidence.String(),
	}
	switch setBy {
	case setByNobodyDeclared:
		finding.Summary = fmt.Sprintf("%s lifts a refusal in %s, and no enforcement point says who sets it",
			check.Request, decision)
		return finding
	case setByCallerInPart:
		finding.Summary = fmt.Sprintf("%s lifts a refusal in %s, and the enforcement point does not give all of it to one setter (%s)",
			check.Request, decision, a.EnforcementPoint.File)
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
