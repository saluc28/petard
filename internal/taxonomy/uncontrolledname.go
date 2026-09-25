package taxonomy

import (
	"fmt"
	"strings"

	"github.com/saluc28/petard/internal/opaengine"
	"github.com/saluc28/petard/internal/pep"
	"github.com/saluc28/petard/internal/writemodel"
)

// GrantOnUncontrolledName is the id of the OPA instance of the uncontrolled
// identifier category.
const GrantOnUncontrolledName = "PTD-OPA-010"

// GrantsOnUncontrolledNames finds the decisions that grant on a name somebody
// outside the policy picks.
//
// The three signals of the pattern, in order:
//
//  1. a check holds a part of the request against a value the policy writes,
//     input.groups[_] == "security", and holding moves a decision towards
//     granting;
//  2. the enforcement point says an issuer sets that part, and that what the
//     issuer puts there is a name;
//  3. the write model names who can make the issuer say a name, in an entry on
//     that part of the request.
//
// The first is structure and the engine reads it off the policy. The second is
// not in the policy at all: a group called security and the id the directory
// gave it are compared the same way, and only the declaration says that
// whoever creates or renames a group picks the first. The third decides between
// a finding and a candidate, the way the write model does for a document. A
// part the declaration puts on the caller is not this pattern's to report: a
// comparison of what the caller writes with a constant is how every policy
// says what is being asked for.
//
// With no declaration at all it finds nothing, for the same reason.
func GrantsOnUncontrolledNames(a Analysis) ([]Finding, error) {
	if a.EnforcementPoint == nil {
		return nil, nil
	}
	type key struct{ decision, request string }
	byKey := map[key]int{}
	var findings []Finding

	for _, check := range a.Reads.Checks {
		if check.Operator == opaengine.CheckTrue {
			// A part of the request asked to be true is compared with no name.
			continue
		}
		field, answered, declared := fieldOfCheck(a.EnforcementPoint, check)
		if !declared || field.SetBy != pep.SetByIssuer || field.Identifier != pep.IdentifierName {
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
			finding, err := nameFinding(a, decision.Name, answered, field, site)
			if err != nil {
				return nil, err
			}
			byKey[k] = len(findings)
			findings = append(findings, finding)
		}
	}
	return sortedFindings(findings), nil
}

// nameFinding says what was found: the decision, the part of the request that
// carries the name, who vouches for it, and who can make them say it when the
// write model names anybody.
func nameFinding(a Analysis, decision, request string, field pep.Field, site ReadSite) (Finding, error) {
	finding := Finding{
		PatternID:  GrantOnUncontrolledName,
		Verdict:    VerdictCandidate,
		Decision:   decision,
		Path:       request,
		Reads:      []ReadSite{site},
		Subject:    a.Shape.Subject,
		Confidence: a.Shape.Confidence.String(),
	}
	entries, err := nameWriters(a.Model, request)
	if err != nil {
		return Finding{}, err
	}
	if len(entries) == 0 {
		finding.Summary = fmt.Sprintf("%s grants on a name in %s, which %s hands over, and no write model says who can make it say one",
			decision, request, field.Issuer)
		return finding, nil
	}

	// Both halves of the claim are declarations, of who sets the part of the
	// request and of who can make the issuer say it, the first of the levels.
	var writers []string
	for _, entry := range entries {
		for _, writer := range entry.WritableBy {
			writers = append(writers, writer.Principal)
		}
	}
	finding.Verdict = VerdictFinding
	finding.Confidence = opaengine.ConfidenceDeclared.String()
	finding.ViaWritePath = entries[0].RawPath
	finding.Via = entries[0].WritableBy[0].Via
	finding.Summary = fmt.Sprintf("%s grants on a name in %s, and %s can make %s say one",
		decision, request, strings.Join(writers, ", "), field.Issuer)
	return finding, nil
}

// nameWriters returns the entries of the write model on a part of the request:
// who can make the issuer say a name there. A write model speaks about the
// request the way it speaks about a document, and an entry on input.groups[_]
// is read by nothing else, since every other question it answers is about a
// read of data.
func nameWriters(model *writemodel.Model, request string) ([]writemodel.Entry, error) {
	if model == nil {
		return nil, nil
	}
	path, err := writemodel.ParsePath(request)
	if err != nil {
		return nil, err
	}
	return model.Covering(path), nil
}
