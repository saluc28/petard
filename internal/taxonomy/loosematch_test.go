package taxonomy

import (
	"testing"

	"github.com/saluc28/petard/internal/opaengine"
)

// The case and the counter case sit in one decision of the fixture: the document
// is served when its id contains a marker (a substring), or when its id is the
// exact one. Only the substring is matched more loosely than the id it names, so
// only it is reported, and as a finding because a crafted id slips through.
func TestLooseMatchOnFixture(t *testing.T) {
	a := fixtureAnalysis(t)

	findings := GrantsOnLooseMatches(a)
	if len(findings) != 1 {
		t.Fatalf("findings = %v, want one", findings)
	}
	finding := findings[0]
	if finding.Path != "input.doc" || finding.Decision != "data.quill.library.allow_doc" {
		t.Errorf("finding on %s for %s, want input.doc for the library decision", finding.Path, finding.Decision)
	}
	if finding.Verdict != VerdictFinding {
		t.Errorf("verdict %s, want a finding: a substring match lets a crafted value through", finding.Verdict)
	}
	if len(finding.Reads) != 1 || finding.Reads[0].Rule != "data.quill.library.allow_doc" {
		t.Errorf("places to look = %+v, want the rule holding the match", finding.Reads)
	}
}

// A prefix, a suffix or a glob is often an intended wildcard, so it is a
// candidate rather than a finding. The engine reads the form, and the pattern
// judges it. This runs on a generated world to show the verdict rests on the
// policy, not the data.
func TestLooseMatchVerdictFollowsTheForm(t *testing.T) {
	cases := []struct {
		operator opaengine.CheckOperator
		verdict  Verdict
	}{
		{opaengine.CheckSubstring, VerdictFinding},
		{opaengine.CheckRegex, VerdictFinding},
		{opaengine.CheckPrefix, VerdictCandidate},
		{opaengine.CheckSuffix, VerdictCandidate},
		{opaengine.CheckGlob, VerdictCandidate},
	}
	for _, tc := range cases {
		a := Analysis{
			Shape: opaengine.Shape{Resource: "input.doc", Confidence: opaengine.ConfidenceNames},
			Reads: &opaengine.ReadSet{Checks: []opaengine.Check{{
				Request:   "input.doc",
				Value:     `"public"`,
				Operator:  tc.operator,
				Rule:      "data.t.allow",
				Decisions: []opaengine.CheckedDecision{{Name: "data.t.allow", Grants: true}},
			}}},
		}
		findings := GrantsOnLooseMatches(a)
		if len(findings) != 1 || findings[0].Verdict != tc.verdict {
			t.Errorf("%s: findings = %v, want one %s", tc.operator, findings, tc.verdict)
		}
	}
}

// A loose match on a part of the request that is neither the resource nor the
// action is not this pattern's concern: a name matched loosely is PTD-OPA-010.
func TestLooseMatchLeavesNonResourceFieldsAlone(t *testing.T) {
	a := Analysis{
		Shape: opaengine.Shape{Resource: "input.doc", Action: "input.action", Confidence: opaengine.ConfidenceNames},
		Reads: &opaengine.ReadSet{Checks: []opaengine.Check{{
			Request:   "input.group",
			Value:     `"admin-"`,
			Operator:  opaengine.CheckPrefix,
			Rule:      "data.t.allow",
			Decisions: []opaengine.CheckedDecision{{Name: "data.t.allow", Grants: true}},
		}}},
	}
	if findings := GrantsOnLooseMatches(a); len(findings) != 0 {
		t.Errorf("findings = %v, want none: the match is on neither the resource nor the action", findings)
	}
}

// With no resource and no action recognized there is nothing to call the
// enforced value, so the pattern stays quiet rather than guess.
func TestLooseMatchNeedsAResourceOrAction(t *testing.T) {
	a := Analysis{
		Shape: opaengine.Shape{Confidence: opaengine.ConfidenceNone},
		Reads: &opaengine.ReadSet{Checks: []opaengine.Check{{
			Request:   "input.doc",
			Value:     `"public"`,
			Operator:  opaengine.CheckSubstring,
			Rule:      "data.t.allow",
			Decisions: []opaengine.CheckedDecision{{Name: "data.t.allow", Grants: true}},
		}}},
	}
	if findings := GrantsOnLooseMatches(a); len(findings) != 0 {
		t.Errorf("findings = %v, want none with no resource or action recognized", findings)
	}
}
