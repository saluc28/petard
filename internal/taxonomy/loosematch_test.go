package taxonomy

import (
	"path/filepath"
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
		{opaengine.CheckGlobEmbedded, VerdictFinding},
		{opaengine.CheckPrefix, VerdictCandidate},
		{opaengine.CheckSuffix, VerdictCandidate},
		{opaengine.CheckGlob, VerdictCandidate},
		{opaengine.CheckRegexAnchored, VerdictCandidate},
	}
	for _, tc := range cases {
		reads := &opaengine.ReadSet{
			InputPaths: []string{"input.doc"},
			Checks: []opaengine.Check{{
				Request:   "input.doc",
				Value:     `"public"`,
				Operator:  tc.operator,
				Rule:      "data.t.allow",
				Decisions: []opaengine.CheckedDecision{{Name: "data.t.allow", Grants: true}},
			}},
		}
		findings := GrantsOnLooseMatches(Analysis{Reads: reads, Shape: opaengine.RecognizeShape(reads)})
		if len(findings) != 1 || findings[0].Verdict != tc.verdict {
			t.Errorf("%s: findings = %v, want one %s", tc.operator, findings, tc.verdict)
		}
	}
}

// A loose match on a part of the request that is neither the resource nor the
// action is not this pattern's concern: a name matched loosely is PTD-OPA-010.
func TestLooseMatchLeavesNonResourceFieldsAlone(t *testing.T) {
	reads := &opaengine.ReadSet{
		InputPaths: []string{"input.action", "input.doc", "input.group"},
		Checks: []opaengine.Check{{
			Request:   "input.group",
			Value:     `"admin-"`,
			Operator:  opaengine.CheckPrefix,
			Rule:      "data.t.allow",
			Decisions: []opaengine.CheckedDecision{{Name: "data.t.allow", Grants: true}},
		}},
	}
	a := Analysis{Reads: reads, Shape: opaengine.RecognizeShape(reads)}
	if findings := GrantsOnLooseMatches(a); len(findings) != 0 {
		t.Errorf("findings = %v, want none: the match is on neither the resource nor the action", findings)
	}
}

// With no resource and no action recognized there is nothing to call the
// enforced value, so the pattern stays quiet rather than guess.
func TestLooseMatchNeedsAResourceOrAction(t *testing.T) {
	reads := &opaengine.ReadSet{
		InputPaths: []string{"input.ref"},
		Checks: []opaengine.Check{{
			Request:   "input.ref",
			Value:     `"public"`,
			Operator:  opaengine.CheckSubstring,
			Rule:      "data.t.allow",
			Decisions: []opaengine.CheckedDecision{{Name: "data.t.allow", Grants: true}},
		}},
	}
	a := Analysis{Reads: reads, Shape: opaengine.RecognizeShape(reads)}
	if findings := GrantsOnLooseMatches(a); len(findings) != 0 {
		t.Errorf("findings = %v, want none with no resource or action recognized", findings)
	}
}

// The marker a path is searched for is as often read from a document as written
// in the policy, and the match is as loose either way. This is the shape the
// fix of defenseclaw's F-0543 replaced: a path that embeds one of the markers of
// an allow list entry passes. A prefix read from the data is a candidate, as a
// written one is, and a match by whole components is neither.
func TestLooseMatchOnAValueReadFromTheData(t *testing.T) {
	tests := []struct {
		name    string
		match   string
		verdict Verdict
	}{
		{name: "a substring", match: `contains(lower(input.path), lower(marker))`, verdict: VerdictFinding},
		{name: "a prefix", match: `startswith(input.path, marker)`, verdict: VerdictCandidate},
		{name: "whole components", match: `marker in split(input.path, "/")`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := `package admission

# METADATA
# entrypoint: true
default allowed := false

allowed if {
	some entry in data.allow_list
	entry.name == input.target_name
	path_matches(entry)
}

path_matches(entry) if {
	some marker in entry.source_path_contains
	` + tt.match + `
}
`
			dir := t.TempDir()
			writeCaseFile(t, filepath.Join(dir, "p.rego"), policy)
			bundle, err := opaengine.Load([]string{dir}, opaengine.ParseModeV1)
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			reads, err := opaengine.Reads(bundle, opaengine.Limits{})
			if err != nil {
				t.Fatalf("Reads() error = %v", err)
			}

			findings := GrantsOnLooseMatches(Analysis{Bundle: bundle, Reads: reads, Shape: opaengine.RecognizeShape(reads)})
			if tt.verdict == "" {
				if len(findings) != 0 {
					t.Errorf("findings = %v, want none", findings)
				}
				return
			}
			if len(findings) != 1 {
				t.Fatalf("findings = %v, want one", findings)
			}
			finding := findings[0]
			if finding.Verdict != tt.verdict || finding.Path != "input.path" ||
				finding.Value != "data.allow_list[_].source_path_contains[_]" {
				t.Errorf("a %s on %s against %s, want a %s on input.path against the markers of the entry",
					finding.Verdict, finding.Path, finding.Value, tt.verdict)
			}
		})
	}
}

// The resource and the action are recognized whoever is asking. A router that
// grants on the method and the path reads no subject, and a subject declared
// from outside says who is asking and nothing about the rest of the request:
// either way the path matched as a substring is reported, at the level its name
// was recognized at and not at the level of the subject.
func TestLooseMatchNeedsNoSubject(t *testing.T) {
	const policy = `package example

# METADATA
# entrypoint: true
default allow_route := false

allow_route if {
	input.method == "GET"
	contains(input.path, "/public/")
}

# METADATA
# entrypoint: true
default allow_admin := false

allow_admin if input.operator == "root"
`
	dir := t.TempDir()
	writeCaseFile(t, filepath.Join(dir, "p.rego"), policy)
	bundle, err := opaengine.Load([]string{dir}, opaengine.ParseModeV1)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	reads, err := opaengine.Reads(bundle, opaengine.Limits{})
	if err != nil {
		t.Fatalf("Reads() error = %v", err)
	}

	for _, subject := range []string{"", "input.operator"} {
		shape, err := opaengine.ShapeOf(reads, subject)
		if err != nil {
			t.Fatalf("ShapeOf() error = %v", err)
		}
		if target := shape.Target(); target.Resource != "input.path" || target.Action != "input.method" || target.Confidence == shape.Confidence {
			t.Fatalf("with the subject %q, the shape asks for %q and %q at level %s, the level of the subject: "+
				"the test is about a path and a method recognized apart from it",
				subject, target.Resource, target.Action, target.Confidence)
		}

		findings := GrantsOnLooseMatches(Analysis{Bundle: bundle, Reads: reads, Shape: shape})
		if len(findings) != 1 {
			t.Fatalf("with the subject %q, findings = %v, want one", subject, findings)
		}
		finding := findings[0]
		if finding.Path != "input.path" || finding.Verdict != VerdictFinding || finding.Confidence != "D" {
			t.Errorf("with the subject %q, a %s on %s at level %s, want a finding on input.path at level D",
				subject, finding.Verdict, finding.Path, finding.Confidence)
		}
	}
}
