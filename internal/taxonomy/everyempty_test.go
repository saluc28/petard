package taxonomy

import (
	"path/filepath"
	"testing"

	"github.com/saluc28/petard/internal/opaengine"
)

// The case of PTD-OPA-007 on the real fixture: the merge decision approves when
// every reviewer approves, and with no reviewers the every is vacuously true, so
// the merge goes through unreviewed. The finding has to come out of the real
// policy, not out of a ReadSet written to produce it.
func TestFailOpenOnEmptyEveryOnFixture(t *testing.T) {
	reads, _, _ := analyzeFixture(t)

	findings := FailOpenOnEmptyEvery(reads)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want the one unguarded every the fixture holds:\n%v", len(findings), findings)
	}

	f := findings[0]
	if f.PatternID != EveryOverEmptyDomain {
		t.Errorf("pattern = %s, want %s", f.PatternID, EveryOverEmptyDomain)
	}
	if f.Verdict != VerdictFinding {
		t.Errorf("verdict = %s, want a finding", f.Verdict)
	}
	if f.Decision != "data.quill.review.allow_unguarded" {
		t.Errorf("decision = %q, want the unguarded merge decision", f.Decision)
	}
	if f.Path != "input.reviews" {
		t.Errorf("domain = %q, want input.reviews", f.Path)
	}
	if len(f.Reads) == 0 || f.Reads[0].Line == 0 {
		t.Errorf("the finding points at no line of policy: %+v", f.Reads)
	}
}

// The counter case is the guarded decision: the same every over the same domain,
// behind count(input.reviews) > 0, which denies the empty case. Only the guard
// tells them apart, and without signal 4 the pattern would be a lint on the
// presence of an every.
func TestFailOpenOnEmptyEveryLeavesTheGuardedCaseAlone(t *testing.T) {
	reads, _, _ := analyzeFixture(t)

	for _, f := range FailOpenOnEmptyEvery(reads) {
		if f.Decision == "data.quill.review.allow_guarded" {
			t.Errorf("the guarded counter case was reported: %s", f)
		}
	}

	// And the every really is there for the guarded decision, so the silence
	// comes from the guard and not from having missed the construct.
	var guardedSeen bool
	for _, q := range reads.Quantifiers {
		for _, d := range q.Decisions {
			if d.Name == "data.quill.review.allow_guarded" {
				guardedSeen = true
				if !q.Guarded {
					t.Error("the guarded every is not marked guarded, so this test proves nothing")
				}
			}
		}
	}
	if !guardedSeen {
		t.Error("the guarded decision reaches no every, so the counter case is not exercised")
	}
}

// A guard is not always a count next to the every. Each of these decisions
// refuses a request that carries the domain empty, by a guard the body does not
// show where the every is, and the question put to the decision is what finds
// it. The one with no guard is still reported.
func TestGrantsOnEmptyEveryAsksTheDecision(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		reported bool
	}{
		{
			name: "no guard",
			body: `allow if {
	every review in input.reviews {
		review.approved
	}
}
`,
			reported: true,
		},
		{
			name: "an iteration of the domain",
			body: `allow if {
	input.reviews[_]
	every review in input.reviews {
		review.approved
	}
}
`,
		},
		{
			name: "a some that binds an element",
			body: `allow if {
	some first in input.reviews
	first.id
	every review in input.reviews {
		review.approved
	}
}
`,
		},
		{
			name: "a count in a rule the decision also asks for",
			body: `allow if {
	reviewed
	approved
}

reviewed if count(input.reviews) > 0

approved if {
	every review in input.reviews {
		review.approved
	}
}
`,
		},
		{
			// Another way to the same decision holds with the domain empty, so
			// the decision does not refuse it.
			name: "a guard on one way and none on another",
			body: `allow if {
	count(input.reviews) > 0
	every review in input.reviews {
		review.approved
	}
}

allow if {
	input.label == "trivial"
	every review in input.reviews {
		review.approved
	}
}
`,
			reported: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := "package p\n\n# METADATA\n# entrypoint: true\ndefault allow := false\n\n" + tt.body
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
			if len(FailOpenOnEmptyEvery(reads)) == 0 {
				t.Fatal("the body shows a guard, and the test is about one it does not show")
			}

			findings, err := GrantsOnEmptyEvery(t.Context(), Analysis{Bundle: bundle, Reads: reads})
			if err != nil {
				t.Fatalf("GrantsOnEmptyEvery() error = %v", err)
			}
			if reported := len(findings) > 0; reported != tt.reported {
				t.Errorf("findings = %v, want reported = %t", findings, tt.reported)
			}
		})
	}
}

// The question is put only where it can be answered. A decision that reads the
// documents cannot be asked without them, and the match stays as the body
// reads it; with them it is asked like any other.
func TestGrantsOnEmptyEveryKeepsWhatItCannotAsk(t *testing.T) {
	policy := `package p

# METADATA
# entrypoint: true
default allow := false

allow if {
	data.projects[input.project].open
	reviewed
	every review in input.reviews {
		review.approved
	}
}

reviewed if count(input.reviews) > 0
`
	dir := t.TempDir()
	writeCaseFile(t, filepath.Join(dir, "policy", "p.rego"), policy)
	bundle, err := opaengine.Load([]string{filepath.Join(dir, "policy")}, opaengine.ParseModeV1)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	reads, err := opaengine.Reads(bundle, opaengine.Limits{})
	if err != nil {
		t.Fatalf("Reads() error = %v", err)
	}
	a := Analysis{Bundle: bundle, Reads: reads}

	findings, err := GrantsOnEmptyEvery(t.Context(), a)
	if err != nil {
		t.Fatalf("GrantsOnEmptyEvery() error = %v", err)
	}
	if len(findings) != 1 {
		t.Errorf("without the data, findings = %v, want the match kept", findings)
	}

	writeCaseFile(t, filepath.Join(dir, "data", "data.json"), `{"projects": {"p1": {"open": true}}}`)
	if a.Data, err = opaengine.LoadData([]string{filepath.Join(dir, "data")}); err != nil {
		t.Fatalf("LoadData() error = %v", err)
	}
	findings, err = GrantsOnEmptyEvery(t.Context(), a)
	if err != nil {
		t.Fatalf("GrantsOnEmptyEvery() error = %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("with the data, findings = %v, want none: the decision refuses an empty list of reviews", findings)
	}
}
