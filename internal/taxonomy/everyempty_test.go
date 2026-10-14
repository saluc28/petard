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
			// Another way to the same decision holds on the vacuous truth, with
			// no guard of its own.
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

// What an every being vacuously true is worth is asked of the policy, so the
// answer does not turn on how a guard is written, on what the body of the every
// tests, on the other rules of the decision, or on where the domain is kept.
// The same decision is asked of the policy and of a copy where that every
// cannot hold over an empty domain, and only a difference is reported.
func TestGrantsOnEmptyEveryAsksWhatTheVacuousTruthIsWorth(t *testing.T) {
	const reviewed = `{"reviews": {"c1": [{"approved": true}], "c2": []}, "required": ["lint"], "open": true}`

	tests := []struct {
		name     string
		body     string
		data     string
		deny     bool
		valued   bool
		reported bool
	}{
		{
			// The registry declared this one a false positive it could not tell
			// apart: the release manager is granted whatever the reviews are, so
			// the decision holds with none, and not through the every.
			name: "a guarded every, next to a rule that grants anyway",
			body: `allow if input.role == "release-manager"

allow if {
	input.reviews[_]
	every review in input.reviews {
		review.approved
	}
}
`,
		},
		{
			name: "an every nothing guards, next to a rule that grants anyway",
			body: `allow if input.role == "release-manager"

allow if {
	input.author != ""
	every review in input.reviews {
		review.approved
	}
}
`,
			reported: true,
		},
		{
			// A body any element satisfies, a wrong one included: nothing about
			// the elements tells this every from a guarded one.
			name: "a body that holds for whatever the domain holds",
			body: `allow if {
	input.author != ""
	every review in input.reviews {
		not review.rejected
	}
}
`,
			reported: true,
		},
		{
			name: "a guard three rules away",
			body: `allow if {
	ready
	approved
}

ready if staffed

staffed if some_reviewer

some_reviewer if input.reviews[_].id

approved if {
	every review in input.reviews {
		review.approved
	}
}
`,
		},
		{
			name: "a document that is the domain, guarded",
			body: `allow if {
	data.open
	data.required[_]
	every check in data.required {
		check in input.passed
	}
}
`,
			data: reviewed,
		},
		{
			name: "a document that is the domain, not guarded",
			body: `allow if {
	data.open
	every check in data.required {
		check in input.passed
	}
}
`,
			data:     reviewed,
			reported: true,
		},
		{
			name: "a document the request picks, guarded",
			body: `allow if {
	data.reviews[input.change][_]
	every review in data.reviews[input.change] {
		review.approved
	}
}
`,
			data: reviewed,
		},
		{
			name: "a document the request picks, not guarded",
			body: `allow if {
	data.open
	every review in data.reviews[input.change] {
		review.approved
	}
}
`,
			data:     reviewed,
			reported: true,
		},
		{
			// The rule is defined either way, and what differs is what it says:
			// compliant with no review to look at.
			name: "a report whose verdict the every decides",
			body: `allow := {"compliant": approved, "reviews": count(input.reviews)}

default approved := false

approved if {
	input.author != ""
	every review in input.reviews {
		review.approved
	}
}
`,
			valued:   true,
			reported: true,
		},
		{
			// Partial evaluation hands a comprehension back as it is written,
			// naming the rule that holds the every. What it leaves reads the same
			// with and without the guard, and is not the same.
			name: "a score counted in a comprehension",
			body: `allow := count([check |
	checks := [staffed, approved]
	check := checks[_]
	check == true
])

staffed if input.author != ""

approved if {
	every review in input.reviews {
		review.approved
	}
}
`,
			valued:   true,
			reported: true,
		},
		{
			// A collection written out in the policy is never empty, whatever the
			// request and the data hold.
			name: "a domain the policy writes out in a rule of its own",
			body: `required := {"lint", "test"}

allow if {
	input.author != ""
	every check in required {
		check in input.passed
	}
}
`,
		},
		{
			name: "a domain the policy builds from the request",
			body: `required := {check | some check in input.required}

allow if {
	input.author != ""
	every check in required {
		check in input.passed
	}
}
`,
			reported: true,
		},
		{
			// Declared to deny: the vacuous truth keeps the violation from being
			// raised, which is the request let through.
			name: "a decision that refuses, not guarded",
			body: `allow contains "unapproved" if not approved

approved if {
	every review in input.reviews {
		review.approved
	}
}
`,
			deny:     true,
			reported: true,
		},
		{
			name: "a decision that refuses, guarded",
			body: `allow contains "unapproved" if not approved

approved if {
	input.reviews[_]
	every review in input.reviews {
		review.approved
	}
}
`,
			deny: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := "package p\n\n" + tt.body
			switch {
			case tt.valued:
				// The decision answers with a value of its own, and has no
				// default to fall back to.
				policy = "package p\n\n# METADATA\n# entrypoint: true\n" + tt.body
			case !tt.deny:
				policy = "package p\n\n# METADATA\n# entrypoint: true\ndefault allow := false\n\n" + tt.body
			}
			dir := t.TempDir()
			writeCaseFile(t, filepath.Join(dir, "policy", "p.rego"), policy)
			bundle, err := opaengine.Load([]string{filepath.Join(dir, "policy")}, opaengine.ParseModeV1)
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if tt.deny {
				bundle.DenyEntrypoints = []string{"data.p.allow"}
			}
			reads, err := opaengine.Reads(bundle, opaengine.Limits{})
			if err != nil {
				t.Fatalf("Reads() error = %v", err)
			}
			if len(FailOpenOnEmptyEvery(reads)) == 0 {
				t.Fatal("the body shows a guard, or no every on the side that grants, and the test is about a match")
			}
			a := Analysis{Bundle: bundle, Reads: reads}
			if tt.data != "" {
				writeCaseFile(t, filepath.Join(dir, "data", "data.json"), tt.data)
				if a.Data, err = opaengine.LoadData([]string{filepath.Join(dir, "data")}); err != nil {
					t.Fatalf("LoadData() error = %v", err)
				}
			}

			findings, err := GrantsOnEmptyEvery(t.Context(), a)
			if err != nil {
				t.Fatalf("GrantsOnEmptyEvery() error = %v", err)
			}
			if reported := len(findings) > 0; reported != tt.reported {
				t.Errorf("findings = %v, want reported = %t", findings, tt.reported)
			}
		})
	}
}

// A decision may hold more than one every over the same domain, and they are
// one match: the question is asked of every way of choosing among them. Asking
// it of the first alone would drop a match whose first every is guarded and
// whose second is not.
func TestGrantsOnEmptyEveryAsksEveryPlaceOfAMatch(t *testing.T) {
	guardedFive := ""
	for _, field := range []string{"approved", "signed", "listed", "dated", "named"} {
		guardedFive += "allow if {\n\tinput.reviews[_]\n\tevery review in input.reviews {\n\t\treview." + field + "\n\t}\n}\n\n"
	}

	tests := []struct {
		name     string
		body     string
		places   int
		reported bool
	}{
		{
			name: "a guard the body does not show on the first, and none on the second",
			body: `allow if {
	some first in input.reviews
	first.id
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
			places:   2,
			reported: true,
		},
		{
			// Either rule alone leaves the other to grant, so only the copy that
			// takes the vacuous truth from both says anything else.
			name: "two rules that each grant on the vacuous truth",
			body: `allow if {
	every review in input.reviews {
		review.approved
	}
}

allow if {
	every review in input.reviews {
		not review.rejected
	}
}
`,
			places:   2,
			reported: true,
		},
		{
			name: "two rules, each with a guard the body does not show",
			body: `allow if {
	input.reviews[_]
	every review in input.reviews {
		review.approved
	}
}

allow if {
	some first in input.reviews
	first.id
	every review in input.reviews {
		not review.rejected
	}
}
`,
			places: 2,
		},
		{
			// With no review the request is granted through approved alone. The
			// copy that guards both grants it too, through the rule that asks for
			// no sign-off, so only the copy that guards the one says anything else.
			name: "an every whose guard would hand the grant to another rule",
			body: `allow if approved

allow if not signed_off

allow if {
	signed_off
	count(input.reviews) > 5
}

approved if {
	every review in input.reviews {
		review.approved
	}
}

signed_off if {
	every review in input.reviews {
		review.signed
	}
}
`,
			places:   2,
			reported: true,
		},
		{
			// Each of the five is guarded, and thirty-one copies would say so. Past
			// the bound the question is not asked, and the match stays.
			name:     "more every expressions than are asked about",
			body:     guardedFive,
			places:   5,
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
			matches := FailOpenOnEmptyEvery(reads)
			if len(matches) != 1 || len(matches[0].Reads) != tt.places {
				t.Fatalf("matches = %v, want one with %d places", matches, tt.places)
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
