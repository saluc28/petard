package taxonomy

import "testing"

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
