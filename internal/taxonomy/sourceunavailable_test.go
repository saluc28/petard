package taxonomy

import (
	"slices"
	"strings"
	"testing"
)

// The case and the three counter cases of PTD-OPA-005 on the real fixture. All
// four rules call the same builtin against the same host, and what separates
// them is where the answer is consumed and whether anything notices that it did
// not arrive.
func TestGrantsWhenSourceFailsOnFixture(t *testing.T) {
	reads, _, _ := analyzeFixture(t)

	findings := GrantsWhenSourceFails(reads)

	var decisions []string
	for _, finding := range findings {
		if finding.Verdict != VerdictFinding {
			t.Errorf("%s is a %s: this pattern needs no write model", finding.Decision, finding.Verdict)
		}
		if finding.Confidence != "A" {
			t.Errorf("confidence = %q, want A: the side that denies is declared, not guessed", finding.Confidence)
		}
		if finding.Source != "risk.petard-fixture.invalid" {
			t.Errorf("source = %q, want the host that stops answering", finding.Source)
		}
		decisions = append(decisions, finding.Decision)
	}
	slices.Sort(decisions)

	// allow_defensive consumes the error and denies, allow_positive_side
	// consumes the answer on the side that grants and therefore fails closed:
	// neither is here, and the two that are include the one written without
	// raise_error, which is what proves the pattern is not a lint rule on that
	// option wearing a disguise.
	expected := []string{"data.quill.risk.allow_default_option", "data.quill.risk.allow_vulnerable"}
	if !slices.Equal(decisions, expected) {
		t.Errorf("findings = %v, want %v", decisions, expected)
	}
}

// The option decides nothing about whether the decision fails open, and
// everything about whether anybody outside the policy can notice that it did.
// Both fixture cases are findings, and they carry different notes.
func TestGrantsWhenSourceFailsSaysWhatIsLeftToMitigateWith(t *testing.T) {
	reads, _, _ := analyzeFixture(t)

	tests := []struct {
		name     string
		decision string
		note     string
	}{
		{
			name:     "the call suppresses its errors",
			decision: "data.quill.risk.allow_vulnerable",
			note:     "no error left",
		},
		{
			name:     "the call is written at the default",
			decision: "data.quill.risk.allow_default_option",
			note:     "strict-builtin-errors",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, finding := range GrantsWhenSourceFails(reads) {
				if finding.Decision != tt.decision {
					continue
				}
				if !strings.Contains(finding.Note, tt.note) {
					t.Errorf("note = %q, want it to mention %q", finding.Note, tt.note)
				}
				return
			}
			t.Fatalf("%s was not reported at all", tt.decision)
		})
	}
}

// A rule that reads the error of the call was written to notice the failure,
// and the branch that does it is a branch of its own: seen one body at a time,
// the other branch of the same rule looks exactly like the vulnerable form.
//
// The engine has to have seen those calls, or the silence would come from
// having missed them rather than from the defence.
func TestGrantsWhenSourceFailsLeavesTheDefensiveFormAlone(t *testing.T) {
	reads, _, _ := analyzeFixture(t)

	for _, finding := range GrantsWhenSourceFails(reads) {
		if finding.Decision == "data.quill.risk.allow_defensive" {
			t.Errorf("the defensive form was reported: %s", finding)
		}
	}

	var noticed int
	for _, taint := range reads.Taints {
		if taint.Rule == "data.quill.risk.denied_defensive" {
			noticed++
		}
	}
	if noticed != 3 {
		t.Errorf("values the engine saw in the defensive rule = %d, want 3: this test would prove nothing otherwise", noticed)
	}
}

// A body carrying an error of its own is the service reporting something, not
// the call failing to happen. A rule that reads it never looks at whether the
// answer arrived at all, so it is still the vulnerable form and has to be
// reported: taking it for a defence would silence exactly the rules that talk
// about errors without handling them.
func TestGrantsWhenSourceFailsTellsAFailedCallFromAnAnsweredOne(t *testing.T) {
	_, reads, _ := analyze(t, `package t

# METADATA
# scope: document
# entrypoint: true
default allow := false

allow if {
	input.action == "read"
	not denied
}

denied if {
	answer := http.send({"method": "GET", "url": "https://risk.invalid/score", "raise_error": false})
	answer.body.error == "flagged"
}
`, `{"unused": true}`)

	findings := GrantsWhenSourceFails(reads)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1: reading body.error is not noticing a failed call:\n%v",
			len(findings), findings)
	}
}

// The same call consumed on the side that grants fails closed, which is
// availability rather than authorization. It is also a finding of PTD-OPA-004,
// on the content of the answer rather than on its absence, and the two patterns
// do not silence each other.
func TestGrantsWhenSourceFailsLeavesTheGrantingSideAlone(t *testing.T) {
	reads, _, _ := analyzeFixture(t)

	for _, finding := range GrantsWhenSourceFails(reads) {
		if finding.Decision == "data.quill.risk.allow_positive_side" {
			t.Errorf("a rule that fails closed was reported: %s", finding)
		}
	}

	var alsoTaint bool
	for _, finding := range TaintedByExternalSource(reads) {
		if finding.Decision == "data.quill.risk.allow_positive_side" {
			alsoTaint = true
		}
	}
	if !alsoTaint {
		t.Error("the same rule is no longer a finding of PTD-OPA-004, so the two patterns stopped saying different things")
	}
}
