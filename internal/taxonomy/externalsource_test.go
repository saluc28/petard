package taxonomy

import (
	"slices"
	"strings"
	"testing"

	"github.com/saluc28/petard/internal/opaengine"
)

// The case and the counter case of PTD-OPA-004 on the real fixture. Two rules
// call the same builtin and only one contributes to a decision, which is the
// difference between taint and the mere presence of http.send.
//
// Two findings, not one. The enrichment decision is the case EXPECTED.md
// describes; allow_positive_side is the second, and it is a true positive of
// this pattern for a reason that has nothing to do with PTD-OPA-005: that rule
// grants access when a service answers a low number, so whoever controls the
// service grants access. The two patterns say different things about the same
// rule, one about the content of the answer and one about its absence, and
// neither silences the other.
func TestTaintedByExternalSourceOnFixture(t *testing.T) {
	reads, _, _ := analyzeFixture(t)

	findings := TaintedByExternalSource(reads)
	if len(findings) != 2 {
		t.Fatalf("findings = %d, want 2:\n%v", len(findings), findings)
	}

	var decisions []string
	for _, finding := range findings {
		if finding.Verdict != VerdictFinding {
			t.Errorf("%s is a %s: this pattern needs no write model", finding.Decision, finding.Verdict)
		}
		if finding.Confidence != "A" {
			t.Errorf("confidence = %q, want A: the chain is structure, not a guess about the subject", finding.Confidence)
		}
		if finding.Origin != "http.send" {
			t.Errorf("origin = %q, want http.send", finding.Origin)
		}
		if len(finding.Reads) != 1 {
			t.Errorf("%s has %d places to look, want 1", finding.Decision, len(finding.Reads))
		}
		decisions = append(decisions, finding.Decision+" -> "+finding.Source)
	}
	slices.Sort(decisions)

	expected := []string{
		"data.quill.enrichment.allow -> idp.petard-fixture.invalid",
		"data.quill.risk.allow_positive_side -> risk.petard-fixture.invalid",
	}
	if !slices.Equal(decisions, expected) {
		t.Errorf("findings = %v, want %v", decisions, expected)
	}
}

// The five values that only reach a decision through a negation are left out,
// and the engine did see all five: controlling a source that denies is a
// different fact from controlling one that grants, and the second is what this
// pattern reports.
func TestTaintedByExternalSourceLeavesTheDenyingSideAlone(t *testing.T) {
	reads, _, _ := analyzeFixture(t)

	findings := TaintedByExternalSource(reads)
	for _, finding := range findings {
		if finding.Decision == "data.quill.risk.allow_vulnerable" || finding.Decision == "data.quill.risk.allow_defensive" {
			t.Errorf("a value that only denies was reported: %s", finding)
		}
	}

	// And the engine measured them, so the silence comes from the negation and
	// not from having missed the calls.
	var denying int
	for _, taint := range reads.Taints {
		for _, decision := range taint.Decisions {
			if decision.UnderNegation {
				denying++
			}
		}
	}
	if denying != 5 {
		t.Errorf("values reaching a decision only to deny = %d, want 5: this test would prove nothing otherwise", denying)
	}
}

// Every builtin the engine reports is nondeterministic, which is not the same
// as talking to somebody. A decision that depends on the clock is not one an
// endpoint controls, and reporting it would be the noise the pattern exists to
// avoid.
func TestTaintedByExternalSourceIgnoresBuiltinsWithNoOtherEnd(t *testing.T) {
	reads := &opaengine.ReadSet{Taints: []opaengine.Taint{
		{
			Rule:      "data.t.allow",
			Ref:       "now.year",
			Origin:    "time.now_ns",
			Decisions: []opaengine.TaintedDecision{{Name: "data.t.allow"}},
		},
	}}

	if findings := TaintedByExternalSource(reads); len(findings) != 0 {
		t.Errorf("findings = %v, want none: time.now_ns reaches nobody", findings)
	}
}

// One finding per fact, and the fact is that a decision depends on a party.
// A source read in two rules that both feed the same decision widened the trust
// perimeter of that decision once, and counting it twice would inflate every
// precision number the patterns are judged by.
func TestTaintedByExternalSourceGroupsByDecisionAndSource(t *testing.T) {
	reads := &opaengine.ReadSet{Taints: []opaengine.Taint{
		{
			Rule:      "data.t.helper",
			Ref:       "enrichment.body.clearance",
			Origin:    "http.send",
			Endpoint:  "https://idp.invalid/attrs",
			Decisions: []opaengine.TaintedDecision{{Name: "data.t.allow"}},
		},
		{
			Rule:      "data.t.allow",
			Ref:       "enrichment.body.tier",
			Origin:    "http.send",
			Endpoint:  "https://idp.invalid/tiers",
			Decisions: []opaengine.TaintedDecision{{Name: "data.t.allow"}},
		},
	}}

	findings := TaintedByExternalSource(reads)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1: same decision, same host, two paths on it", len(findings))
	}
	if len(findings[0].Reads) != 2 {
		t.Errorf("places to look = %d, want both", len(findings[0].Reads))
	}
	if findings[0].Source != "idp.invalid" {
		t.Errorf("source = %q, want the host: two paths on one host are one party", findings[0].Source)
	}
}

// A destination the request steers is worse than a fixed one, so it must read
// as its own thing rather than as a host nobody could parse.
func TestTaintedByExternalSourceSaysWhenTheDestinationIsComputed(t *testing.T) {
	reads := &opaengine.ReadSet{Taints: []opaengine.Taint{
		{
			Rule:      "data.t.allow",
			Ref:       "enrichment.body.clearance",
			Origin:    "http.send",
			Decisions: []opaengine.TaintedDecision{{Name: "data.t.allow"}},
		},
	}}

	findings := TaintedByExternalSource(reads)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if findings[0].Source != "" {
		t.Errorf("source = %q, want empty for a destination the policy computes", findings[0].Source)
	}
	if got := findings[0].String(); !strings.Contains(got, "a destination the policy computes") {
		t.Errorf("the report reads %q, and does not say the destination is computed", got)
	}
}
