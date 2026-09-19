package taxonomy

import (
	"maps"
	"strings"
	"testing"

	"github.com/saluc28/petard/internal/opaengine"
)

// The cases and the counter case of PTD-OPA-004 on the real fixture. Two rules
// of enrichment.rego call the same builtin and only one contributes to a
// decision, which is the difference between taint and the mere presence of
// http.send.
//
// Five findings, one per decision and party. The enrichment decision grants on
// the answer. The four decisions of risk.rego all consume the scoring service,
// allow_positive_side to grant and the other three to deny, and each of them is
// decided by whoever answers: PTD-OPA-005 says something else about the same
// rules, about the answer not arriving, and neither silences the other.
func TestTaintedByExternalSourceOnFixture(t *testing.T) {
	reads, _, _ := analyzeFixture(t)

	findings := TaintedByExternalSource(reads)
	places := map[string]int{}
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
		places[finding.Decision+" -> "+finding.Source] = len(finding.Reads)
	}

	// allow_defensive reads the answer in three places: the error and the
	// score in the branch that denies on a high score, and the error again in
	// the branch that denies when the service fails.
	expected := map[string]int{
		"data.quill.enrichment.allow -> idp.petard-fixture.invalid":           1,
		"data.quill.risk.allow_positive_side -> risk.petard-fixture.invalid":  1,
		"data.quill.risk.allow_vulnerable -> risk.petard-fixture.invalid":     1,
		"data.quill.risk.allow_defensive -> risk.petard-fixture.invalid":      3,
		"data.quill.risk.allow_default_option -> risk.petard-fixture.invalid": 1,
	}
	if !maps.Equal(places, expected) {
		t.Errorf("findings and their places to look = %v, want %v", places, expected)
	}
}

// A source consumed only to deny is reported like one consumed to grant. The
// party that answers the blocklist decides who is not blocked, and the side the
// answer lands on changes what its absence does, not what that party can do.
//
// The test checks the values really reach those decisions through a negation,
// so that it proves the rule and not a flag the engine forgot to set.
func TestTaintedByExternalSourceReportsTheDenyingSide(t *testing.T) {
	reads, _, _ := analyzeFixture(t)

	var denying int
	for _, taint := range reads.Taints {
		for _, decision := range taint.Decisions {
			if decision.UnderNegation {
				denying++
			}
		}
	}
	if denying != 4 {
		t.Fatalf("values reaching a decision only to deny = %d, want 4: this test would prove nothing otherwise", denying)
	}

	reported := map[string]bool{}
	for _, finding := range TaintedByExternalSource(reads) {
		reported[finding.Decision] = true
	}
	for _, decision := range []string{
		"data.quill.risk.allow_vulnerable",
		"data.quill.risk.allow_defensive",
		"data.quill.risk.allow_default_option",
	} {
		if !reported[decision] {
			t.Errorf("%s consumes the answer to deny and was not reported", decision)
		}
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
