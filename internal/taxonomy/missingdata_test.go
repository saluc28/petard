package taxonomy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/saluc28/petard/internal/graph"
	"github.com/saluc28/petard/internal/opaengine"
)

// fixtureData loads the concrete documents of the fixture, which is what this
// pattern cannot do without.
func fixtureData(t *testing.T) *opaengine.Data {
	t.Helper()

	data, err := opaengine.LoadData([]string{fixturePath("data")})
	if err != nil {
		t.Fatalf("LoadData() error = %v", err)
	}
	return data
}

// fixtureBundle loads the policy of the fixture, for the patterns that have to
// evaluate it and not only read what came out of it.
func fixtureBundle(t *testing.T) *opaengine.Bundle {
	t.Helper()

	bundle, err := opaengine.Load([]string{fixturePath("policy-v1")}, opaengine.ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	return bundle
}

// analyze runs the engine over a policy and a set of documents written out
// here. A pattern tested against a ReadSet built by hand would only prove that
// the assertions match the fixture the test wrote for itself.
func analyze(t *testing.T, policy, documents string) (*opaengine.Bundle, *opaengine.ReadSet, *opaengine.Data) {
	t.Helper()

	write := func(name, content string) string {
		t.Helper()
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
		return dir
	}

	bundle, err := opaengine.Load([]string{write("policy.rego", policy)}, opaengine.ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	reads, err := opaengine.Reads(bundle, opaengine.Limits{})
	if err != nil {
		t.Fatalf("Reads() error = %v", err)
	}
	data, err := opaengine.LoadData([]string{write("data.json", documents)})
	if err != nil {
		t.Fatalf("LoadData() error = %v", err)
	}
	return bundle, reads, data
}

// The case and the counter case of PTD-OPA-002 on the real fixture. Both checks
// live on the side the decision negates and both read a field of the same
// collection: only the data separates the one that covers every tenant from the
// one that skips a tenant in silence.
func TestFailOpenOnMissingDataOnFixture(t *testing.T) {
	reads, _, _ := analyzeFixture(t)

	findings, err := FailOpenOnMissingData(t.Context(), reads, fixtureData(t))
	if err != nil {
		t.Fatalf("FailOpenOnMissingData() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1:\n%v", len(findings), findings)
	}

	finding := findings[0]
	if finding.Path != "data.tenants[_].policy.require_mfa" {
		t.Errorf("path = %q, want the field the deny rule reads", finding.Path)
	}
	if finding.Decision != "data.quill.tenant_policy.allow" {
		t.Errorf("decision = %q, want the tenant decision", finding.Decision)
	}
	if expected := []string{"dolm"}; !slices.Equal(finding.UncoveredKeys, expected) {
		t.Errorf("uncovered keys = %v, want %v", finding.UncoveredKeys, expected)
	}
	if finding.KeysChecked != 2 {
		t.Errorf("keys checked = %d, want both tenants", finding.KeysChecked)
	}
	if finding.Verdict != VerdictFinding {
		t.Errorf("verdict = %s, want a finding: this pattern needs no write model", finding.Verdict)
	}
	if finding.Confidence != "A" {
		t.Errorf("confidence = %q, want A: the side that denies is declared, not guessed", finding.Confidence)
	}
	if len(finding.Reads) != 1 || finding.Reads[0].Rule != "data.quill.tenant_policy.denied_mfa" {
		t.Errorf("places to look = %v, want the deny rule", finding.Reads)
	}
}

// The finding says a check does not reach dolm. This measures what that means
// for the decision, which is the claim the report ends up carrying: with the
// same request and no MFA, the tenant that declares the field still has a
// condition to meet, and the tenant that does not is allowed outright.
//
// It is the measurement of EXPECTED.md section 3 run through the engine, and it
// belongs to the test rather than to the pattern: partial evaluation is not one
// of the signals, and a pattern that evaluated every key to report one would be
// measuring the consequence instead of the cause.
func TestFailOpenOnMissingDataMatchesWhatTheDecisionGrants(t *testing.T) {
	bundle, err := opaengine.Load([]string{fixturePath("policy-v1")}, opaengine.ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	data := fixtureData(t)

	ask := func(tenant string) *opaengine.ResidualSet {
		t.Helper()
		residuals, err := opaengine.Residuals(t.Context(), bundle, data, opaengine.Request{
			Decision: "data.quill.tenant_policy.allow",
			Unknowns: []string{"input.mfa"},
			Input:    map[string]any{"action": "read", "tenant": tenant},
		}, opaengine.Limits{})
		if err != nil {
			t.Fatalf("Residuals() error = %v", err)
		}
		return residuals
	}

	// What separates the two is whether MFA is still part of the answer. For the
	// tenant that declares the field the decision comes back conditional on it;
	// for the other it comes back as the constant true, which is the check
	// having disappeared rather than having been satisfied.
	if covered := ask("berq"); !asksAbout(covered, "input.mfa") {
		t.Errorf("the tenant that declares require_mfa is granted under %v, with nothing to satisfy about mfa",
			covered.Conditions)
	}
	if uncovered := ask("dolm"); asksAbout(uncovered, "input.mfa") {
		t.Errorf("the tenant without the field is still asked about mfa (%v), so nothing was skipped",
			uncovered.Conditions)
	}
}

// asksAbout reports whether any residual condition still constrains a part of
// the request.
func asksAbout(residuals *opaengine.ResidualSet, term string) bool {
	for _, condition := range residuals.Conditions {
		if strings.Contains(condition.Query, term) {
			return true
		}
	}
	return false
}

// The same missing field, read on the side that grants, is not this pattern:
// there the request fails instead of passing. It is the counter case that
// separates a hole in a check from a check that simply does not match.
func TestFailOpenOnMissingDataLeavesTheGrantingSideAlone(t *testing.T) {
	_, reads, data := analyze(t, `package t

# METADATA
# scope: document
# entrypoint: true
default allow := false

allow if data.tenants[input.tenant].policy.require_mfa == true
`, `{"tenants": {"berq": {"policy": {"require_mfa": true}}, "dolm": {}}}`)

	findings, err := FailOpenOnMissingData(t.Context(), reads, data)
	if err != nil {
		t.Fatalf("FailOpenOnMissingData() error = %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("findings = %v, want none: a missing field on the granting side denies", findings)
	}
}

// A default is what decides whether an undefined body stays silent or answers.
// Only one of the three forms closes the hole, and the two that do not have to
// stay reported: a rule defaulting to false is false, and a not on false
// succeeds exactly like a not on nothing.
func TestFailOpenOnMissingDataReadsTheDefaultOfTheDenyRule(t *testing.T) {
	tests := []struct {
		name     string
		fallback string
		findings int
	}{
		{name: "no default at all", fallback: "", findings: 1},
		{name: "a default that does not deny", fallback: "default denied := false\n", findings: 1},
		{name: "a default that denies", fallback: "default denied := true\n", findings: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, reads, data := analyze(t, `package t

# METADATA
# scope: document
# entrypoint: true
default allow := false

allow if {
	input.action == "read"
	not denied
}

`+tt.fallback+`
denied if {
	data.tenants[input.tenant].policy.require_mfa == true
	not input.mfa
}
`, `{"tenants": {"berq": {"policy": {"require_mfa": true}}, "dolm": {}}}`)

			findings, err := FailOpenOnMissingData(t.Context(), reads, data)
			if err != nil {
				t.Fatalf("FailOpenOnMissingData() error = %v", err)
			}
			if len(findings) != tt.findings {
				t.Errorf("findings = %d, want %d:\n%v", len(findings), tt.findings, findings)
			}
		})
	}
}

// A second deny rule that fires when the document is missing is the ordinary
// way to defend against this, and reporting it would cost the reader's trust.
// The guard covers the field it sits above, since the object being absent is
// what makes the field absent.
func TestFailOpenOnMissingDataStopsAtADefenceOnTheSameDecision(t *testing.T) {
	const policy = `package t

# METADATA
# scope: document
# entrypoint: true
default allow := false

allow if {
	input.action == "read"
	not denied_mfa
	%s
}

denied_mfa if {
	data.tenants[input.tenant].policy.require_mfa == true
	not input.mfa
}

denied_without_policy if not data.tenants[input.tenant].policy
`
	const documents = `{"tenants": {"berq": {"policy": {"require_mfa": true}}, "dolm": {}}}`

	tests := []struct {
		name     string
		guard    string
		findings int
	}{
		{name: "the defence is never consulted", guard: "", findings: 1},
		{name: "the decision consults the defence", guard: "not denied_without_policy", findings: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, reads, data := analyze(t, fmt.Sprintf(policy, tt.guard), documents)

			findings, err := FailOpenOnMissingData(t.Context(), reads, data)
			if err != nil {
				t.Fatalf("FailOpenOnMissingData() error = %v", err)
			}
			if len(findings) != tt.findings {
				t.Errorf("findings = %d, want %d:\n%v", len(findings), tt.findings, findings)
			}
		})
	}
}

// Without the data the pattern has nothing to say, and saying nothing would
// read as a policy whose checks cover everything.
func TestFailOpenOnMissingDataNeedsTheData(t *testing.T) {
	reads, _, _ := analyzeFixture(t)

	if _, err := FailOpenOnMissingData(t.Context(), reads, nil); !errors.Is(err, ErrNeedsData) {
		t.Errorf("FailOpenOnMissingData() error = %v, want ErrNeedsData", err)
	}
}

// What this pattern learns about a read afterwards belongs on that read, not on
// an edge of its own: the graph would otherwise hold the same relation twice
// with half the truth on each.
func TestMissingDataMarksTheRead(t *testing.T) {
	a := fixtureAnalysis(t)
	g := graphOn(t, a)

	findings, err := FailOpenOnMissingData(t.Context(), a.Reads, a.Data)
	if err != nil {
		t.Fatalf("FailOpenOnMissingData() error = %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("the fixture stopped holding a check that does not cover all the data")
	}

	unmatched, err := AddFindings(g, a.Reads, findings)
	if err != nil {
		t.Fatalf("AddFindings() error = %v", err)
	}
	if unmatched != 0 {
		t.Errorf("%d findings reached no read, and every one of them names a read the graph holds", unmatched)
	}

	enriched := 0
	for _, edge := range edgesOfKind(g, graph.EdgeKindReads) {
		if edge.Properties[graph.PropUncoveredKeys] == nil {
			continue
		}
		enriched++
		if edge.Properties[graph.PropEnforcingSide] == nil {
			t.Errorf("the read %s -> %s says which keys are absent and not how the enforcing side was established", edge.From, edge.To)
		}
		if edge.Properties[graph.PropKeysChecked] == nil {
			t.Errorf("the read %s -> %s says which keys are absent and not how many were tried", edge.From, edge.To)
		}
	}
	if enriched == 0 {
		t.Error("no read carries the gap the pattern found")
	}
}

// The case of the fixture written the way a decision that answers with its
// violations writes it: a violation for a tenant that requires MFA, and an
// answer that is allowed when there are none. The violation is on the side that
// denies even though no not is written anywhere, and for the tenant with no
// policy it never fires.
func TestFailOpenOnMissingDataThroughCountedViolations(t *testing.T) {
	const policy = `package t

violations contains "multi-factor authentication is required" if {
	data.tenants[input.tenant].policy.require_mfa == true
	not input.mfa
}

decision := {"allowed": count(violations) == 0, "violations": [v | some v in violations]}
`
	const documents = `{"tenants": {"berq": {"policy": {"require_mfa": true}}, "dolm": {"status": "active"}}}`

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "policy.rego"), []byte(policy), 0o600); err != nil {
		t.Fatalf("writing the policy: %v", err)
	}
	bundle, err := opaengine.Load([]string{dir}, opaengine.ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	bundle.Entrypoints = []string{"t/decision/allowed"}
	reads, err := opaengine.Reads(bundle, opaengine.Limits{})
	if err != nil {
		t.Fatalf("Reads() error = %v", err)
	}
	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, "data.json"), []byte(documents), 0o600); err != nil {
		t.Fatalf("writing the data: %v", err)
	}
	data, err := opaengine.LoadData([]string{dataDir})
	if err != nil {
		t.Fatalf("LoadData() error = %v", err)
	}

	findings, err := FailOpenOnMissingData(t.Context(), reads, data)
	if err != nil {
		t.Fatalf("FailOpenOnMissingData() error = %v", err)
	}
	if len(findings) != 1 || findings[0].Decision != "data.t.decision.allowed" ||
		!slices.Equal(findings[0].UncoveredKeys, []string{"dolm"}) {
		t.Fatalf("findings = %v, want the check that does not reach dolm", findings)
	}

	// What that means for the answer: without MFA, berq is refused and dolm is
	// allowed.
	for tenant, always := range map[string]bool{"berq": false, "dolm": true} {
		residuals, err := opaengine.Residuals(t.Context(), bundle, data, opaengine.Request{
			Decision: "data.t.decision.allowed",
			Unknowns: []string{"input.mfa"},
			Input:    map[string]any{"tenant": tenant},
		}, opaengine.Limits{})
		if err != nil {
			t.Fatalf("Residuals() error = %v", err)
		}
		if residuals.Always != always {
			t.Errorf("%s is allowed whatever the MFA: %v, want %v (%v)", tenant, residuals.Always, always, residuals.Conditions)
		}
	}
}
