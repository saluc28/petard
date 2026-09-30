package analyze

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/saluc28/petard/internal/opaengine"
	"github.com/saluc28/petard/internal/taxonomy"
)

// copyPolicy copies the .rego files of a directory into a new one, so that a
// test can add to the policy or change it without touching the fixture.
func copyPolicy(t *testing.T, from string) string {
	t.Helper()

	to := t.TempDir()
	entries, err := os.ReadDir(from)
	if err != nil {
		t.Fatalf("reading %s: %v", from, err)
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".rego" {
			continue
		}
		content, err := os.ReadFile(filepath.Join(from, entry.Name()))
		if err != nil {
			t.Fatalf("reading %s: %v", entry.Name(), err)
		}
		if err := os.WriteFile(filepath.Join(to, entry.Name()), content, 0o600); err != nil {
			t.Fatalf("writing %s: %v", entry.Name(), err)
		}
	}
	return to
}

// passes runs one test of the module in dir the way opa test does, by asking
// for the rule: a test that fails is undefined.
func passes(t *testing.T, dir, dataDir, test string) bool {
	t.Helper()

	bundle, err := opaengine.Load([]string{dir}, opaengine.ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	data, err := opaengine.LoadData([]string{dataDir})
	if err != nil {
		t.Fatalf("LoadData() error = %v", err)
	}
	held, err := opaengine.Holds(t.Context(), bundle, data, "data.petard.escalations_test."+test, nil)
	if err != nil {
		t.Fatalf("Holds(%s) error = %v", test, err)
	}
	return held
}

// The tests written for the fixture fail while its two escalations are open.
// Once the role assignment decision stops letting support assign editor, which
// is the fix the registry gives PTD-OPA-006, carol's test passes and mallory's,
// whose write no decision of the policy guards, still fails.
func TestRunWritesATestThatFailsWhileTheEscalationIsOpen(t *testing.T) {
	policy := copyPolicy(t, fixture("policy-v1"))
	tests := filepath.Join(policy, "escalations_test.rego")
	dataDir := filepath.Join("..", "..", "..", "fixtures", "vulnerable-bundle", "data")

	var stdout, stderr bytes.Buffer
	args := withFixtureData("-fail-on", failOnNone, "-tests", tests)
	if code := Run(args, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "2 tests written to "+tests) {
		t.Errorf("the run does not say where the tests went:\n%s", stdout.String())
	}

	for _, test := range []string{"test_carol_cannot_reach_alice", "test_mallory_cannot_reach_dave"} {
		if passes(t, policy, dataDir, test) {
			t.Errorf("%s passes, and the escalation it names is open", test)
		}
	}

	admin := filepath.Join(policy, "admin.rego")
	content, err := os.ReadFile(admin)
	if err != nil {
		t.Fatalf("reading admin.rego: %v", err)
	}
	fixed := strings.Replace(string(content), `input.role in {"viewer", "editor"}`, `input.role in {"viewer"}`, 1)
	if fixed == string(content) {
		t.Fatal("the role assignment decision no longer reads as the test expects")
	}
	if err := os.WriteFile(admin, []byte(fixed), 0o600); err != nil {
		t.Fatalf("writing admin.rego: %v", err)
	}
	if !passes(t, policy, dataDir, "test_carol_cannot_reach_alice") {
		t.Error("carol's test still fails once support may no longer assign editor")
	}
	if passes(t, policy, dataDir, "test_mallory_cannot_reach_dave") {
		t.Error("mallory's test passes, and nothing closed their escalation")
	}
}

// A decision that collects grants when what it collected is not empty, which a
// test writes as a count, and a write into an element of a list is repeated by
// replacing the list, since a with modifier cannot name the element.
func TestRegoTestsCountACollectedDecisionAndReplaceAList(t *testing.T) {
	dir := t.TempDir()
	policy := `package roster

grants contains "remove" if {
	some member in data.team.members
	member.user == input.user
	member.role == "owner"
}
`
	if err := os.WriteFile(filepath.Join(dir, "roster.rego"), []byte(policy), 0o600); err != nil {
		t.Fatalf("writing the policy: %v", err)
	}
	dataDir := t.TempDir()
	document := `{"team": {"members": [{"user": "alice", "role": "editor"}, {"user": "bob", "role": "owner"}]}}`
	if err := os.WriteFile(filepath.Join(dataDir, "data.json"), []byte(document), 0o600); err != nil {
		t.Fatalf("writing the data: %v", err)
	}

	bundle, err := opaengine.Load([]string{dir}, opaengine.ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	data, err := opaengine.LoadData([]string{dataDir})
	if err != nil {
		t.Fatalf("LoadData() error = %v", err)
	}
	escalation := taxonomy.Finding{
		PatternID: taxonomy.WriteAllowedByAnotherDecision,
		Summary:   "alice can set their role to owner",
		Principal: "alice",
		Target:    "bob",
		Witness: &taxonomy.Witness{
			Decision: "data.roster.grants",
			Request:  map[string]any{"user": "alice"},
			Document: "data.team.members[0].role",
			Value:    "owner",
		},
	}

	module, written, err := regoTests(t.Context(), taxonomy.Analysis{Bundle: bundle, Data: data}, []taxonomy.Finding{escalation})
	if err != nil {
		t.Fatalf("regoTests() error = %v", err)
	}
	if written != 1 {
		t.Errorf("tests written = %d, want 1", written)
	}
	for _, want := range []string{
		`count(data.roster.grants) == 0 with input as {"user": "alice"}`,
		`count(data.roster.grants) > 0 with input as {"user": "alice"}`,
		`with data.team.members as [{"role": "owner", "user": "alice"}, {"role": "owner", "user": "bob"}]`,
	} {
		if !strings.Contains(module, want) {
			t.Errorf("the module does not say %q:\n%s", want, module)
		}
	}

	if err := os.WriteFile(filepath.Join(dir, "escalations_test.rego"), []byte(module), 0o600); err != nil {
		t.Fatalf("writing the tests: %v", err)
	}
	if passes(t, dir, dataDir, "test_alice_cannot_reach_bob") {
		t.Errorf("the test passes, and alice reaches bob:\n%s", module)
	}
}

// A test is named after the two principals in what a rule name can hold, and
// the same two principals a second time get a number.
func TestTestName(t *testing.T) {
	taken := map[string]bool{}
	for _, want := range []string{
		"test_user_bob_cannot_reach_team_admins",
		"test_user_bob_cannot_reach_team_admins_2",
	} {
		if got := testName(taken, "user:bob", "team:admins"); got != want {
			t.Errorf("testName() = %s, want %s", got, want)
		}
	}
}
