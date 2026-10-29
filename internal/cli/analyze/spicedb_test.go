package analyze

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/saluc28/petard/internal/zanzibar"
)

func spicedbTestdata(name string) string {
	return filepath.Join("..", "..", "zanzibar", "spicedb", "testdata", name)
}

// spicedbFixture is the vulnerable SpiceDB fixture.
var spicedbFixture = filepath.Join("..", "..", "..", "fixtures", "vulnerable-spicedb")

// A directory holding SpiceDB files and no policy is not an error: the run
// says what the files declare, and what the patterns found, nothing here.
func TestRunReadsSpiceDBFiles(t *testing.T) {
	var stdout, stderr bytes.Buffer

	if code := Run([]string{spicedbTestdata("find")}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}

	out := stdout.String()
	for _, expected := range []string{
		"3 SpiceDB files",
		"2 definitions, 1 relation, 1 permission, 0 caveats",
		"2 relationships, 2 assertions",
		"Findings\n  nothing",
	} {
		if !strings.Contains(out, expected) {
			t.Errorf("the report does not say %q:\n%s", expected, out)
		}
	}
}

// With -quiet a run prints nothing when it finds nothing, SpiceDB files or not.
func TestRunQuietOnSpiceDBFiles(t *testing.T) {
	var stdout, stderr bytes.Buffer

	if code := Run([]string{"-quiet", spicedbTestdata("find")}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("-quiet printed:\n%s", stdout.String())
	}
}

// The fixture has a write model beside its schema, so the two check parameters
// a writer can fix are findings: the write model says who writes the relation
// and that the parameter is the check's. The run names each, the permission it
// raises, and nothing on the parameters the relationships are meant to carry.
func TestRunReportsSpiceDBFindings(t *testing.T) {
	var stdout, stderr bytes.Buffer

	if code := Run([]string{spicedbFixture}, &stdout, &stderr); code != exitFound {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitFound, stderr.String())
	}
	out := stdout.String()
	for _, expected := range []string{
		"Findings",
		"2  PTD-ZAN-001  A relationship fixes a caveat value the check was meant to supply",
		"document#viewer, user_ip of caveat ip_allowlist  (PTD-ZAN-001)",
		"document#editor, now of caveat not_expired  (PTD-ZAN-001)",
		"from conditional to unconditional",
	} {
		if !strings.Contains(out, expected) {
			t.Errorf("the report does not say %q:\n%s", expected, out)
		}
	}
	for _, unexpected := range []string{"cidr of caveat", "until of caveat"} {
		if strings.Contains(out, unexpected) {
			t.Errorf("the report says %q, which the relationships are meant to carry:\n%s", unexpected, out)
		}
	}
}

// The fixture leaves document#owner and the folder relations without a write
// rule, so the run proposes a safe gate for each, and -questions writes them as
// a relationship-writes model the author confirms and reruns with.
func TestRunProposesSafeGatesForSpiceDB(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run([]string{spicedbFixture}, &stdout, &stderr); code != exitFound {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitFound, stderr.String())
	}
	out := stdout.String()
	for _, expected := range []string{
		"Relations with no write rule",
		"document#owner",
		"safe to gate on edit",
	} {
		if !strings.Contains(out, expected) {
			t.Errorf("the report does not propose a gate: missing %q:\n%s", expected, out)
		}
	}

	path := filepath.Join(t.TempDir(), "proposed.yaml")
	var qout, qerr bytes.Buffer
	if code := Run([]string{"-questions", path, spicedbFixture}, &qout, &qerr); code != exitFound {
		t.Fatalf("questions run exit = %d (stderr: %s)", code, qerr.String())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the questions file: %v", err)
	}
	content := string(raw)
	for _, expected := range []string{
		"model: relationship-writes",
		"relation: owner",
		"gate: { holds: edit }",
	} {
		if !strings.Contains(content, expected) {
			t.Errorf("the skeleton is missing %q:\n%s", expected, content)
		}
	}
	if _, err := zanzibar.LoadWriteModel(path); err != nil {
		t.Errorf("the proposed write model does not load: %v", err)
	}
}

// A relation on a type with no permission to gate on has no gate to propose.
// The report tells the harmless case from the dangerous one by what writing the
// relation raises: tag#label is read by nothing, so it raises nothing and is
// safe to write; group#member is read across types by document#view, so it
// escalates with no local permission to gate it. Neither is claimed to let any
// permission escalate, which no permission on the type was tried for.
func TestRunProposalMessagesByReachability(t *testing.T) {
	dir := t.TempDir()
	schema := "definition user {}\n\n" +
		"definition tag {\n  relation label: user\n}\n\n" +
		"definition group {\n  relation member: user\n}\n\n" +
		"definition document {\n" +
		"  relation owner: user\n" +
		"  relation viewer: user | group#member\n" +
		"  permission view = viewer + owner\n" +
		"  permission edit = owner\n" +
		"}\n"
	schemaPath := filepath.Join(dir, "schema.zed")
	if err := os.WriteFile(schemaPath, []byte(schema), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := Run([]string{schemaPath}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}
	out := stdout.String()
	for _, expected := range []string{
		"no permission on group to gate on; writing it raises document#view",
		"nothing to gate: writing it raises no permission",
	} {
		if !strings.Contains(out, expected) {
			t.Errorf("the report does not say %q:\n%s", expected, out)
		}
	}
	if strings.Contains(out, "any lets a coalition escalate") {
		t.Errorf("the report still claims an escalation for a type with no permission to gate on:\n%s", out)
	}
}

// A schema with no write model and no validation file still gets safe-gate
// proposals: the gates rest on the positions generated from the schema, so a
// run on a bare schema proposes the write-model skeleton to start from. This is
// what lets someone validate their own schema without first writing the model
// by hand.
func TestRunProposesSafeGatesFromABareSchema(t *testing.T) {
	dir := t.TempDir()
	schema := "caveat recent(now timestamp, until timestamp) {\n" +
		"  now < until\n" +
		"}\n\n" +
		"definition user {}\n\n" +
		"definition document {\n" +
		"  relation owner: user\n" +
		"  relation viewer: user | user with recent\n" +
		"  permission edit = owner\n" +
		"  permission view = viewer + edit\n" +
		"}\n"
	schemaPath := filepath.Join(dir, "schema.zed")
	if err := os.WriteFile(schemaPath, []byte(schema), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := Run([]string{schemaPath}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}
	out := stdout.String()
	for _, expected := range []string{
		"Relations with no write rule",
		"document#viewer",
		"safe to gate on",
	} {
		if !strings.Contains(out, expected) {
			t.Errorf("a bare schema does not propose a gate: missing %q:\n%s", expected, out)
		}
	}

	qpath := filepath.Join(dir, "skeleton.yaml")
	var qout, qerr bytes.Buffer
	if code := Run([]string{"-questions", qpath, schemaPath}, &qout, &qerr); code != exitOK {
		t.Fatalf("questions exit = %d (stderr: %s)", code, qerr.String())
	}
	raw, err := os.ReadFile(qpath)
	if err != nil {
		t.Fatalf("reading the skeleton: %v", err)
	}
	content := string(raw)
	// The skeleton fills the subjects the schema allows and the caveat the
	// relation carries, so the author confirms rather than looks them up.
	for _, expected := range []string{
		"model: relationship-writes",
		"relation: viewer",
		"gate: { holds:",
		"subject: [user]",
		"caveat:",
		"- name: recent",
		"now: writer",
	} {
		if !strings.Contains(content, expected) {
			t.Errorf("the skeleton from a bare schema is missing %q:\n%s", expected, content)
		}
	}
	// The type that appears both plain and caveated is listed once, not twice.
	if strings.Contains(content, "[user, user]") {
		t.Errorf("the subject lists a type twice instead of deduplicating:\n%s", content)
	}
	if _, err := zanzibar.LoadWriteModel(qpath); err != nil {
		t.Errorf("the proposed write model does not load: %v", err)
	}
}

// A schema with a write model but no validation file is still analyzed: the
// escalation patterns run from the positions generated from the schema, so a
// finding surfaces without a validation file written by hand. Here a holder of
// edit may write a wildcard viewer, which grants view to every user at once.
func TestRunFindsEscalationsFromASchemaAndWriteModel(t *testing.T) {
	dir := t.TempDir()
	schema := "definition user {}\n\n" +
		"definition document {\n" +
		"\trelation editor: user\n" +
		"\trelation viewer: user | user:*\n" +
		"\tpermission edit = editor\n" +
		"\tpermission view = viewer\n" +
		"}\n"
	writeModel := "schema_version: 1\n" +
		"model: relationship-writes\n" +
		"writes:\n" +
		"  - resource: document\n" +
		"    relation: viewer\n" +
		"    operations: [create, touch]\n" +
		"    gate: { holds: edit }\n" +
		"    subject: [user]\n" +
		"    wildcard: true\n"
	if err := os.WriteFile(filepath.Join(dir, "schema.zed"), []byte(schema), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "writes.yaml"), []byte(writeModel), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := Run([]string{dir}, &stdout, &stderr); code != exitFound {
		t.Fatalf("exit = %d, want %d (stderr: %s)", code, exitFound, stderr.String())
	}
	out := stdout.String()
	for _, expected := range []string{
		"document#view, a grant to every subject at once  (PTD-ZAN-003)",
		"whoever holds edit may write document#viewer",
	} {
		if !strings.Contains(out, expected) {
			t.Errorf("the run does not report the escalation from the schema and write model: missing %q:\n%s", expected, out)
		}
	}
}

// The witness behind an escalation is evidence: the default names the decisive
// write, and -v adds the whole path. The arrow-link finding takes two writes,
// creating a folder and linking the document to it, so the created folder and
// the link through it show only under -v.
func TestTheEscalationWitnessIsBehindTheFlag(t *testing.T) {
	var brief, detail, stderr bytes.Buffer
	if code := Run([]string{"-fail-on", "none", spicedbFixture}, &brief, &stderr); code != exitOK {
		t.Fatalf("exit = %d (stderr: %s)", code, stderr.String())
	}
	if code := Run([]string{"-fail-on", "none", "-v", spicedbFixture}, &detail, &stderr); code != exitOK {
		t.Fatalf("exit = %d (stderr: %s)", code, stderr.String())
	}

	for _, witness := range []string{
		"folder:created-1",
		"document:roadmap#parent@folder:created-1",
	} {
		if strings.Contains(brief.String(), witness) {
			t.Errorf("the default report prints the witness (%q):\n%s", witness, brief.String())
		}
		if !strings.Contains(detail.String(), witness) {
			t.Errorf("-v does not print the witness (%q)", witness)
		}
	}
	if !strings.Contains(detail.String(), "path") {
		t.Errorf("-v does not label the witness path:\n%s", detail.String())
	}
	// Offering a flag already passed reads as a report that is not listening.
	if strings.Contains(detail.String(), "Run with -v") {
		t.Error("-v still offers -v")
	}
}

// Findings fail the run by default, and on -fail-on any, and never on none, the
// same as the findings of a policy.
func TestRunFailsOnSpiceDBFindings(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want int
	}{
		{name: "by default", args: []string{spicedbFixture}, want: exitFound},
		{name: "on any match", args: []string{"-fail-on", "any", spicedbFixture}, want: exitFound},
		{name: "on none", args: []string{"-fail-on", "none", spicedbFixture}, want: exitOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := Run(tt.args, &stdout, &stderr); code != tt.want {
				t.Errorf("exit code = %d, want %d (stderr: %s)", code, tt.want, stderr.String())
			}
		})
	}
}

// Quiet, a run with matches prints them and leaves out the list of files.
func TestRunQuietPrintsSpiceDBMatches(t *testing.T) {
	var stdout, stderr bytes.Buffer

	if code := Run([]string{"-quiet", spicedbFixture}, &stdout, &stderr); code != exitFound {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitFound, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "PTD-ZAN-001") || strings.Contains(out, "SpiceDB files") {
		t.Errorf("-quiet printed:\n%s", out)
	}
}

// A run over policies and SpiceDB files sums up both before it says where the
// rest is, and a run over SpiceDB files alone, when it found escalations, offers
// -v for the writes behind them.
func TestTheFooterComesAfterEverySummary(t *testing.T) {
	var mixed, alone, stderr bytes.Buffer
	if code := Run([]string{"-fail-on", "none", fixture("policy-v1"), spicedbFixture}, &mixed, &stderr); code != exitOK {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}
	if code := Run([]string{spicedbFixture}, &alone, &stderr); code != exitFound {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitFound, stderr.String())
	}

	out := mixed.String()
	trust := strings.Index(out, "How much to trust this")
	files := strings.Index(out, "2 SpiceDB files")
	footer := strings.Index(out, "Run petard explain")
	if trust < 0 || files < trust || footer < files {
		t.Errorf("the policies, the SpiceDB files and the footer are not printed in that order:\n%s", out)
	}
	if !strings.HasSuffix(out, "what it will not report.\n") {
		t.Errorf("the run does not end with the footer:\n%s", out)
	}

	if !strings.Contains(alone.String(), "Run with -v for the writes behind each escalation") {
		t.Errorf("a SpiceDB-alone run with escalations does not offer -v for their evidence:\n%s", alone.String())
	}
	if !strings.Contains(alone.String(), "Run petard explain") {
		t.Errorf("a SpiceDB-alone run does not point to petard explain:\n%s", alone.String())
	}
}

// A schema with no write model that no validation file reads gives the patterns
// nothing to run from, and the run says so instead of reading as clean.
func TestRunSaysWhichSchemasHaveNoEvidence(t *testing.T) {
	var stdout, stderr bytes.Buffer

	if code := Run([]string{filepath.Join(spicedbTestdata("find"), "schema.zed")}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}
	if !strings.Contains(stdout.String(), "has no write model and is read by no validation file") {
		t.Errorf("the report does not say the schema has no evidence:\n%s", stdout.String())
	}
}

// A validation file that cannot be read stops the run, the way a policy that
// does not parse does.
func TestRunStopsOnABrokenSpiceDBFile(t *testing.T) {
	var stdout, stderr bytes.Buffer

	if code := Run([]string{spicedbTestdata("broken")}, &stdout, &stderr); code != exitFailure {
		t.Fatalf("exit code = %d, want %d", code, exitFailure)
	}
	if !strings.Contains(stderr.String(), "missing.yaml") {
		t.Errorf("stderr does not name the file:\n%s", stderr.String())
	}
}
