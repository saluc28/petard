package analyze

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/saluc28/petard/internal/cli/render"
	"github.com/saluc28/petard/internal/zanzibar"
)

// Somebody reads a report to know what to change, and one write rule can open many
// raises. So the escalations come under the rule behind them, the rule that opens the
// most first, with the permissions that rise the same way on one line. The counts stay
// the matches they were, and so does the verdict of the run.
func TestTheEscalationsComeUnderTheRuleBehindThem(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run([]string{spicedbFixture}, &stdout, &stderr); code != exitFound {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitFound, stderr.String())
	}
	out := stdout.String()

	for _, expected := range []string{
		"    3  PTD-ZAN-006  A gated write grants to another a right the writer never held",
		"  anyone may write document#viewer, through POST /api/v1/documents/{id}/viewers\n" +
			"    PTD-ZAN-003  a grant to every subject at once\n" +
			"    raises       access and view on document, from no to yes\n" +
			"    PTD-ZAN-006  a grant written for another the writer lacks\n",
		"  anyone may delete document#banned, through DELETE /api/v1/documents/{id}/bans/{user}\n" +
			"    PTD-ZAN-002  a deny lifted by a delete\n" +
			"    raises       access on document, from no to yes\n",
	} {
		if !strings.Contains(out, expected) {
			t.Errorf("the report does not say %q:\n%s", expected, out)
		}
	}
	if strings.Count(out, "anyone may write document#viewer, through") != 1 {
		t.Errorf("a rule comes under more than one heading:\n%s", out)
	}
	most := strings.Index(out, "anyone may write document#viewer, through")
	least := strings.Index(out, "anyone may delete document#banned")
	if most > least {
		t.Errorf("the rule that opens the most does not come first:\n%s", out)
	}
	if !strings.Contains(out, "document#viewer, user_ip of caveat ip_allowlist  (PTD-ZAN-001)") {
		t.Errorf("the caveat finding, which no gate closes, left its own heading:\n%s", out)
	}
}

// Two schemas can hold rules that read alike, and a rule of one says nothing about the
// other, so they stay apart and each says where it comes from. With one schema there is
// nothing to tell apart and the report does not say it.
func TestARuleOfOneSchemaStaysApartFromAnother(t *testing.T) {
	openfgaFixture := filepath.Join("..", "..", "..", "fixtures", "vulnerable-openfga")
	var stdout, stderr bytes.Buffer
	Run([]string{spicedbFixture, openfgaFixture}, &stdout, &stderr)
	out := stdout.String()
	if got := strings.Count(out, "anyone may delete document#banned, through"); got != 2 {
		t.Errorf("the rule comes under %d headings, want one per schema:\n%s", got, out)
	}
	for _, schema := range []string{"vulnerable-spicedb/schema.zed", "vulnerable-openfga/model.fga"} {
		if !strings.Contains(out, "    in           ") || !strings.Contains(out, schema) {
			t.Errorf("no group says it comes from %s:\n%s", schema, out)
		}
	}

	stdout.Reset()
	Run([]string{spicedbFixture}, &stdout, &stderr)
	if strings.Contains(stdout.String(), "    in           ") {
		t.Errorf("with one schema a group still says where it comes from:\n%s", stdout.String())
	}
}

// Grouping prints less, and what it leaves out has to be what repeats. A permission that
// rises another way keeps its own line, an aspect true of one match is still said, and a
// witness several permissions share prints once while one that differs says what it is for.
func TestALimitTheAnalysisReachedIsSaid(t *testing.T) {
	var out bytes.Buffer
	r := zanzibarRun{limits: zanzibar.Limits{SearchesStopped: 2}}
	printZanzibar(&out, r, nil, printing{})
	if !strings.Contains(out.String(), "2 searches for a witness stopped at the limit") {
		t.Errorf("the report does not say the analysis stopped short:\n%s", out.String())
	}

	out.Reset()
	printZanzibar(&out, zanzibarRun{}, nil, printing{})
	if strings.Contains(out.String(), "limit") {
		t.Errorf("nothing stopped short, and the report says so:\n%s", out.String())
	}
}

// What the engine says of a run reaches the report. A coalition can join any of thirty
// teams, more sets of up to four than a search weighs.
func TestARunThatReachesALimitSaysSo(t *testing.T) {
	dir := t.TempDir()
	schema := "definition user {}\n\n" +
		"definition team {\n" +
		"\trelation member: user\n" +
		"}\n\n" +
		"definition document {\n" +
		"\trelation viewer: team#member\n" +
		"\tpermission view = viewer\n" +
		"}\n"
	writeModel := "schema_version: 1\n" +
		"model: relationship-writes\n" +
		"writes:\n" +
		"  - resource: team\n" +
		"    relation: member\n" +
		"    operations: [create]\n" +
		"    gate: anyone\n" +
		"    subject: self\n"
	var validation strings.Builder
	validation.WriteString("schemaFile: schema.zed\nrelationships: |-\n")
	for i := range 30 {
		fmt.Fprintf(&validation, "  document:roadmap#viewer@team:t%d#member\n", i)
	}
	for name, content := range map[string]string{"schema.zed": schema, "writes.yaml": writeModel, "validation.yaml": validation.String()} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"-fail-on", "none", dir}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit = %d (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "stopped at the limit") {
		t.Errorf("the report does not say the search stopped:\n%s", stdout.String())
	}
}

func TestPrintCauseLosesNothingAMatchSays(t *testing.T) {
	match := func(typ, permission string, before zanzibar.Level, details ...zanzibar.Detail) zanzibar.Match {
		return zanzibar.Match{
			PatternID: "PTD-ZAN-006",
			Details:   details,
			Raise: &zanzibar.Raise{
				Cause:      "anyone may write team#member",
				Kind:       "a grant written for another",
				Type:       typ,
				Permission: permission,
				Before:     before,
				After:      zanzibar.Yes,
			},
		}
	}
	witness := func(step string) zanzibar.Detail {
		return zanzibar.Detail{Label: "path", Text: step, Verbose: true}
	}
	chain := zanzibar.Detail{Label: "also", Text: "a chain of 2 writes"}

	tests := []struct {
		name     string
		matches  []zanzibar.Match
		verbose  bool
		expected string
	}{
		{
			name: "permissions that rise the same way share a line",
			matches: []zanzibar.Match{
				match("document", "view", zanzibar.No),
				match("document", "edit", zanzibar.No),
				match("document", "access", zanzibar.No),
			},
			expected: "    raises       view, edit and access on document, from no to yes\n",
		},
		{
			name: "another type or another level keeps its own line",
			matches: []zanzibar.Match{
				match("document", "view", zanzibar.No),
				match("team", "member", zanzibar.No),
				match("document", "edit", zanzibar.Conditional),
			},
			expected: "    raises       view on document, from no to yes\n" +
				"    raises       member on team, from no to yes\n" +
				"    raises       edit on document, from conditional to yes\n",
		},
		{
			name: "an aspect of one match is said once",
			matches: []zanzibar.Match{
				match("document", "view", zanzibar.No),
				match("document", "edit", zanzibar.No, chain),
				match("document", "access", zanzibar.No, chain),
			},
			expected: "    also         a chain of 2 writes\n",
		},
		{
			name: "a shared witness prints once",
			matches: []zanzibar.Match{
				match("document", "view", zanzibar.No, witness("write a")),
				match("document", "edit", zanzibar.No, witness("write a")),
			},
			verbose:  true,
			expected: "    path         write a\n",
		},
		{
			name: "a witness that differs says what it is for",
			matches: []zanzibar.Match{
				match("document", "view", zanzibar.No, witness("write a")),
				match("document", "edit", zanzibar.No, witness("write b")),
				match("document", "access", zanzibar.No, witness("write a")),
			},
			verbose: true,
			expected: "    path         for view and access:\n" +
				"                 write a\n" +
				"                 for edit:\n" +
				"                 write b\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			group := causeGroup{cause: "anyone may write team#member", matches: tt.matches}
			printCause(&out, group, false, render.Style{}, tt.verbose)
			if !strings.Contains(out.String(), tt.expected) {
				t.Errorf("printCause does not say\n%s\nit prints\n%s", tt.expected, out.String())
			}
			if strings.Count(out.String(), "write a\n") > 1 || strings.Count(out.String(), "a chain of 2 writes") > 1 {
				t.Errorf("printCause repeats itself:\n%s", out.String())
			}
			if !tt.verbose && strings.Contains(out.String(), "path") {
				t.Errorf("a witness is on the first screen:\n%s", out.String())
			}
		})
	}
}

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
		"2  PTD-ZAN-001  A relationship fixes a condition value the check was meant to supply",
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
		"PTD-ZAN-003  a grant to every subject at once",
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

const (
	openFGAModel = `model
  schema 1.1
type user
type team
  relations
    define member: [user]
type document
  relations
    define owner: [user]
    define banned: [user]
    define viewer: ([user with within, team#member] or owner) but not banned
condition within(cidr: string, user_ip: string) {
  user_ip == cidr
}
`
	openFGAWrites = `schema_version: 1
model: relationship-writes
writes:
  - resource: document
    relation: viewer
    operations: [create]
    gate: anyone
    subject: [user, "team#member"]
    caveat:
      - name: within
        parameters:
          cidr: writer
          user_ip: application
    via: POST /documents/viewers
  - resource: team
    relation: member
    operations: [create]
    gate: anyone
    subject: self
    via: POST /teams/join
  - resource: document
    relation: banned
    operations: [delete]
    gate: anyone
    subject: self
    via: DELETE /documents/bans
`
	openFGAStore = `model_file: model.fga
tuples:
  - {user: user:anne, relation: owner, object: document:1}
  - {user: "team:eng#member", relation: viewer, object: document:1}
tests:
  - name: reads
    check:
      - {user: user:anne, object: document:1, assertions: {viewer: true}}
  - name: joined
    tuples:
      - {user: user:bob, relation: member, object: team:eng}
    check:
      - {user: user:bob, object: document:1, assertions: {viewer: true}}
`
)

func writeOpenFGA(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// An OpenFGA model with a write model beside it gets the patterns of the engine, in
// the words of the product, and its exit code as a SpiceDB schema does.
func TestRunReportsOpenFGAFindings(t *testing.T) {
	dir := writeOpenFGA(t, map[string]string{"model.fga": openFGAModel, "writes.yaml": openFGAWrites, "store.fga.yaml": openFGAStore})

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"-no-color", dir}, &stdout, &stderr); code != exitFound {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitFound, stderr.String())
	}
	out := stdout.String()
	for _, expected := range []string{
		"2 OpenFGA files",
		"3 types, 4 relations, 1 condition",
		"store file of",
		"test joined, 3 tuples, 1 check",
		"(PTD-ZAN-001)",
		"PTD-ZAN-002  a deny lifted by a delete",
		"PTD-ZAN-005  a group the coalition can join",
		"PTD-ZAN-008  written in behind a gate that needs no permission",
		"user_ip of condition within",
		"which the writer may set on the tuple instead",
		"model.fga:11:",
	} {
		if !strings.Contains(out, expected) {
			t.Errorf("the report does not say %q:\n%s", expected, out)
		}
	}
	for _, unwanted := range []string{"SpiceDB", "of caveat", "on the relationship"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("the report says %q:\n%s", unwanted, out)
		}
	}
}

// With no write model and no store file, a model is reported as having no evidence,
// in the words of the product, and not read as clean. A relation with no rule still
// gets a gate proposed.
func TestRunSaysAnOpenFGAModelHasNoEvidence(t *testing.T) {
	dir := writeOpenFGA(t, map[string]string{"model.fga": openFGAModel})

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"-no-color", dir}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}
	out := strings.Join(strings.Fields(stdout.String()), " ")
	for _, expected := range []string{
		"1 OpenFGA file",
		"is read by no store file",
		"no tuple or check to take as evidence",
		"Relations with no write rule",
	} {
		if !strings.Contains(out, expected) {
			t.Errorf("the report does not say %q:\n%s", expected, stdout.String())
		}
	}
}

// The skeleton -questions writes for an OpenFGA model holds writes the product has, and
// reads back as a write model the next run takes.
func TestRunWritesAnOpenFGAWriteModel(t *testing.T) {
	dir := writeOpenFGA(t, map[string]string{"model.fga": openFGAModel})
	skeleton := filepath.Join(t.TempDir(), "writes.yaml")

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"-no-color", "-questions", skeleton, dir}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}
	content, err := os.ReadFile(skeleton)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "operations: [create]") || strings.Contains(string(content), "touch") {
		t.Errorf("the skeleton does not propose the writes OpenFGA has:\n%s", content)
	}
	if _, err := zanzibar.LoadWriteModel(skeleton); err != nil {
		t.Errorf("the skeleton does not read back: %v\n%s", err, content)
	}
}

// A directory holding both products reports both, each under its own heading.
func TestRunReportsBothProducts(t *testing.T) {
	dir := writeOpenFGA(t, map[string]string{
		"model.fga":  openFGAModel,
		"schema.zed": "definition user {}\n",
	})

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"-no-color", dir}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}
	out := stdout.String()
	openFGA, spiceDB := strings.Index(out, "1 OpenFGA file"), strings.Index(out, "1 SpiceDB file")
	if openFGA < 0 || spiceDB < 0 || openFGA > spiceDB {
		t.Errorf("want a heading for each product, in order:\n%s", out)
	}
}

// The question whose answer decides the most comes first: the relation whose writes can
// raise the most permissions. A relation that raises nothing comes last, and two that
// raise as many keep the order of the schema.
func TestTheQuestionsComeInTheOrderOfWhatTheyCanRaise(t *testing.T) {
	dir := t.TempDir()
	schema := "definition user {}\n\n" +
		"definition document {\n" +
		"\trelation note: user\n" +
		"\trelation viewer: user\n" +
		"\trelation reviewer: user\n" +
		"\trelation editor: user\n" +
		"\tpermission edit = editor\n" +
		"\tpermission view = viewer + reviewer + edit\n" +
		"}\n"
	if err := os.WriteFile(filepath.Join(dir, "schema.zed"), []byte(schema), 0o600); err != nil {
		t.Fatal(err)
	}
	order := func(text string, names ...string) {
		t.Helper()
		last := -1
		for _, name := range names {
			at := strings.Index(text, name)
			if at < 0 || at < last {
				t.Errorf("%s is not where it belongs, after %v:\n%s", name, names, text)
				return
			}
			last = at
		}
	}

	var stdout, stderr bytes.Buffer
	path := filepath.Join(t.TempDir(), "questions.yaml")
	if code := Run([]string{"-fail-on", "none", "-questions", path, dir}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit = %d (stderr: %s)", code, stderr.String())
	}
	order(stdout.String(), "document#editor", "document#viewer", "document#reviewer", "document#note")
	if !strings.Contains(stdout.String(), "can raise 2") {
		t.Errorf("the report does not say how much a relation can raise:\n%s", stdout.String())
	}

	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content := string(written)
	order(content, "relation: editor", "relation: viewer", "relation: reviewer", "relation: note")
	order(content, "# can raise document#edit, document#view\n", "relation: editor")
}
