package analyze

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
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
// rest is, and a run over SpiceDB files alone does not offer the evidence -v
// adds for policies.
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

	if !strings.Contains(alone.String(), "Run petard explain") || strings.Contains(alone.String(), "Run with -v") {
		t.Errorf("the footer of a run over SpiceDB files alone is wrong:\n%s", alone.String())
	}
}

// A schema no validation file reads gives the patterns nothing to take
// evidence from, and the run says so instead of reading as clean.
func TestRunSaysWhichSchemasHaveNoEvidence(t *testing.T) {
	var stdout, stderr bytes.Buffer

	if code := Run([]string{filepath.Join(spicedbTestdata("find"), "schema.zed")}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}
	if !strings.Contains(stdout.String(), "is read by no validation file under the paths") {
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
