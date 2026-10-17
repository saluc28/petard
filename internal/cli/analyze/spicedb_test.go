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

// The fixture holds two parameters the checks supply and two the relationships
// carry, and the run reports the first two as candidates with the check each
// lets through, and nothing on the others.
func TestRunReportsSpiceDBCandidates(t *testing.T) {
	var stdout, stderr bytes.Buffer

	if code := Run([]string{spicedbFixture}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}
	out := stdout.String()
	for _, expected := range []string{
		"Candidates, which match a pattern and are not proven",
		"2  PTD-ZAN-001  A relationship fixes a caveat value the check was meant to supply",
		"document#viewer, user_ip of caveat ip_allowlist  (PTD-ZAN-001)",
		"document#editor, now of caveat not_expired  (PTD-ZAN-001)",
		"goes from no to yes",
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

// Candidates fail the run when -fail-on asks for any match, and only then, the
// same as the candidates of a policy.
func TestRunFailsOnSpiceDBCandidatesWhenAsked(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want int
	}{
		{name: "by default", args: []string{spicedbFixture}, want: exitOK},
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

	if code := Run([]string{"-quiet", spicedbFixture}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "PTD-ZAN-001") || strings.Contains(out, "SpiceDB files") {
		t.Errorf("-quiet printed:\n%s", out)
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
