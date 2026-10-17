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

// A directory holding SpiceDB files and no policy is not an error: the run
// says what the files declare, and that nothing was checked in them.
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
		"No pattern runs on SpiceDB schemas in this version",
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
