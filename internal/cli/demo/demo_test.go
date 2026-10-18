package demo

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/saluc28/petard/internal/cli/analyze"
)

// Somebody holding a release binary has no policy of their own yet, and this is
// the command that answers what the tool does. If the fixtures are not in the
// binary, or the analysis does not reach the patterns, there is nothing to see.
func TestDemoAnalyzesTheFixturesInTheBinary(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run(nil, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}

	out := stdout.String()
	for _, want := range []string{
		"parsed as rego v1",
		"carol -> alice",
		"PUT /api/v1/users/{id}/roles",
		"2 SpiceDB files",
		"document#viewer, user_ip of caveat ip_allowlist  (PTD-ZAN-001)",
		"petard demo -extract",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the demo does not say %q:\n%s", want, out)
		}
	}
}

// The evidence is a flag away here as it is in analyze, because the first thing
// somebody asks of a summary is where it got that.
func TestDemoShowsTheEvidenceWhenAsked(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"-v"}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}

	out := stdout.String()
	for _, want := range []string{
		"PTD-OPA-006 finding: carol can write editor",
		// The report names the files it read, and they read like a checkout
		// rather than like wherever the fixtures happened to be unpacked, with
		// the same slashes for a schema as for a policy.
		"vulnerable-bundle/policy-v1/authz.rego:",
		"vulnerable-spicedb/schema.zed:26:3",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the detailed demo does not say %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "petard-demo-") || strings.Contains(out, os.TempDir()) {
		t.Errorf("the report shows the temporary directory it ran in:\n%s", out)
	}
}

// The report lines file names up in columns, so a directory whose name changes
// length from one run to the next would move them. Unpacked under two
// directories of different lengths, the demo prints the same bytes.
func TestDemoPrintsTheSameWhereverItUnpacks(t *testing.T) {
	long := filepath.Join(t.TempDir(), "a-directory-with-a-name-long-enough-to-widen-a-column")
	if err := os.Mkdir(long, 0o750); err != nil {
		t.Fatalf("creating %s: %v", long, err)
	}

	var reports [][]string
	for _, dir := range []string{t.TempDir(), long} {
		// os.TempDir reads TMPDIR on Unix and TMP on Windows.
		t.Setenv("TMPDIR", dir)
		t.Setenv("TMP", dir)

		var stdout, stderr bytes.Buffer
		if code := Run([]string{"-v"}, &stdout, &stderr); code != exitOK {
			t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
		}
		reports = append(reports, strings.Split(stdout.String(), "\n"))
	}

	short, wide := reports[0], reports[1]
	for i := range min(len(short), len(wide)) {
		if short[i] != wide[i] {
			t.Fatalf("line %d changes with the directory the bundle is in:\n%s\n%s", i+1, short[i], wide[i])
		}
	}
	if len(short) != len(wide) {
		t.Errorf("the report has %d lines under one directory and %d under the other", len(short), len(wide))
	}
}

// The fixtures are worth having on disk: they are the thing to edit to see what
// the analysis says about a change.
func TestExtractWritesTheBundleAndStops(t *testing.T) {
	dir := t.TempDir()

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"-extract", dir}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}

	for _, name := range []string{
		filepath.Join("vulnerable-bundle", "write-model.yaml"),
		filepath.Join("vulnerable-bundle", "policy-v1", "authz.rego"),
		filepath.Join("vulnerable-bundle", "data"),
		filepath.Join("vulnerable-bundle", "EXPECTED.md"),
		filepath.Join("vulnerable-spicedb", "schema.zed"),
		filepath.Join("vulnerable-spicedb", "validation.yaml"),
		filepath.Join("vulnerable-spicedb", "EXPECTED.md"),
	} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s is missing from the unpacked bundle: %v", name, err)
		}
	}
	if out := stdout.String(); strings.Contains(out, "decisions:") {
		t.Errorf("extracting also ran the analysis:\n%s", out)
	}
}

// What -extract wrote is there to be edited, so a second run into the same
// directory refuses rather than write over the edits.
func TestExtractDoesNotWriteOverAFixture(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"-extract", dir}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}
	edited := filepath.Join(dir, "vulnerable-bundle", "write-model.yaml")
	if err := os.WriteFile(edited, []byte("edited\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	stderr.Reset()
	if code := Run([]string{"-extract", dir}, &stdout, &stderr); code != exitFailure {
		t.Fatalf("exit code = %d, want %d", code, exitFailure)
	}
	if !strings.Contains(stderr.String(), "vulnerable-bundle is already there") {
		t.Errorf("the refusal does not name the directory:\n%s", stderr.String())
	}
	if content, err := os.ReadFile(edited); err != nil || string(content) != "edited\n" {
		t.Errorf("the edit is gone: %q, %v", content, err)
	}
}

// The command -extract prints is the run the demo makes. Run where the fixtures
// were written, it prints what the demo prints, up to the lines the demo adds
// at the end.
func TestTheExtractedCommandPrintsWhatTheDemoPrints(t *testing.T) {
	var demo, stderr bytes.Buffer
	if code := Run(nil, &demo, &stderr); code != exitOK {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}

	t.Chdir(t.TempDir())
	var extracted bytes.Buffer
	if code := Run([]string{"-extract", "."}, &extracted, &stderr); code != exitOK {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}
	_, command, ok := strings.Cut(extracted.String(), "analyze them with: petard analyze ")
	if !ok {
		t.Fatalf("-extract prints no command:\n%s", extracted.String())
	}

	// The fixtures are full of findings, so the run exits 3; what it prints is
	// what is compared.
	var own bytes.Buffer
	analyze.Run(strings.Fields(command), &own, &stderr)
	if own.Len() == 0 || !strings.HasPrefix(demo.String(), own.String()) {
		t.Errorf("the command -extract prints does not print what the demo prints:\n%s", own.String())
	}
}

func TestDemoRefusesAPathOfItsOwn(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"some/policy"}, &stdout, &stderr); code != exitUsage {
		t.Errorf("exit code = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(stderr.String(), "petard analyze") {
		t.Errorf("the refusal does not point at the command that takes a path:\n%s", stderr.String())
	}
}
