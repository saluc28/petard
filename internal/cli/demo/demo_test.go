package demo

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Somebody holding a release binary has no policy of their own yet, and this is
// the command that answers what the tool does. If the bundle is not in the
// binary, or the analysis does not reach the patterns, there is nothing to see.
func TestDemoAnalyzesTheBundleInTheBinary(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run(nil, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}

	out := stdout.String()
	for _, want := range []string{
		"parsed as rego v1",
		"carol -> alice",
		"PUT /api/v1/users/{id}/roles",
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
		// rather than like wherever the bundle happened to be unpacked.
		"vulnerable-bundle/policy-v1/authz.rego:",
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

// The bundle is worth having on disk: it is the thing to edit to see what the
// analysis says about a change.
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
	} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s is missing from the unpacked bundle: %v", name, err)
		}
	}
	if out := stdout.String(); strings.Contains(out, "decisions:") {
		t.Errorf("extracting also ran the analysis:\n%s", out)
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
