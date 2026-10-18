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

// Somebody who uses one of the products has no use for the other's fixture, and
// a name gives them theirs alone, before the flags or after them.
func TestDemoAnalyzesOneFixtureByName(t *testing.T) {
	tests := []struct {
		name           string
		args           []string
		fixture        string
		want, unwanted string
	}{
		{name: "opa", args: []string{"opa"}, fixture: "opa", want: "carol -> alice", unwanted: "SpiceDB file"},
		{name: "spicedb", args: []string{"spicedb"}, fixture: "spicedb", want: "(PTD-ZAN-001)", unwanted: "parsed as rego"},
		{name: "a flag after the name", args: []string{"spicedb", "-v"}, fixture: "spicedb", want: "(PTD-ZAN-001)", unwanted: "parsed as rego"},
		{name: "a flag before the name", args: []string{"-v", "opa"}, fixture: "opa", want: "PTD-OPA-006 finding", unwanted: "SpiceDB file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := Run(tt.args, &stdout, &stderr); code != exitOK {
				t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
			}
			out := stdout.String()
			if !strings.Contains(out, tt.want) || strings.Contains(out, tt.unwanted) {
				t.Errorf("the demo of one fixture does not say %q, or says %q:\n%s", tt.want, tt.unwanted, out)
			}
			if !strings.Contains(out, "petard demo -extract <dir> "+tt.fixture) {
				t.Errorf("the closing line does not offer to extract %s:\n%s", tt.fixture, out)
			}
		})
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
// the analysis says about a change. A name writes that fixture alone.
func TestExtractWritesTheFixturesAndStops(t *testing.T) {
	bundle := []string{
		filepath.Join("vulnerable-bundle", "write-model.yaml"),
		filepath.Join("vulnerable-bundle", "policy-v1", "authz.rego"),
		filepath.Join("vulnerable-bundle", "data"),
		filepath.Join("vulnerable-bundle", "EXPECTED.md"),
	}
	schema := []string{
		filepath.Join("vulnerable-spicedb", "schema.zed"),
		filepath.Join("vulnerable-spicedb", "validation.yaml"),
		filepath.Join("vulnerable-spicedb", "EXPECTED.md"),
	}
	tests := []struct {
		name            string
		args            []string
		want, unwritten []string
	}{
		{name: "all of them", want: append(bundle, schema...)},
		{name: "by name", args: []string{"spicedb"}, want: schema, unwritten: []string{"vulnerable-bundle"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			var stdout, stderr bytes.Buffer
			if code := Run(append([]string{"-extract", dir}, tt.args...), &stdout, &stderr); code != exitOK {
				t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
			}
			for _, name := range tt.want {
				if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
					t.Errorf("%s is missing from what was unpacked: %v", name, err)
				}
			}
			for _, name := range tt.unwritten {
				if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
					t.Errorf("%s was written, and the name asked for another fixture", name)
				}
			}
			if out := stdout.String(); strings.Contains(out, "decisions") || strings.Contains(out, "SpiceDB file") {
				t.Errorf("extracting also ran the analysis:\n%s", out)
			}
		})
	}
}

// What -extract wrote is there to be edited, so a second run into the same
// directory refuses rather than write over the edits, and writes nothing at all.
func TestExtractDoesNotWriteOverAFixture(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"-extract", dir, "opa"}, &stdout, &stderr); code != exitOK {
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
	if _, err := os.Stat(filepath.Join(dir, "vulnerable-spicedb")); err == nil {
		t.Error("the run that refused wrote the other fixture")
	}

	// The fixture that is not there yet can still be written beside it.
	if code := Run([]string{"-extract", dir, "spicedb"}, &stdout, &stderr); code != exitOK {
		t.Errorf("exit code = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}
}

// The command -extract prints is the run the demo makes. Run where the fixtures
// were written, it prints what the demo prints, up to the lines the demo adds
// at the end, for all of them and for every fixture alone.
func TestTheExtractedCommandPrintsWhatTheDemoPrints(t *testing.T) {
	for _, name := range append([]string{""}, names()...) {
		t.Run("demo "+name, func(t *testing.T) {
			var args []string
			if name != "" {
				args = []string{name}
			}
			var demo, stderr bytes.Buffer
			if code := Run(args, &demo, &stderr); code != exitOK {
				t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
			}

			t.Chdir(t.TempDir())
			var extracted bytes.Buffer
			if code := Run(append([]string{"-extract", "."}, args...), &extracted, &stderr); code != exitOK {
				t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
			}
			_, command, ok := strings.Cut(extracted.String(), " with: petard analyze ")
			if !ok {
				t.Fatalf("-extract prints no command:\n%s", extracted.String())
			}

			// The fixtures are full of findings, so the run exits 3; what it
			// prints is what is compared.
			var own bytes.Buffer
			analyze.Run(strings.Fields(command), &own, &stderr)
			if own.Len() == 0 || !strings.HasPrefix(demo.String(), own.String()) {
				t.Errorf("the command -extract prints does not print what the demo prints:\n%s", own.String())
			}
		})
	}
}

// The demo takes the name of one of its fixtures and nothing else: a path is
// for petard analyze.
func TestDemoRefusesWhatIsNotTheNameOfAFixture(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "a path", args: []string{"some/policy"}, want: "opa and spicedb; run petard analyze"},
		{name: "two names", args: []string{"opa", "spicedb"}, want: "one name at most"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := Run(tt.args, &stdout, &stderr); code != exitUsage {
				t.Errorf("exit code = %d, want %d", code, exitUsage)
			}
			if !strings.Contains(stderr.String(), tt.want) {
				t.Errorf("the refusal does not say %q:\n%s", tt.want, stderr.String())
			}
		})
	}
}
