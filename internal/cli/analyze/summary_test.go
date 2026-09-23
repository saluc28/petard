package analyze

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/saluc28/petard/internal/cli/render"
)

// withFixtureData is the fixture with everything declared: the documents and
// who can write them, which is what turns matches into findings about named
// people.
func withFixtureData(args ...string) []string {
	bundle := filepath.Join("..", "..", "..", "fixtures", "vulnerable-bundle")
	return append([]string{
		"-write-model", filepath.Join(bundle, "write-model.yaml"),
		"-data", filepath.Join(bundle, "data"),
	}, append(args, fixture("policy-v1"))...)
}

// clean writes a policy nothing in the taxonomy matches, which is the run that
// has to end in silence and in a zero.
func clean(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	policy := "package clean\n\ndefault allow := false\n\nallow if input.user == \"root\"\n"
	if err := os.WriteFile(filepath.Join(dir, "clean.rego"), []byte(policy), 0o600); err != nil {
		t.Fatalf("writing the policy: %v", err)
	}
	return dir
}

// The first screen is the point of the summary: who can take whose place, how
// they do it, and under which pattern. Everything else can wait for -v.
func TestTheSummaryLeadsWithTheEscalations(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run(withFixtureData("-fail-on", failOnNone), &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}

	out := stdout.String()
	for _, want := range []string{
		"Escalations",
		"mallory -> dave  (PTD-OPA-003, confidence D)",
		"carol -> alice  (PTD-OPA-006, confidence D)",
		"editor into data.users.{owner}.roles",
		"PUT /api/v1/users/{id}/roles",
		"Findings",
		"5  PTD-OPA-004  A decision depends on an external source",
		"Candidates, which need a write model to become findings",
		"How much to trust this",
		"Level D (field names): the subject is input.user",
		"The write model covers 6 of 11 paths read (54%).",
		"Run with -v",
		"petard explain",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the summary does not say %q:\n%s", want, out)
		}
	}

	// The escalations come before the counts. A report that buries the two
	// named people under a table of reads is the report this replaced.
	if strings.Index(out, "Escalations") > strings.Index(out, "Findings") {
		t.Errorf("the escalations are printed after the findings:\n%s", out)
	}

	// The names are the ones the policy uses. BloodHound upper-cases them on
	// ingest, and that is BloodHound's business, not the terminal's.
	if strings.Contains(out, "CAROL") || strings.Contains(out, "MALLORY") {
		t.Errorf("the summary shouts the principals:\n%s", out)
	}
}

// The evidence is what -v adds, and what the default leaves out. Both halves
// matter: a summary that still prints the reads is not a summary.
func TestTheEvidenceIsBehindTheFlag(t *testing.T) {
	var brief, detail, stderr bytes.Buffer
	if code := Run(withFixtureData("-fail-on", failOnNone), &brief, &stderr); code != exitOK {
		t.Fatalf("exit code = %d (stderr: %s)", code, stderr.String())
	}
	if code := Run(withFixtureData("-fail-on", failOnNone, "-v"), &detail, &stderr); code != exitOK {
		t.Fatalf("exit code = %d (stderr: %s)", code, stderr.String())
	}

	for _, evidence := range []string{
		"PATH",
		"data paths read by the decisions",
		"RESIDUAL CONDITIONS",
		"places to look",
		"not covered:",
	} {
		if strings.Contains(brief.String(), evidence) {
			t.Errorf("the summary prints the evidence (%q):\n%s", evidence, brief.String())
		}
		if !strings.Contains(detail.String(), evidence) {
			t.Errorf("-v does not print the evidence (%q)", evidence)
		}
	}

	// Offering a flag somebody has already passed reads as a report that is
	// not listening.
	if strings.Contains(detail.String(), "Run with -v") {
		t.Error("-v still offers -v")
	}
}

// Without a write model there is nobody to name as a writer, so there are no
// escalations to report, and a bare "none" would read as "none exist".
func TestWithoutAWriteModelTheSummarySaysWhy(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"-fail-on", failOnNone, fixture("policy-v1")}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d (stderr: %s)", code, stderr.String())
	}

	out := stdout.String()
	for _, want := range []string{
		"none named: without a write model nobody is declared able to write",
		"No write model: every match stays a candidate",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the summary does not say %q:\n%s", want, out)
		}
	}
}

// A pattern that could not run is not a pattern that found nothing, and the
// summary has to keep the difference the long report keeps.
func TestTheSummarySaysWhichPatternsDidNotRun(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"-fail-on", failOnNone, fixture("policy-v1")}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d (stderr: %s)", code, stderr.String())
	}

	out := stdout.String()
	if !strings.Contains(out, "Patterns that did not run") {
		t.Errorf("the summary hides the patterns that could not run:\n%s", out)
	}
	for _, id := range []string{"PTD-OPA-002", "PTD-OPA-003", "PTD-OPA-006", "PTD-OPA-008"} {
		if !strings.Contains(out, id+"  it reads the concrete data") {
			t.Errorf("%s is not named among the patterns that did not run:\n%s", id, out)
		}
	}
}

// Quiet is for the pipeline: a line in the log when there is something, and not
// a byte when there is not.
func TestQuietPrintsTheResultsAndNothingElse(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run(withFixtureData("-fail-on", failOnNone, "-quiet"), &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d (stderr: %s)", code, stderr.String())
	}

	out := stdout.String()
	if !strings.Contains(out, "carol -> alice") || !strings.Contains(out, "PTD-OPA-004") {
		t.Errorf("quiet dropped the results themselves:\n%s", out)
	}
	for _, unwanted := range []string{"parsed as rego", "How much to trust this", "Run with -v"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("quiet printed %q:\n%s", unwanted, out)
		}
	}

	stdout.Reset()
	if code := Run([]string{"-quiet", "-entrypoint", "clean/allow", clean(t)}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d (stderr: %s)", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("quiet printed something about a policy with nothing in it:\n%s", stdout.String())
	}
}

// The exit code is what a pipeline reads, and the whole reason it can read it
// is that having found something and having broken down are different numbers.
func TestTheExitCodeSaysWhatWasFound(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
		want int
	}{
		{"findings by default", withFixtureData(), exitFound},
		{"findings asked for", withFixtureData("-fail-on", failOnFindings), exitFound},
		{"anything at all", withFixtureData("-fail-on", failOnAny), exitFound},
		{"nothing fails", withFixtureData("-fail-on", failOnNone), exitOK},
		{"a clean policy", []string{"-entrypoint", "clean/allow", clean(t)}, exitOK},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := Run(test.args, &stdout, &stderr); code != test.want {
				t.Errorf("exit code = %d, want %d (stderr: %s)", code, test.want, stderr.String())
			}
		})
	}
}

// Two runs of the same bundle have to print the same bytes, or a diff between
// two reports is unreadable and a report in version control churns. The
// findings are grouped and the patterns that did not run are listed out of
// maps, which is where the order would come from if nobody imposed one.
func TestTwoRunsPrintTheSameReport(t *testing.T) {
	var first, second, stderr bytes.Buffer
	Run(withFixtureData("-fail-on", failOnNone), &first, &stderr)
	Run(withFixtureData("-fail-on", failOnNone), &second, &stderr)

	if first.String() != second.String() {
		t.Errorf("two runs printed different reports:\n%s\n---\n%s", first.String(), second.String())
	}
}

// The first place this lands is a CI log. Nothing in the summary is worth a
// line that wraps there, and nothing in it is worth a character the log is not
// sure to hold.
func TestTheSummaryFitsATerminal(t *testing.T) {
	var stdout, stderr bytes.Buffer
	Run(withFixtureData("-fail-on", failOnNone), &stdout, &stderr)

	for _, line := range strings.Split(stdout.String(), "\n") {
		if len(line) > render.Width {
			t.Errorf("line of %d columns: %s", len(line), line)
		}
		for _, r := range line {
			if r > 126 {
				t.Errorf("line with a character no log is sure to hold (%q): %s", r, line)
				break
			}
		}
	}
}
