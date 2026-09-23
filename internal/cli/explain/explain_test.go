package explain

import (
	"bytes"
	"strings"
	"testing"

	"github.com/saluc28/petard/internal/cli/render"
	"github.com/saluc28/petard/internal/taxonomy"
	registry "github.com/saluc28/petard/taxonomy-registry"
)

// What a finding costs the reader is a trip to the repository, and this is the
// command that saves it: the same file, in the terminal, out of the binary.
func TestExplainPrintsThePatternBehindAFinding(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"PTD-OPA-001"}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}

	out := stdout.String()
	for _, want := range []string{
		"PTD-OPA-001  attribute-self-write",
		"The subject writes an attribute the policy reads to decide about them",
		"ATTR-SELF-WRITE",
		"What it is",
		"What has to be true for it to be a defect",
		"What it looks for",
		"It needs a write model",
		"Where it fires with nothing behind it",
		"taxonomy-registry/opa/PTD-OPA-001-attribute-self-write.yaml",
		registry.URL,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the explanation does not say %q:\n%s", want, out)
		}
	}

	// The markdown emphasis of the files is for GitHub. In a terminal it is
	// noise, and the sentence is the same without it.
	if strings.Contains(out, "**") {
		t.Errorf("markdown emphasis reached the terminal:\n%s", out)
	}
}

// A report prints both the id and the name, so both have to work. Asking
// somebody to remember which one the command wants is asking them to look it up
// before they can look it up.
func TestTheNameAndTheIDReachTheSamePattern(t *testing.T) {
	var byID, byName, stderr bytes.Buffer
	if code := Run([]string{"PTD-OPA-006"}, &byID, &stderr); code != exitOK {
		t.Fatalf("by id: exit code = %d (stderr: %s)", code, stderr.String())
	}
	if code := Run([]string{"Write-Allowed-By-Another-Decision"}, &byName, &stderr); code != exitOK {
		t.Fatalf("by name: exit code = %d (stderr: %s)", code, stderr.String())
	}
	if byID.String() != byName.String() {
		t.Error("the id and the name print different things")
	}
}

// Every pattern of the registry has to survive being printed, not just the one
// that was open while this was written. A file that leaves a section empty
// prints without it rather than printing a heading with nothing under it.
func TestEveryPatternPrintsWhole(t *testing.T) {
	all, err := taxonomy.LoadRegistry(registry.OPA)
	if err != nil {
		t.Fatalf("LoadRegistry() error = %v", err)
	}

	for _, pattern := range all {
		t.Run(pattern.ID, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := Run([]string{pattern.ID}, &stdout, &stderr); code != exitOK {
				t.Fatalf("exit code = %d (stderr: %s)", code, stderr.String())
			}

			out := stdout.String()
			for _, want := range []string{pattern.Title, "What it is", "Written down in", pattern.File} {
				if !strings.Contains(out, want) {
					t.Errorf("the explanation does not say %q", want)
				}
			}
			for _, line := range strings.Split(out, "\n") {
				// A URL is one word, and breaking it is worse than letting it
				// run over: nobody can copy half a link.
				if len(line) > render.Width && !strings.Contains(line, "://") {
					t.Errorf("line of %d columns: %s", len(line), line)
				}
			}
		})
	}
}

// An id nobody has heard of is the common typo, and the answer to it is the
// list, not a stack trace.
func TestAnUnknownPatternPointsAtTheList(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"PTD-OPA-404"}, &stdout, &stderr); code != exitUsage {
		t.Errorf("exit code = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(stderr.String(), "petard patterns") {
		t.Errorf("the error does not send anybody to the list: %s", stderr.String())
	}
	if stdout.Len() > 0 {
		t.Errorf("a failed lookup printed something anyway:\n%s", stdout.String())
	}
}

func TestExplainRefusesWhatItCannotDo(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
		want int
	}{
		{"no pattern at all", nil, exitUsage},
		{"two patterns", []string{"PTD-OPA-001", "PTD-OPA-002"}, exitUsage},
		{"a registry that is not there", []string{"-registry", "nowhere", "PTD-OPA-001"}, exitFailure},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := Run(test.args, &stdout, &stderr); code != test.want {
				t.Errorf("exit code = %d, want %d", code, test.want)
			}
			if stderr.Len() == 0 {
				t.Error("nothing was said on stderr")
			}
		})
	}
}
