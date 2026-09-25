package patterns

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/saluc28/petard/internal/cli/render"
)

// The list is what a report sends people to, and it has to hold without a
// checkout: the patterns come out of the binary, not out of a directory that
// happens to be next to it.
func TestPatternsListsTheRegistryInTheBinary(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run(nil, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}

	out := stdout.String()
	for _, want := range []string{
		"10 patterns, in 8 categories.",
		"ATTR-SELF-WRITE, Attribute self-write",
		"PTD-OPA-001  The subject writes an attribute",
		"petard explain",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the list does not say %q:\n%s", want, out)
		}
	}

	// Three OPA patterns are one category, and the grouping is the thing this
	// list says that a flat table would not.
	group := strings.Index(out, "FAIL-OPEN-ON-ABSENCE")
	for _, id := range []string{"PTD-OPA-002", "PTD-OPA-005", "PTD-OPA-007"} {
		if at := strings.Index(out, id); at < group {
			t.Errorf("%s is printed before its category", id)
		}
	}
}

// The first place this output lands is a terminal somebody is reading, and the
// second is a log that wraps.
func TestTheListFitsTheWidth(t *testing.T) {
	var stdout, stderr bytes.Buffer
	Run(nil, &stdout, &stderr)

	for _, line := range strings.Split(stdout.String(), "\n") {
		if len(line) > render.Width {
			t.Errorf("line of %d columns: %s", len(line), line)
		}
	}
}

// JSON is for the thing that reads a list of ids: a pipeline that keeps its own
// table of what it cares about, or an editor. Every field of it comes from the
// registry, so a pattern added there arrives here with nothing to write.
func TestJSONCarriesEveryPattern(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"-format", "json"}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}

	var decoded struct {
		Patterns []struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Title    string `json:"title"`
			Engine   string `json:"engine"`
			Status   string `json:"status"`
			Category struct {
				ID    string `json:"id"`
				Title string `json:"title"`
			} `json:"category"`
			RequiresWriteModel bool   `json:"requires_write_model"`
			URL                string `json:"url"`
		} `json:"patterns"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("the output is not JSON: %v\n%s", err, stdout.String())
	}
	if len(decoded.Patterns) != 10 {
		t.Fatalf("patterns = %d, want the ten of the registry", len(decoded.Patterns))
	}

	ids := make([]string, 0, len(decoded.Patterns))
	for _, pattern := range decoded.Patterns {
		ids = append(ids, pattern.ID)
		if pattern.Name == "" || pattern.Title == "" || pattern.Engine == "" || pattern.Status == "" {
			t.Errorf("%s is missing a field: %+v", pattern.ID, pattern)
		}
		if pattern.Category.ID == "" || pattern.Category.Title == "" {
			t.Errorf("%s has no category", pattern.ID)
		}
		if !strings.HasSuffix(pattern.URL, ".yaml") {
			t.Errorf("%s does not link its file: %q", pattern.ID, pattern.URL)
		}
	}
	if !slices.IsSorted(ids) {
		t.Errorf("the ids are not in order: %v", ids)
	}

	// PTD-OPA-001 is the pattern that cannot be told from the policy alone, and
	// a consumer deciding whether to pass -write-model reads this field.
	if !decoded.Patterns[0].RequiresWriteModel {
		t.Errorf("%s does not declare requires_write_model", decoded.Patterns[0].ID)
	}
}

func TestPatternsRefusesWhatItCannotDo(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
		want int
	}{
		{"a format that is neither", []string{"-format", "yaml"}, exitUsage},
		{"an argument", []string{"PTD-OPA-001"}, exitUsage},
		{"a registry that is not there", []string{"-registry", "nowhere"}, exitFailure},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := Run(test.args, &stdout, &stderr); code != test.want {
				t.Errorf("exit code = %d, want %d", code, test.want)
			}
			if stderr.Len() == 0 {
				t.Error("nothing was said on stderr")
			}
			if stdout.Len() > 0 {
				t.Errorf("a failed run printed a report anyway:\n%s", stdout.String())
			}
		})
	}
}
