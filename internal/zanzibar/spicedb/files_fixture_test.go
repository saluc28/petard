package spicedb

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	yaml "go.yaml.in/yaml/v3"

	"github.com/saluc28/petard/internal/zanzibar"
	registry "github.com/saluc28/petard/taxonomy-registry"
)

// fixtureValidation is the validation file of the vulnerable SpiceDB fixture.
var fixtureValidation = filepath.Join("..", "..", "..", "fixtures", "vulnerable-spicedb", "validation.yaml")

// The fixture holds two parameters the checks supply, the address of the
// caller and the time of the request, and two the relationships are meant to
// carry, the network and the date. EXPECTED.md says the same.
func TestFixture(t *testing.T) {
	f := findOne(t, fixtureValidation)
	matches := zanzibar.Run(f.Sample(time.Now()))

	var subjects []string
	for _, m := range matches {
		subjects = append(subjects, m.Subject)
		if m.PatternID != zanzibar.WriterSetParameterID || m.Verdict != zanzibar.Candidate {
			t.Errorf("%s: %s %s, want a candidate of %s", m.Subject, m.PatternID, m.Verdict, zanzibar.WriterSetParameterID)
		}
		for _, d := range m.Details {
			t.Logf("%s | %-12s %s (%s)", m.Subject, d.Label, d.Text, d.Position)
		}
	}
	want := []string{
		"document#editor, now of caveat not_expired",
		"document#viewer, user_ip of caveat ip_allowlist",
	}
	slices.Sort(subjects)
	if !slices.Equal(subjects, want) {
		t.Errorf("matches on %v, want %v", subjects, want)
	}
}

// zanzibarEntry is the part of a Zanzibar registry file the engine is held to:
// its fixture, and the cases of its declared false positives.
type zanzibarEntry struct {
	ID      string `yaml:"id"`
	Fixture struct {
		Validation string `yaml:"validation"`
	} `yaml:"fixture"`
	FalsePositives []struct {
		Condition string `yaml:"condition"`
		Case      *struct {
			Validation string `yaml:"validation"`
			Reports    bool   `yaml:"reports"`
		} `yaml:"case"`
	} `yaml:"false_positives"`
}

// reports says whether the pattern of id matches anything in a file.
func reports(t *testing.T, path, id string) bool {
	t.Helper()

	for _, m := range zanzibar.Run(findOne(t, path).Sample(time.Now())) {
		if m.PatternID == id {
			return true
		}
	}
	return false
}

// Every Zanzibar pattern finds its case in the fixture, and every declared false
// positive written as a case does what the registry says it does: reported
// when the file admits it still is, told apart when it says so.
func TestRegistryCases(t *testing.T) {
	files, err := fs.Glob(registry.Zanzibar, "*.yaml")
	if err != nil || len(files) == 0 {
		t.Fatalf("no Zanzibar pattern in the registry: %v", err)
	}
	for _, file := range files {
		t.Run(file, func(t *testing.T) {
			raw, err := fs.ReadFile(registry.Zanzibar, file)
			if err != nil {
				t.Fatal(err)
			}
			var entry zanzibarEntry
			if err := yaml.Unmarshal(raw, &entry); err != nil {
				t.Fatal(err)
			}

			fixture := filepath.Join("..", "..", "..", filepath.FromSlash(entry.Fixture.Validation))
			if !reports(t, fixture, entry.ID) {
				t.Errorf("%s is not found in its fixture, %s", entry.ID, entry.Fixture.Validation)
			}

			for _, fp := range entry.FalsePositives {
				if fp.Case == nil {
					continue
				}
				path := filepath.Join(t.TempDir(), "case.yaml")
				if err := os.WriteFile(path, []byte(fp.Case.Validation), 0o600); err != nil {
					t.Fatal(err)
				}
				if got := reports(t, path, entry.ID); got != fp.Case.Reports {
					t.Errorf("case of %q: reported %t, the registry says %t", fp.Condition, got, fp.Case.Reports)
				}
			}
		})
	}
}
