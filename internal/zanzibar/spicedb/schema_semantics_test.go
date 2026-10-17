package spicedb

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	yaml "go.yaml.in/yaml/v3"

	"github.com/saluc28/petard/internal/zanzibar"
)

// assertion is one check a validation file asserts, with the level it asserts.
type assertion struct {
	resource zanzibar.Object
	name     string
	subject  zanzibar.Subject
	want     zanzibar.Level
	text     string
}

// readAssertions reads the assertions of a validation file. One that supplies
// context with the check, written "... with {...}", is left out: the engine
// does not take check time context yet.
func readAssertions(t *testing.T, path string) []assertion {
	t.Helper()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var v validationFile
	if err := yaml.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	var out []assertion
	for level, texts := range map[zanzibar.Level][]string{
		zanzibar.Yes:         v.Assertions.True,
		zanzibar.No:          v.Assertions.False,
		zanzibar.Conditional: v.Assertions.Caveated,
	} {
		for _, text := range texts {
			if strings.Contains(text, " with ") {
				continue
			}
			parsed, err := ParseRelationships(path, 1, text)
			if err != nil || len(parsed) != 1 {
				t.Fatalf("assertion %q: %v", text, err)
			}
			out = append(out, assertion{
				resource: parsed[0].Resource,
				name:     parsed[0].Relation,
				subject:  parsed[0].Subject,
				want:     level,
				text:     text,
			})
		}
	}
	return out
}

// The engine has to give every answer the validation files of testdata
// assert. zed validate holds the same files against SpiceDB in TestOracle.
func TestAssertions(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("testdata", "*.yaml"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("no testdata: %v", err)
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			f := findOne(t, path)
			checker := zanzibar.NewChecker(f.Schema.Model, f.Relationships, f.Schema, time.Now())
			for _, a := range readAssertions(t, path) {
				got, err := checker.Check(a.resource, a.name, a.subject)
				if err != nil {
					t.Errorf("%s: %v", a.text, err)
					continue
				}
				if got.Level != a.want {
					t.Errorf("%s = %s, want %s", a.text, got.Level, a.want)
				}
			}
		})
	}
}
