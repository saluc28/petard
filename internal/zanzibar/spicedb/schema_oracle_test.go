package spicedb

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	yaml "go.yaml.in/yaml/v3"

	"github.com/saluc28/petard/internal/zanzibar"
)

// zedEnv names the zed binary the oracle runs, and corpusEnv a directory of
// validation files to hold against it besides testdata, such as the
// integration test configs of SpiceDB:
//
//	PETARD_ZED=zed PETARD_ZANZIBAR_CORPUS="$(go list -m -f '{{.Dir}}' github.com/authzed/spicedb)/internal/services/integrationtesting/testconfigs" go test ./internal/zanzibar/spicedb -run TestOracle
const (
	zedEnv    = "PETARD_ZED"
	corpusEnv = "PETARD_ZANZIBAR_CORPUS"
)

// unlistedID names an object no relationship mentions, so that every type has
// one object only a wildcard or nothing at all can grant to.
const unlistedID = "petard-unlisted"

// The engine against SpiceDB itself. For every validation file, every check
// the file's objects allow is answered by the engine and written as an
// assertion, and zed validate says whether SpiceDB gives the same answers.
// A check that cut a loop without granting is left out: SpiceDB fails it at
// its depth limit rather than answering.
func TestOracle(t *testing.T) {
	zed := os.Getenv(zedEnv)
	if zed == "" {
		t.Skipf("%s is not set: the oracle needs the zed binary", zedEnv)
	}

	paths, err := filepath.Glob(filepath.Join("testdata", "*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if corpus := os.Getenv(corpusEnv); corpus != "" {
		more, err := filepath.Glob(filepath.Join(corpus, "*.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		if len(more) == 0 {
			// A corpus that resolved to the wrong directory would otherwise
			// pass on testdata alone and look like a run over it.
			t.Fatalf("%s=%s holds no validation file", corpusEnv, corpus)
		}
		paths = append(paths, more...)
	}

	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			generated, count, skipped := oracleFile(t, path)
			out, err := exec.Command(zed, "validate", generated).CombinedOutput()
			if err != nil {
				t.Fatalf("zed validate disagrees on %d checks of %s: %v\n%s", count, path, err, tail(out))
			}
			t.Logf("SpiceDB agrees on %d checks, %d left out for a loop", count, skipped)
		})
	}
}

// oracleFile writes a validation file holding the schema and relationships of
// path and the engine's answer to every check, and returns it with the number
// of checks it asserts and the number it left out.
func oracleFile(t *testing.T, path string) (string, int, int) {
	t.Helper()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var v validationFile
	if err := yaml.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	schemaText := v.Schema.Value
	if v.SchemaFile != "" {
		named, err := os.ReadFile(filepath.Join(filepath.Dir(path), filepath.FromSlash(v.SchemaFile)))
		if err != nil {
			t.Fatal(err)
		}
		schemaText = string(named)
	}

	f := findOne(t, path)
	checker := zanzibar.NewChecker(f.Schema.Model, f.Relationships, f.Schema, time.Now())

	asserted := map[zanzibar.Level][]string{}
	count, skipped := 0, 0
	subjects := subjectsOf(f)
	for _, resource := range objectsOf(f) {
		typ := f.Schema.Model.Type(resource.Type)
		for _, name := range namesOf(typ) {
			for _, subject := range subjects {
				got, err := checker.Check(resource, name, subject)
				if err != nil {
					t.Fatalf("Check(%s#%s@%s) error = %v", resource, name, subject, err)
				}
				if got.Cycle && got.Level != zanzibar.Yes {
					skipped++
					continue
				}
				asserted[got.Level] = append(asserted[got.Level], fmt.Sprintf("%s#%s@%s", resource, name, subject))
				count++
			}
		}
	}

	out := map[string]any{
		"schema":        schemaText,
		"relationships": v.Relationships.Value,
		"assertions": map[string][]string{
			"assertTrue":     asserted[zanzibar.Yes],
			"assertFalse":    asserted[zanzibar.No],
			"assertCaveated": asserted[zanzibar.Conditional],
		},
	}
	encoded, err := yaml.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	generated := filepath.Join(t.TempDir(), "oracle.yaml")
	if err := os.WriteFile(generated, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	return generated, count, skipped
}

// objectsOf is every object the relationships of f mention, and one more per
// type that none of them mentions.
func objectsOf(f *File) []zanzibar.Object {
	seen := map[zanzibar.Object]bool{}
	var out []zanzibar.Object
	add := func(o zanzibar.Object) {
		if o.ID == zanzibar.WildcardID || seen[o] || f.Schema.Model.Type(o.Type) == nil {
			return
		}
		seen[o] = true
		out = append(out, o)
	}
	for _, r := range f.Relationships {
		add(r.Resource)
		add(r.Subject.Object)
	}
	for _, typ := range f.Schema.Model.Types {
		add(zanzibar.Object{Type: typ.Name, ID: unlistedID})
	}
	return out
}

// subjectsOf is every object that can be asked about as a subject: those of a
// type some relation allows as a subject, and, when a permission uses self,
// those of every type.
func subjectsOf(f *File) []zanzibar.Subject {
	allowed := map[string]bool{}
	for _, typ := range f.Schema.Model.Types {
		for _, r := range typ.Relations {
			for _, a := range r.Allowed {
				allowed[a.Type] = true
			}
		}
		for _, p := range typ.Permissions {
			if usesSelf(p.Expr) {
				for _, every := range f.Schema.Model.Types {
					allowed[every.Name] = true
				}
			}
		}
	}
	var out []zanzibar.Subject
	for _, o := range objectsOf(f) {
		if allowed[o.Type] {
			out = append(out, zanzibar.Subject{Object: o})
		}
	}
	return out
}

func usesSelf(expr zanzibar.Expr) bool {
	switch e := expr.(type) {
	case zanzibar.Self:
		return true
	case zanzibar.Union:
		return slices.ContainsFunc(e.Children, usesSelf)
	case zanzibar.Intersection:
		return slices.ContainsFunc(e.Children, usesSelf)
	case zanzibar.Exclusion:
		return usesSelf(e.Base) || slices.ContainsFunc(e.Subtracted, usesSelf)
	}
	return false
}

func namesOf(typ *zanzibar.Type) []string {
	var out []string
	for _, r := range typ.Relations {
		out = append(out, r.Name)
	}
	for _, p := range typ.Permissions {
		out = append(out, p.Name)
	}
	return out
}

// tail keeps the end of what zed printed, where it says which assertion
// failed.
func tail(out []byte) string {
	const keep = 4000
	s := strings.TrimSpace(string(out))
	if len(s) > keep {
		return "..." + s[len(s)-keep:]
	}
	return s
}
