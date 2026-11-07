package spicedb

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	yaml "go.yaml.in/yaml/v3"

	"github.com/saluc28/petard/internal/zanzibar"
	"github.com/saluc28/petard/internal/zanzibar/zanzibartest"
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

// The engine against SpiceDB itself. For every validation file, those of
// testdata, the SpiceDB fixture the demo carries and the corpus, every check
// the file's objects allow is answered by the engine and written as an
// assertion, and zed validate says whether SpiceDB gives the same answers. The
// subjects are the objects and the usersets the schema allows, and each check
// is asked with no context and with every context the file's own assertions
// supply. A check that cut a loop without granting is left out: SpiceDB fails
// it at its depth limit rather than answering.
func TestOracle(t *testing.T) {
	zed := os.Getenv(zedEnv)
	if zed == "" {
		t.Skipf("%s is not set: the oracle needs the zed binary", zedEnv)
	}

	paths, err := filepath.Glob(filepath.Join("testdata", "*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	paths = append(paths, fixtureValidation, agentSwarmValidation)
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
	objects := zanzibartest.Objects(f.Schema.Model, f.Relationships)
	subjects := zanzibartest.Subjects(f.Schema.Model, f.Relationships)
	for _, context := range contextsOf(t, f) {
		for _, resource := range objects {
			typ := f.Schema.Model.Type(resource.Type)
			for _, name := range zanzibartest.Names(typ) {
				for _, subject := range subjects {
					check := zanzibar.Assertion{Resource: resource, Name: name, Subject: subject, Context: context}
					got, err := checker.Check(resource, name, subject, context)
					if err != nil {
						t.Fatalf("Check(%s) error = %v", check, err)
					}
					if got.Cycle && got.Level != zanzibar.Yes {
						skipped++
						continue
					}
					asserted[got.Level] = append(asserted[got.Level], check.String())
					count++
				}
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

// contextsOf is no context, then every distinct context the file's
// assertions supply.
func contextsOf(t *testing.T, f *File) []map[string]any {
	t.Helper()

	out := []map[string]any{nil}
	seen := map[string]bool{}
	for _, a := range f.Assertions {
		if a.Context == nil {
			continue
		}
		key, err := json.Marshal(a.Context)
		if err != nil {
			t.Fatal(err)
		}
		if !seen[string(key)] {
			seen[string(key)] = true
			out = append(out, a.Context)
		}
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
