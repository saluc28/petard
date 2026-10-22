package spicedb

import (
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	yaml "go.yaml.in/yaml/v3"

	"github.com/saluc28/petard/internal/graph"
	"github.com/saluc28/petard/internal/zanzibar"
	registry "github.com/saluc28/petard/taxonomy-registry"
)

// fixtureValidation is the validation file of the vulnerable SpiceDB fixture.
var fixtureValidation = filepath.Join("..", "..", "..", "fixtures", "vulnerable-spicedb", "validation.yaml")

// The fixture holds two parameters the checks supply, the address of the
// caller and the time of the request, and two the relationships are meant to
// carry, the network and the date. With the write model they are findings,
// since who writes the relation and that the parameter is the check's are
// declared; without it they are the same two matches as candidates. EXPECTED.md
// says the same.
func TestFixture(t *testing.T) {
	sample := findOne(t, fixtureValidation).Sample(time.Now())
	want := []string{
		"document#editor, now of caveat not_expired",
		"document#viewer, user_ip of caveat ip_allowlist",
	}

	wm, err := zanzibar.LoadWriteModel(fixtureWrites)
	if err != nil {
		t.Fatalf("LoadWriteModel: %v", err)
	}
	assertMatches(t, zanzibar.Run(sample, wm), zanzibar.Finding, want)
	assertMatches(t, zanzibar.Run(sample, nil), zanzibar.Candidate, want)
}

// assertMatches checks that the PTD-ZAN-001 matches are the ones expected, each
// with the given verdict. A run with a write model also emits the escalation
// findings of the other patterns; those are checked elsewhere, so this looks at
// the self-asserted exemption alone.
func assertMatches(t *testing.T, matches []zanzibar.Match, verdict zanzibar.Verdict, want []string) {
	t.Helper()
	var subjects []string
	for _, m := range matches {
		if m.PatternID != zanzibar.SelfAssertedExemptionID {
			continue
		}
		subjects = append(subjects, m.Subject)
		if m.Verdict != verdict {
			t.Errorf("%s: %s %s, want a %s", m.Subject, m.PatternID, m.Verdict, verdict)
		}
	}
	slices.Sort(subjects)
	if !slices.Equal(subjects, want) {
		t.Errorf("%s matches on %v, want %v", verdict, subjects, want)
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

// reports says whether the pattern of id matches anything in a file. It loads a
// write model sitting beside the file, as an analysis does, so the patterns that
// rest on who writes a relation, the escalation categories, are found where the
// caveat candidate of PTD-ZAN-001 needs none.
func reports(t *testing.T, path, id string) bool {
	t.Helper()

	var wm *zanzibar.WriteModel
	writes := filepath.Join(filepath.Dir(path), "writes.yaml")
	if _, err := os.Stat(writes); err == nil {
		loaded, err := zanzibar.LoadWriteModel(writes)
		if err != nil {
			t.Fatalf("LoadWriteModel %s: %v", writes, err)
		}
		wm = loaded
	}
	for _, m := range zanzibar.Run(findOne(t, path).Sample(time.Now()), wm) {
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

// The registry says where each pattern leaves its id in the exported graph, and
// the saved queries rest on that. So it is held against the engine: on the
// fixture, the kinds a pattern marks are the ones its file declares, and a
// pattern that declares none leaves none, as the caveat finding does, drawing no
// edge.
func TestRegistryMarksAreWhereTheEngineLeavesThem(t *testing.T) {
	wm, err := zanzibar.LoadWriteModel(fixtureWrites)
	if err != nil {
		t.Fatalf("LoadWriteModel: %v", err)
	}
	g, err := zanzibar.EscalationGraph(findOne(t, fixtureValidation).Sample(time.Now()), wm)
	if err != nil {
		t.Fatalf("EscalationGraph: %v", err)
	}

	// marked holds, per pattern and per kind, the properties of every element
	// the pattern left its id on.
	marked := map[string]map[string][]map[string]any{}
	note := func(kind string, properties map[string]any) {
		ids, _ := properties[graph.PropPatterns].([]string)
		for _, id := range ids {
			if marked[id] == nil {
				marked[id] = map[string][]map[string]any{}
			}
			marked[id][kind] = append(marked[id][kind], properties)
		}
	}
	for _, node := range g.Nodes() {
		note(string(node.Kind), node.Properties)
	}
	for _, edge := range g.Edges() {
		note(string(edge.Kind), edge.Properties)
	}

	files, err := fs.Glob(registry.Zanzibar, "*.yaml")
	if err != nil || len(files) == 0 {
		t.Fatalf("no Zanzibar pattern in the registry: %v", err)
	}
	for _, file := range files {
		raw, err := fs.ReadFile(registry.Zanzibar, file)
		if err != nil {
			t.Fatal(err)
		}
		var entry struct {
			ID    string `yaml:"id"`
			Graph struct {
				Marks []struct {
					Kind       string   `yaml:"kind"`
					Properties []string `yaml:"properties"`
				} `yaml:"marks"`
			} `yaml:"graph"`
		}
		if err := yaml.Unmarshal(raw, &entry); err != nil {
			t.Fatal(err)
		}

		t.Run(entry.ID, func(t *testing.T) {
			declared := map[string][]string{}
			for _, mark := range entry.Graph.Marks {
				declared[mark.Kind] = mark.Properties
			}
			kinds := slices.Sorted(maps.Keys(marked[entry.ID]))
			if expected := slices.Sorted(maps.Keys(declared)); !slices.Equal(kinds, expected) {
				t.Fatalf("the engine marks %v on the fixture, the file declares %v", kinds, expected)
			}
			for kind, properties := range declared {
				for _, property := range properties {
					if !slices.ContainsFunc(marked[entry.ID][kind], func(held map[string]any) bool {
						_, found := held[property]
						return found
					}) {
						t.Errorf("no %s the pattern marks carries %q", kind, property)
					}
				}
			}
		})
	}
}
