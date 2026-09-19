package queries

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/saluc28/petard/internal/graph"
	"github.com/saluc28/petard/internal/taxonomy"
)

var update = flag.Bool("update", false, "rewrite queries.json from the query files")

// The list queries.specterops.io reads is the same set as the files, and a
// change to one without the other would leave two libraries that disagree.
func TestCommittedLibraryMatchesTheFiles(t *testing.T) {
	all, err := All()
	if err != nil {
		t.Fatalf("All() error = %v", err)
	}
	// Without escaping, an arrow in a query reads as an arrow.
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(all); err != nil {
		t.Fatal(err)
	}
	generated := buffer.Bytes()

	if *update {
		if err := os.WriteFile(LibraryFile, generated, 0o600); err != nil {
			t.Fatalf("writing %s: %v", LibraryFile, err)
		}
		t.Logf("rewrote %s", LibraryFile)
		return
	}
	committed, err := os.ReadFile(LibraryFile)
	if err != nil {
		t.Fatalf("reading %s: %v (run the test with -update to create it)", LibraryFile, err)
	}
	if string(committed) != string(generated) {
		t.Errorf("%s is not what the query files produce; run go test ./queries -update and read the diff", LibraryFile)
	}
}

var guid = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// Every query carries what the library asks of one, under a name and a guid of
// its own, and belongs either to Petard as a whole or to a pattern the registry
// holds, under that pattern's category and with a link to its file.
func TestEveryQueryIsComplete(t *testing.T) {
	all, err := All()
	if err != nil {
		t.Fatalf("All() error = %v", err)
	}
	patterns, err := taxonomy.LoadRegistry(filepath.Join("..", "taxonomy-registry", "opa"))
	if err != nil {
		t.Fatalf("LoadRegistry() error = %v", err)
	}
	byID := map[string]taxonomy.Pattern{}
	for _, pattern := range patterns {
		byID[pattern.ID] = pattern
	}

	names, guids, perPattern := map[string]bool{}, map[string]bool{}, map[string]int{}
	for _, query := range all {
		t.Run(query.Name, func(t *testing.T) {
			if names[query.Name] || guids[query.GUID] {
				t.Errorf("name or guid used twice")
			}
			names[query.Name], guids[query.GUID] = true, true
			if !guid.MatchString(query.GUID) {
				t.Errorf("guid %q is not a version 4 uuid", query.GUID)
			}
			if query.Prebuilt || query.Revision < 1 || query.Description == "" || query.Query == "" {
				t.Errorf("prebuilt, revision, description or query is not what the library asks for")
			}
			if !slices.Equal(query.Platforms, []string{"Open Policy Agent"}) || len(query.Resources) != 1 {
				t.Errorf("platforms = %v, resources = %v", query.Platforms, query.Resources)
			}

			id, _, found := strings.Cut(query.Name, ": ")
			if !found {
				t.Fatalf("the name does not say what it belongs to")
			}
			if id == "Petard" {
				if query.Category != "Petard" {
					t.Errorf("category = %q, want Petard", query.Category)
				}
				return
			}
			pattern, known := byID[id]
			if !known {
				t.Fatalf("%s is not a pattern of the registry", id)
			}
			perPattern[id]++
			if query.Category != pattern.Category.Title {
				t.Errorf("category = %q, want the registry's %q", query.Category, pattern.Category.Title)
			}
			if !strings.HasSuffix(query.Resources[0], "/taxonomy-registry/opa/"+id+"-"+pattern.Name+".yaml") {
				t.Errorf("resource %q is not the file of %s", query.Resources[0], id)
			}
		})
	}
	for _, pattern := range patterns {
		if perPattern[pattern.ID] < 3 {
			t.Errorf("%s has %d queries, and every pattern gets at least three", pattern.ID, perPattern[pattern.ID])
		}
	}
}

var (
	label    = regexp.MustCompile(`:(PTD_[A-Za-z]+)`)
	property = regexp.MustCompile(`\b[a-z]\.([a-z_]+)\b`)
)

// A query that names a kind or a property the graph does not have finds
// nothing, and an empty result reads as a clean policy. So every label and
// every property a query uses has to be one the model declares.
func TestQueriesAskForWhatTheGraphHolds(t *testing.T) {
	all, err := All()
	if err != nil {
		t.Fatalf("All() error = %v", err)
	}

	kinds := map[string]bool{}
	for _, kind := range graph.NodeKinds() {
		kinds[string(kind)] = true
	}
	for _, kind := range graph.EdgeKinds() {
		kinds[string(kind)] = true
	}
	properties := map[string]bool{}
	for _, key := range []string{
		graph.PropSourceFile, graph.PropSourceLine, graph.PropSourceRule, graph.PropName,
		graph.PropIsDecision, graph.PropRef, graph.PropProvenance, graph.PropProvenanceTerm,
		graph.PropProvenanceOrigin, graph.PropUnderNegation, graph.PropConfidence,
		graph.PropDecision, graph.PropCondition, graph.PropAction, graph.PropVia,
		graph.PropViaWritePath, graph.PropAuthorizedBy, graph.PropValue,
		graph.PropWriteConfidence, graph.PropUncoveredKeys, graph.PropKeysChecked,
		graph.PropEnforcingSide, graph.PropReachTransitive, graph.PropReachDirect,
		graph.PropRelation, graph.PropPatterns, graph.PropCandidatePatterns,
		graph.PropPositions, graph.PropEmptyDomains, graph.PropMitigation,
	} {
		properties[key] = true
	}

	for _, query := range all {
		for _, match := range label.FindAllStringSubmatch(query.Query, -1) {
			if !kinds[match[1]] {
				t.Errorf("%s: %s is not a kind of the model", query.Name, match[1])
			}
		}
		for _, match := range property.FindAllStringSubmatch(query.Query, -1) {
			if !properties[match[1]] {
				t.Errorf("%s: %s is not a property of the model", query.Name, match[1])
			}
		}
	}
}
