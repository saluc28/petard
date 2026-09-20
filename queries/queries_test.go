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
	// Two is the floor rather than a target. How many questions a pattern
	// affords depends on what it marks: one that marks a rule and nothing
	// around it has fewer than one that marks a read, and a third query
	// written to reach a quota is one that returns nothing.
	for _, pattern := range patterns {
		if perPattern[pattern.ID] < 2 {
			t.Errorf("%s has %d queries, and every pattern gets at least two", pattern.ID, perPattern[pattern.ID])
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

// unwoundProperty finds UNWIND applied to a property rather than to a list
// written in the query.
var unwoundProperty = regexp.MustCompile(`(?i)UNWIND\s+[a-z][a-z0-9_]*\.`)

// On the PostgreSQL backend, UNWIND over a property fails the whole query:
// dawgs hands the expression to unnest() as it is (cypher/models/pgsql/
// translate/unwind.go at v0.8.1), a property arrives as text, and PostgreSQL
// has no unnest(text). A list is returned whole instead, as one column.
func TestNoQueryUnwindsAProperty(t *testing.T) {
	all, err := All()
	if err != nil {
		t.Fatalf("All() error = %v", err)
	}
	for _, query := range all {
		if found := unwoundProperty.FindString(query.Query); found != "" {
			t.Errorf("%s unwinds a property (%s), which the PostgreSQL backend cannot run",
				query.Name, strings.TrimSpace(found))
		}
	}
}

var (
	returned   = regexp.MustCompile(`(?s)RETURN\s+(.*)$`)
	identifier = regexp.MustCompile(`^[a-z][a-zA-Z0-9_]*$`)
)

// The Explore view shows a graph and nothing else: it treats an answer with no
// nodes and no edges as no answer at all, whatever else came back
// (packages/javascript/bh-shared-ui/src/hooks/useExploreGraph/queries/
// cypherSearch.ts at v9.7.1). A query that returns columns is answered by the
// API and reported to the analyst as "No results match your criteria", which
// reads as a clean policy. What a finding says in words is on the entity, in
// its Entity Panel, and a query is there to put that entity on the screen.
func TestEveryQueryReturnsAGraph(t *testing.T) {
	all, err := All()
	if err != nil {
		t.Fatalf("All() error = %v", err)
	}
	for _, query := range all {
		match := returned.FindStringSubmatch(query.Query)
		if match == nil {
			t.Errorf("%s returns nothing", query.Name)
			continue
		}
		for _, term := range strings.Split(match[1], ",") {
			if term = strings.TrimSpace(term); !identifier.MatchString(term) {
				t.Errorf("%s returns %q rather than a node, a relationship or a path",
					query.Name, term)
			}
		}
	}
}

// comparedName finds a literal compared against the two properties BloodHound
// rewrites.
var comparedName = regexp.MustCompile(`\.(name|objectid)\s*(?:=|=~|STARTS WITH|ENDS WITH|CONTAINS)\s*'([^']*)'`)

// Ingest upper-cases name and objectid unless the use_raw_object_id feature
// flag is on, and that flag ships disabled and not user updatable
// (cmd/api/src/services/graphify/ingestnodes.go and the migration
// 20260710120000_v9_add_use_raw_object_id_flag_bed_8954.sql at v9.7.1). A query
// that compares either against a lower case literal matches nothing, which
// reads like a clean policy. BloodHound's own prebuilt queries write the
// literal in upper case for the same reason.
func TestQueriesCompareNamesInUpperCase(t *testing.T) {
	all, err := All()
	if err != nil {
		t.Fatalf("All() error = %v", err)
	}
	for _, query := range all {
		for _, match := range comparedName.FindAllStringSubmatch(query.Query, -1) {
			if match[2] != strings.ToUpper(match[2]) {
				t.Errorf("%s compares %s against %q, and ingest stores it upper case",
					query.Name, match[1], match[2])
			}
		}
	}
}
