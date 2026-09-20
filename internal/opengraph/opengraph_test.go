package opengraph

import (
	"flag"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/saluc28/bhgraph"

	"github.com/saluc28/petard/internal/graph"
)

// A kind the model declares and the schema does not describe produces nodes
// BloodHound cannot classify, and the mistake shows up in somebody's browser
// rather than here. This is the test that keeps the two from drifting.
//
// Validate also holds every kind name to the rule BloodHound applies when the
// schema is installed: the namespace, then an underscore, then a name.
func TestSchemaDescribesEveryKindOfTheModel(t *testing.T) {
	schema := Schema()

	if err := schema.Validate(); err != nil {
		t.Fatalf("Schema() does not hold together: %v", err)
	}

	var declared []string
	for _, kind := range schema.NodeKinds {
		declared = append(declared, kind.Name)
		if kind.Icon == "" || kind.Color == "" || kind.Description == "" {
			t.Errorf("the node kind %s is not drawn: icon %q, color %q", kind.Name, kind.Icon, kind.Color)
		}
	}
	for _, kind := range graph.NodeKinds() {
		if !slices.Contains(declared, string(kind)) {
			t.Errorf("the model declares %s and the schema does not", kind)
		}
	}

	declared = nil
	for _, kind := range schema.RelationshipKinds {
		declared = append(declared, kind.Name)
		if kind.Description == "" {
			t.Errorf("the relationship kind %s says nothing about what it means", kind.Name)
		}
	}
	for _, kind := range graph.EdgeKinds() {
		if !slices.Contains(declared, string(kind)) {
			t.Errorf("the model declares %s and the schema does not", kind)
		}
	}
}

// The server registers an icon only for a kind declared a display kind
// (upsertCustomIcons in cmd/api/src/database/upsert_schema_extension.go at
// v9.7.1), and the UI falls back to a question mark for a kind it has no icon
// for (GetIconInfo in packages/javascript/bh-shared-ui/src/utils/icons.ts). A
// kind given an icon here and not declared a display kind is a question mark in
// the browser.
func TestEveryKindIsDrawnAndDeclaredADisplayKind(t *testing.T) {
	for _, kind := range Schema().NodeKinds {
		if !kind.IsDisplayKind {
			t.Errorf("%s is not a display kind, so BloodHound draws it as a question mark", kind.Name)
		}
		if kind.Icon == "" || kind.Color == "" {
			t.Errorf("%s has icon %q and color %q", kind.Name, kind.Icon, kind.Color)
		}
	}
}

// Traversability is the whole difference between a graph the UI walks and one
// it only displays, and it is decided in the model. The schema has to carry the
// same answer, not a second opinion.
func TestSchemaTakesTraversabilityFromTheModel(t *testing.T) {
	traversable := Schema().TraversableKinds()
	slices.Sort(traversable)

	var expected []string
	for _, kind := range graph.EdgeKinds() {
		if kind.IsTraversable() {
			expected = append(expected, string(kind))
		}
	}
	slices.Sort(expected)

	if !slices.Equal(traversable, expected) {
		t.Errorf("traversable kinds = %v, want %v", traversable, expected)
	}
}

// The provenance of an edge is a field of its own inside Petard so that nothing
// overwrites it by accident, and a property on the wire because that is all the
// payload has.
func TestPayloadMergesProvenanceIntoProperties(t *testing.T) {
	g := graph.New()
	for _, node := range []graph.Node{
		{ID: "data.t.allow", Kind: graph.NodeKindRule},
		{ID: "data.users[_].roles", Kind: graph.NodeKindAttribute},
	} {
		if err := g.AddNode(node); err != nil {
			t.Fatalf("AddNode() error = %v", err)
		}
	}
	if err := g.AddEdge(graph.Edge{
		Kind:       graph.EdgeKindReads,
		From:       "data.t.allow",
		To:         "data.users[_].roles",
		Source:     graph.Source{File: "authz.rego", Line: 26, Rule: "data.t.allow"},
		Properties: map[string]any{graph.PropProvenance: "input"},
	}); err != nil {
		t.Fatalf("AddEdge() error = %v", err)
	}

	payload := Payload(g)
	if len(payload.Edges) != 1 {
		t.Fatalf("edges = %d, want 1", len(payload.Edges))
	}

	properties := payload.Edges[0].Properties
	for key, expected := range map[string]any{
		graph.PropSourceFile: "authz.rego",
		graph.PropSourceLine: 26,
		graph.PropSourceRule: "data.t.allow",
		graph.PropProvenance: "input",
	} {
		if properties[key] != expected {
			t.Errorf("property %s = %v, want %v", key, properties[key], expected)
		}
	}

	if got := payload.Edges[0].Start.Value; got != "data.t.allow" {
		t.Errorf("start = %q, want the node id", got)
	}
	if err := Validate(payload); err != nil {
		t.Errorf("Validate() error = %v", err)
	}
}

// An edge pointing at a node nobody emitted is accepted by the ingest endpoint
// and then quietly produces nothing, which is the slowest possible way to find
// a mistake. Catching it here is the reason to validate before sending.
func TestValidateRefusesAPayloadThatDoesNotHoldTogether(t *testing.T) {
	g := graph.New()
	if err := g.AddNode(graph.Node{ID: "mallory", Kind: graph.NodeKindPrincipal}); err != nil {
		t.Fatalf("AddNode() error = %v", err)
	}

	payload := Payload(g)
	payload.AddEdge(bhgraph.Edge{
		Kind:  string(graph.EdgeKindCanEscalateTo),
		Start: bhgraph.NodeRef("dave"),
		End:   bhgraph.NodeRef("mallory"),
	})

	if err := Validate(payload); err == nil {
		t.Error("a payload with an edge out of a node nobody emitted was accepted")
	}
}

// The committed schema and the one the model produces have to be the same file.
// Run with -update to rewrite it after a deliberate change, and read the diff
// before you do: these names are a contract with data already ingested.
var update = flag.Bool("update", false, "rewrite schema/petard.json from the model")

func TestCommittedSchemaMatchesTheModel(t *testing.T) {
	path := filepath.Join("..", "..", "schema", SchemaFile)

	generated, err := MarshalSchema()
	if err != nil {
		t.Fatalf("MarshalSchema() error = %v", err)
	}

	if *update {
		if err := os.WriteFile(path, generated, 0o600); err != nil {
			t.Fatalf("writing %s: %v", path, err)
		}
		t.Logf("rewrote %s", path)
		return
	}

	committed, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v (run the test with -update to create it)", path, err)
	}
	if string(committed) != string(generated) {
		t.Errorf("%s is not what the model produces; run go test ./internal/opengraph -update and read the diff", path)
	}
}
