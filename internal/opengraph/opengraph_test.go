package opengraph

import (
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/saluc28/bhgraph"

	"github.com/saluc28/petard/internal/graph"
)

// A kind the model declares and the schema does not describe produces nodes
// BloodHound cannot classify, and the mistake shows up in somebody's browser
// rather than here. This is the test that keeps the two from drifting.
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

// BloodHound refuses an extension unless every kind name starts with the
// declared namespace followed by an underscore, and it adds that underscore
// itself (cmd/api/src/model/graphschema.go:508 at v9.7.0). bhgraph only checks
// that the name starts with the namespace, so a namespace of "PTD_" passes it
// and fails on the server. This test holds the schema to the server's rule, not
// to the looser one.
func TestSchemaKindsCarryTheNamespaceTheWayTheServerReadsIt(t *testing.T) {
	schema := Schema()

	ns := schema.Schema.Namespace
	if ns == "" || ns[len(ns)-1] == '_' {
		t.Fatalf("namespace = %q: the server appends the underscore, so the declared one must not end with it", ns)
	}

	prefix := ns + "_"
	var names []string
	for _, kind := range schema.NodeKinds {
		names = append(names, kind.Name)
	}
	for _, kind := range schema.RelationshipKinds {
		names = append(names, kind.Name)
	}
	for _, name := range names {
		rest, found := strings.CutPrefix(name, prefix)
		if !found || strings.TrimSpace(rest) == "" {
			t.Errorf("kind %q does not start with %q followed by a name, and the server would refuse the schema", name, prefix)
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
