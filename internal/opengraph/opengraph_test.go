package opengraph

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/saluc28/bhgraph"

	"github.com/saluc28/petard/internal/graph"
	"github.com/saluc28/petard/internal/identity"
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
// v9.9.2), and the UI falls back to a question mark for a kind it has no icon
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

// BloodHound keeps one edge of a kind between two nodes, so two edges the graph holds
// apart leave as one. The first speaks for it, the lists of all of them join, and what
// each of the others says differently stays together on a line of its own.
func TestPayloadFoldsEdgesBetweenTheSameNodes(t *testing.T) {
	g := graph.New()
	for _, node := range []graph.Node{
		{ID: "alice", Kind: graph.NodeKindPrincipal},
		{ID: "bob", Kind: graph.NodeKindPrincipal},
		{ID: "roadmap", Kind: graph.NodeKindResource},
	} {
		if err := g.AddNode(node); err != nil {
			t.Fatal(err)
		}
	}
	way := func(from string, kind graph.EdgeKind, line int, properties map[string]any) {
		t.Helper()
		if err := g.AddEdge(graph.Edge{Kind: kind, From: from, To: "roadmap", Source: graph.Source{File: "authz.rego", Line: line}, Properties: properties}); err != nil {
			t.Fatal(err)
		}
	}
	way("alice", graph.EdgeKindCanPerform, 10, map[string]any{graph.PropCondition: "owner", graph.PropPatterns: []string{"PTD-OPA-002"}})
	way("alice", graph.EdgeKindCanPerform, 20, map[string]any{graph.PropCondition: "department", graph.PropAction: "read", graph.PropPatterns: []string{"PTD-OPA-001"}})
	way("alice", graph.EdgeKindCanPerform, 20, map[string]any{graph.PropCondition: "department", graph.PropAction: "read", graph.PropPatterns: []string{"PTD-OPA-002"}})
	way("alice", graph.EdgeKindCanPerform, 10, map[string]any{graph.PropCondition: "owner"})
	way("bob", graph.EdgeKindCanPerform, 30, map[string]any{graph.PropCondition: "bob's"})
	way("alice", graph.EdgeKindCanEscalateTo, 40, map[string]any{graph.PropDecision: "allow"})

	payload := Payload(g)
	if len(payload.Edges) != 3 {
		t.Fatalf("edges = %d, want one for each kind and pair of nodes: %+v", len(payload.Edges), payload.Edges)
	}
	first := payload.Edges[0].Properties
	if first[graph.PropCondition] != "owner" || first[graph.PropSourceLine] != 10 {
		t.Errorf("the first way does not speak for the edge: %v", first)
	}
	if _, found := first[graph.PropAction]; found {
		t.Errorf("the action of the second way reads as the first's: %v", first)
	}
	if got, want := first[graph.PropAlso], []string{"action: read, condition: department, source_line: 20"}; !slices.Equal(got.([]string), want) {
		t.Errorf("also = %v, want %v", got, want)
	}
	if got, want := first[graph.PropPatterns], []string{"PTD-OPA-001", "PTD-OPA-002"}; !slices.Equal(got.([]string), want) {
		t.Errorf("patterns = %v, want %v", got, want)
	}
	for _, other := range payload.Edges[1:] {
		if _, found := other.Properties[graph.PropAlso]; found {
			t.Errorf("an edge on its own carries also: %v", other.Properties)
		}
	}
	if err := Validate(payload); err != nil {
		t.Errorf("Validate() = %v", err)
	}

	again, err := json.Marshal(Payload(g))
	if err != nil {
		t.Fatal(err)
	}
	once, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(once, again) {
		t.Errorf("building the payload twice gives two payloads, so the first changed the graph:\n%s\n%s", once, again)
	}
}

// A link goes out as a PTD_ActsAs from the node of the directory, matched by the
// property the identity map names, to the principal, and the payload it joins
// holds together against the schema: the kind of the start is one of the
// directory's, which no schema of Petard's declares, and it is not asked to.
func TestAddIdentitiesLinksTheDirectoryToThePrincipal(t *testing.T) {
	g := graph.New()
	if err := g.AddNode(graph.Node{ID: "user:s-1-5-21-1-1105", Kind: graph.NodeKindPrincipal}); err != nil {
		t.Fatal(err)
	}
	payload := Payload(g)
	link := identity.Link{
		Principal: "user:s-1-5-21-1-1105",
		Entry:     identity.Entry{Type: "user", Kind: "User", Property: "objectid"},
		ID:        "s-1-5-21-1-1105",
		Map:       `authz\identities.yaml`,
	}
	if err := AddIdentities(&payload, []identity.Link{link}); err != nil {
		t.Fatal(err)
	}
	payload.UppercaseIDs()

	if len(payload.Edges) != 1 {
		t.Fatalf("edges = %+v, want one", payload.Edges)
	}
	edge := payload.Edges[0]
	if edge.Kind != string(graph.EdgeKindActsAs) || edge.End.Value != "USER:S-1-5-21-1-1105" || edge.End.MatchBy != bhgraph.MatchByID {
		t.Errorf("edge = %+v, want a PTD_ActsAs to the principal", edge)
	}
	start := edge.Start
	if start.MatchBy != bhgraph.MatchByProperty || start.Kind != "User" || len(start.PropertyMatchers) != 1 ||
		start.PropertyMatchers[0].Key != "objectid" || start.PropertyMatchers[0].Value != "S-1-5-21-1-1105" {
		t.Errorf("start = %+v, want the User whose objectid is the subject's id, upper cased as BloodHound stores it", start)
	}
	if edge.Properties[graph.PropIdentityProperty] != "objectid" || edge.Properties[graph.PropIdentityMap] != "authz/identities.yaml" {
		t.Errorf("properties = %v, want the property matched and the map, with forward slashes", edge.Properties)
	}
	if err := Validate(payload); err != nil {
		t.Errorf("Validate() = %v", err)
	}
}

// BloodHound keeps a name upper cased, so a link matched by name is sent upper
// cased, and one matched by a property BloodHound keeps as it was ingested is sent
// as the subject's id has it.
func TestAddIdentitiesSendsANameUpperCased(t *testing.T) {
	cases := []struct {
		property, want string
	}{
		{"name", "DEV@PETARD.TEST"},
		{"userprincipalname", "dev@petard.test"},
	}
	for _, tc := range cases {
		t.Run(tc.property, func(t *testing.T) {
			var payload bhgraph.Graph
			link := identity.Link{
				Principal: "user:dev@petard.test",
				Entry:     identity.Entry{Type: "user", Kind: "User", Property: tc.property},
				ID:        "dev@petard.test",
			}
			if err := AddIdentities(&payload, []identity.Link{link}); err != nil {
				t.Fatal(err)
			}
			payload.UppercaseIDs()
			if got := payload.Edges[0].Start.PropertyMatchers[0].Value; got != tc.want {
				t.Errorf("value = %v, want %s", got, tc.want)
			}
		})
	}
}

// A payload with a source kind would give it to the node of the directory each
// link reaches, and deleting that source would delete the user with it, so the
// links are refused rather than sent there.
func TestAddIdentitiesRefusesAPayloadWithASourceKind(t *testing.T) {
	payload := bhgraph.Graph{SourceKind: "PTD"}
	link := identity.Link{Principal: "user:a", Entry: identity.Entry{Type: "user", Kind: "User", Property: "objectid"}, ID: "a"}
	if err := AddIdentities(&payload, []identity.Link{link}); err == nil || len(payload.Edges) != 0 {
		t.Errorf("AddIdentities() = %v with %d edges, want a refusal and no edge", err, len(payload.Edges))
	}
	if err := AddIdentities(&payload, nil); err != nil {
		t.Errorf("no link to add: AddIdentities() = %v, want nothing to refuse", err)
	}
}
