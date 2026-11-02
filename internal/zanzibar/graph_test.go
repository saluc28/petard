package zanzibar

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/saluc28/petard/internal/graph"
)

// bannable is a schema with an exclusion: access is a viewer who is not banned,
// so a coalition banned from a document it may view raises access by deleting
// the ban. It is the smallest schema that exercises the FAIL-OPEN category, and
// so the delete whose writer the closure leaves empty.
func bannable(t *testing.T) *Model {
	t.Helper()
	document := &Type{
		Name: "document",
		Relations: []*Relation{
			{Name: "viewer", Allowed: []Allowed{{Type: "user"}}},
			{Name: "banned", Allowed: []Allowed{{Type: "user"}}},
		},
		Permissions: []*Permission{
			{Name: "access", Expr: Exclusion{
				Base:       Computed{Name: "viewer"},
				Subtracted: []Expr{Computed{Name: "banned"}},
			}},
		},
	}
	m, err := NewModel([]*Type{{Name: "user"}, document}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestEscalationGraph(t *testing.T) {
	tests := []struct {
		name          string
		model         func(t *testing.T) *Model
		relationships []Relationship
		writes        []*WriteRule
		nodes         []string
		edges         []string
	}{
		{
			name:          "a self write and a gated editor",
			model:         documents,
			relationships: []Relationship{rel("document:roadmap", "owner", "user:olivia")},
			writes: []*WriteRule{
				{Resource: "document", Relation: "viewer", Operations: []Operation{Create}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Self: true}},
				{Resource: "document", Relation: "editor", Operations: []Operation{Create}, Gate: Gate{Holds: "view"}, Subject: SubjectSpec{Self: true}},
			},
			nodes: []string{
				"PTD_Principal user:attacker",
				"PTD_Resource document:roadmap",
				"PTD_Attribute document:roadmap#viewer",
				"PTD_Attribute document:roadmap#editor",
				"PTD_Principal user:olivia",
			},
			edges: []string{
				"PTD_WrittenBy document:roadmap#editor -> user:attacker map[]",
				"PTD_WrittenBy document:roadmap#viewer -> user:attacker map[]",
				"PTD_CanEscalateTo user:attacker -> document:roadmap map[patterns:[PTD-ZAN-007 PTD-ZAN-008] permissions:[edit view]]",
				"PTD_CanPerform user:olivia -> document:roadmap map[permissions:[edit view]]",
			},
		},
		{
			name:          "two categories raise one permission",
			model:         documents,
			relationships: []Relationship{rel("document:roadmap", "owner", "user:olivia")},
			writes: []*WriteRule{
				{Resource: "document", Relation: "viewer", Operations: []Operation{Create}, Gate: Gate{Anyone: true}, Wildcard: true},
				{Resource: "document", Relation: "viewer", Operations: []Operation{Create}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Self: true}},
			},
			nodes: []string{
				"PTD_Principal user:attacker",
				"PTD_Resource document:roadmap",
				"PTD_Attribute document:roadmap#viewer",
				"PTD_Principal user:olivia",
			},
			edges: []string{
				"PTD_WrittenBy document:roadmap#viewer -> user:attacker map[]",
				"PTD_CanEscalateTo user:attacker -> document:roadmap map[patterns:[PTD-ZAN-003 PTD-ZAN-008] permissions:[view]]",
				"PTD_CanPerform user:olivia -> document:roadmap map[permissions:[edit view]]",
			},
		},
		{
			name:  "a deny lifted by a delete writes as the banned subject",
			model: bannable,
			relationships: []Relationship{
				rel("document:roadmap", "viewer", "user:mallory"),
				rel("document:roadmap", "banned", "user:mallory"),
			},
			writes: []*WriteRule{
				{Resource: "document", Relation: "banned", Operations: []Operation{Delete}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Any: true}},
			},
			nodes: []string{
				"PTD_Principal user:mallory",
				"PTD_Resource document:roadmap",
				"PTD_Attribute document:roadmap#banned",
			},
			edges: []string{
				"PTD_WrittenBy document:roadmap#banned -> user:mallory map[]",
				"PTD_CanEscalateTo user:mallory -> document:roadmap map[patterns:[PTD-ZAN-002] permissions:[access]]",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Sample{
				Model:         tt.model(t),
				Relationships: tt.relationships,
				Now:           time.Unix(0, 0),
			}
			wm := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: tt.writes}

			g, err := EscalationGraph(s, wm)
			if err != nil {
				t.Fatalf("EscalationGraph: %v", err)
			}
			if got := nodeLines(g); !slices.Equal(got, tt.nodes) {
				t.Errorf("nodes:\n got %#v\nwant %#v", got, tt.nodes)
			}
			if got := edgeLines(g); !slices.Equal(got, tt.edges) {
				t.Errorf("edges:\n got %#v\nwant %#v", got, tt.edges)
			}

			// The export is diffed, so a second run over the same sample has to
			// build byte for byte the same graph.
			again, err := EscalationGraph(s, wm)
			if err != nil {
				t.Fatalf("EscalationGraph again: %v", err)
			}
			if !slices.Equal(nodeLines(again), nodeLines(g)) || !slices.Equal(edgeLines(again), edgeLines(g)) {
				t.Error("two runs over one sample built different graphs")
			}
		})
	}
}

// TestEscalationGraphEmpty checks that a sample with nothing to analyze yields
// an empty graph rather than an error, so an exporter can add it to a combined
// graph unconditionally.
func TestEscalationGraphEmpty(t *testing.T) {
	model := documents(t)
	wm := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: []*WriteRule{
		{Resource: "document", Relation: "viewer", Operations: []Operation{Create}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Self: true}},
	}}

	tests := []struct {
		name   string
		sample Sample
		wm     *WriteModel
	}{
		{"no write model", Sample{Model: model}, nil},
		{"no model", Sample{}, wm},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g, err := EscalationGraph(tt.sample, tt.wm)
			if err != nil {
				t.Fatalf("EscalationGraph: %v", err)
			}
			if n, e := len(g.Nodes()), len(g.Edges()); n != 0 || e != 0 {
				t.Errorf("want an empty graph, got %d nodes and %d edges", n, e)
			}
		})
	}
}

// AddEscalations builds several samples together, so a raise two validation
// files both reach is one edge naming its category once, not one edge per file.
func TestAddEscalationsMergesAcrossSamples(t *testing.T) {
	model := documents(t)
	wm := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: []*WriteRule{
		{Resource: "document", Relation: "viewer", Operations: []Operation{Create}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Self: true}},
	}}
	sample := Sample{
		Model:         model,
		Relationships: []Relationship{rel("document:roadmap", "owner", "user:olivia")},
		Now:           time.Unix(0, 0),
	}

	// The same sample twice stands for two validation files that both reach the
	// same raise.
	g := graph.New()
	if _, err := AddEscalations(g, []GraphInput{{Sample: sample, WriteModel: wm}, {Sample: sample, WriteModel: wm}}); err != nil {
		t.Fatalf("AddEscalations: %v", err)
	}

	wantNodes := []string{
		"PTD_Principal user:attacker",
		"PTD_Resource document:roadmap",
		"PTD_Attribute document:roadmap#viewer",
		"PTD_Principal user:olivia",
	}
	if got := nodeLines(g); !slices.Equal(got, wantNodes) {
		t.Errorf("nodes:\n got %#v\nwant %#v", got, wantNodes)
	}
	// One PTD_WrittenBy, and one PTD_CanEscalateTo whose patterns name the
	// category once rather than twice.
	wantEdges := []string{
		"PTD_WrittenBy document:roadmap#viewer -> user:attacker map[]",
		"PTD_CanEscalateTo user:attacker -> document:roadmap map[patterns:[PTD-ZAN-008] permissions:[view]]",
		"PTD_CanPerform user:olivia -> document:roadmap map[permissions:[edit view]]",
	}
	if got := edgeLines(g); !slices.Equal(got, wantEdges) {
		t.Errorf("edges:\n got %#v\nwant %#v", got, wantEdges)
	}
}

// BloodHound keeps one edge of a kind between two nodes, and merges the properties of
// the others over it, so a graph that held one edge per permission would lose all but
// the last of them. Whatever a graph holds, no two of its edges share a kind and two
// endpoints.
func TestNoTwoEdgesShareAKindAndTheirEndpoints(t *testing.T) {
	model := documents(t)
	wm := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: []*WriteRule{
		{Resource: "document", Relation: "viewer", Operations: []Operation{Create}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Any: true}, Wildcard: true},
		{Resource: "document", Relation: "editor", Operations: []Operation{Create}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Any: true}},
	}}
	sample := Sample{
		Model: model,
		Relationships: []Relationship{
			rel("document:roadmap", "owner", "user:olivia"),
			rel("document:plan", "viewer", "user:vic"),
		},
		Now: time.Unix(0, 0),
	}
	g, err := EscalationGraph(sample, wm)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, e := range g.Edges() {
		key := fmt.Sprintf("%s %s %s", e.Kind, e.From, e.To)
		if seen[key] {
			t.Errorf("two edges of %s", key)
		}
		seen[key] = true
	}
	if len(seen) == 0 {
		t.Fatal("the graph holds no edge")
	}
}

// An object a permission is raised on can also be a subject that raises something, a
// folder inside a folder, and the graph holds one node for it. It has to be a principal,
// since a resource starts no edge, and a graph that called it both would fail to build.
func TestAnObjectThatIsAlsoASubjectIsAPrincipal(t *testing.T) {
	folder := &Type{
		Name: "folder",
		Relations: []*Relation{
			{Name: "owner", Allowed: []Allowed{{Type: "folder"}, {Type: "user"}}},
			{Name: "viewer", Allowed: []Allowed{{Type: "folder"}, {Type: "user"}}},
		},
		Permissions: []*Permission{{Name: "view", Expr: Computed{Name: "viewer"}}, {Name: "own", Expr: Computed{Name: "owner"}}},
	}
	model, err := NewModel([]*Type{{Name: "user"}, folder}, nil)
	if err != nil {
		t.Fatal(err)
	}
	wm := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: []*WriteRule{
		{Resource: "folder", Relation: "viewer", Operations: []Operation{Create}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Self: true}},
	}}
	g, err := EscalationGraph(Sample{
		Model:         model,
		Relationships: []Relationship{rel("folder:a", "owner", "folder:b"), rel("folder:b", "viewer", "user:vic")},
		Now:           time.Unix(0, 0),
	}, wm)
	if err != nil {
		t.Fatalf("EscalationGraph: %v", err)
	}
	if !slices.Contains(nodeLines(g), "PTD_Principal folder:b") {
		t.Errorf("folder:b is both, and should be a principal: %v", nodeLines(g))
	}
}

// A node nobody names says so, and one the relationships name does not, so a query can
// keep what is true of this store apart from what is true of any account.
// Two witnesses can write one relation through two endpoints, and which one somebody has
// to close is the reason to read the edge. The graph holds both, for the export to fold.
func TestARelationWrittenThroughTwoEndpointsKeepsBoth(t *testing.T) {
	roadmap := Object{Type: "document", ID: "roadmap"}
	vic := Object{Type: "user", ID: "vic"}
	escalation := func(via string, subject Subject, permission string) attackerEscalation {
		write := WriteStep{
			Relationship: Relationship{Resource: roadmap, Relation: "viewer", Subject: subject},
			Rule:         &WriteRule{Resource: "document", Relation: "viewer", Via: via},
			Writer:       Subject{Object: vic},
		}
		return attackerEscalation{
			attacker:  vic,
			patternID: "PTD-ZAN-008",
			esc:       ClassifiedEscalation{Escalation: Escalation{Object: roadmap, Permission: permission, Writes: []WriteStep{write}}},
		}
	}
	g := graph.New()
	b := &escalationBuilder{
		g:      g,
		nodes:  map[string]*builderNode{},
		writes: map[string]*writeEdge{},
		raises: map[string]*principalEdge{},
		holds:  map[string]*principalEdge{},
	}
	b.add(escalation("POST /a", Subject{Object: vic}, "view"))
	b.add(escalation("POST /b", Subject{Object: Object{Type: "team", ID: "t"}, Relation: "member"}, "access"))
	b.add(escalation("POST /b", Subject{Object: vic}, "edit"))
	if err := b.flush(); err != nil {
		t.Fatal(err)
	}
	var vias []string
	for _, e := range g.Edges() {
		if e.Kind == graph.EdgeKindWrittenBy {
			vias = append(vias, e.Properties[graph.PropVia].(string))
		}
	}
	if want := []string{"POST /a", "POST /b"}; !slices.Equal(vias, want) {
		t.Errorf("the writes went through %v, want %v", vias, want)
	}
}

// A graph that stopped asking who holds what says so, for the export to report.
func TestTheGraphSaysWhatItDidNotAsk(t *testing.T) {
	inputs := []GraphInput{{Sample: Sample{
		Model: documents(t),
		Relationships: []Relationship{
			rel("document:a", "editor", "user:vic"),
			rel("document:b", "editor", "user:erin"),
			rel("document:c", "editor", "user:dana"),
		},
		Now: time.Unix(0, 0),
	}}}
	limits, err := addEscalations(graph.New(), inputs, 1)
	if err != nil {
		t.Fatal(err)
	}
	if limits.HoldingsLeftOut != 2 {
		t.Errorf("the graph says %d objects were left out, want 2", limits.HoldingsLeftOut)
	}
}

// A node met twice is what the two meetings together say, in either order: a principal if
// either made it one, and hypothetical only if nothing real ever named it.
func TestANodeMetTwiceIsWhatBothSay(t *testing.T) {
	type meeting struct {
		kind         graph.NodeKind
		hypothetical bool
	}
	tests := []struct {
		name         string
		first        meeting
		second       meeting
		kind         graph.NodeKind
		hypothetical bool
	}{
		{
			name:   "a resource that turns out a subject",
			first:  meeting{kind: graph.NodeKindResource},
			second: meeting{kind: graph.NodeKindPrincipal},
			kind:   graph.NodeKindPrincipal,
		},
		{
			name:   "a subject that turns out a resource",
			first:  meeting{kind: graph.NodeKindPrincipal},
			second: meeting{kind: graph.NodeKindResource},
			kind:   graph.NodeKindPrincipal,
		},
		{
			name:   "supposed and then named",
			first:  meeting{kind: graph.NodeKindResource, hypothetical: true},
			second: meeting{kind: graph.NodeKindResource},
			kind:   graph.NodeKindResource,
		},
		{
			name:   "named and then supposed",
			first:  meeting{kind: graph.NodeKindResource},
			second: meeting{kind: graph.NodeKindResource, hypothetical: true},
			kind:   graph.NodeKindResource,
		},
		{
			name:         "supposed both times",
			first:        meeting{kind: graph.NodeKindResource, hypothetical: true},
			second:       meeting{kind: graph.NodeKindResource, hypothetical: true},
			kind:         graph.NodeKindResource,
			hypothetical: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &escalationBuilder{nodes: map[string]*builderNode{}}
			b.node("n", tt.first.kind, tt.first.hypothetical)
			b.node("n", tt.second.kind, tt.second.hypothetical)
			if got := b.nodes["n"]; got.kind != tt.kind || got.hypothetical != tt.hypothetical {
				t.Errorf("node = %+v, want kind %s, hypothetical %v", got, tt.kind, tt.hypothetical)
			}
			if !slices.Equal(b.order, []string{"n"}) {
				t.Errorf("order = %v, want it once", b.order)
			}
		})
	}
}

func TestWhatTheAnalysisSupposesIsMarked(t *testing.T) {
	wm := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: []*WriteRule{
		{Resource: "document", Relation: "editor", Operations: []Operation{Create}, Gate: Gate{Holds: "view"}, Subject: SubjectSpec{Self: true}},
	}}
	tests := []struct {
		name          string
		relationships []Relationship
		expected      map[string]bool
	}{
		{
			name: "a state generated from the schema names nobody",
			expected: map[string]bool{
				"user:attacker":          true,
				"document:target":        true,
				"document:target#editor": true,
			},
		},
		{
			name:          "a real object is not credited with what the object of a position reaches",
			relationships: []Relationship{rel("document:target", "owner", "user:olivia")},
			expected: map[string]bool{
				"user:attacker":            true,
				"document:target-1":        true,
				"document:target-1#editor": true,
				"document:target":          false,
				"user:olivia":              false,
			},
		},
		{
			name:          "the relationships name their objects and subjects",
			relationships: []Relationship{rel("document:roadmap", "owner", "user:olivia")},
			expected: map[string]bool{
				"user:attacker":          true,
				"document:target":        true,
				"document:target#editor": true,
				"document:roadmap":       false,
				"user:olivia":            false,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g, err := EscalationGraph(Sample{Model: documents(t), Relationships: tt.relationships, Now: time.Unix(0, 0)}, wm)
			if err != nil {
				t.Fatal(err)
			}
			if len(g.Nodes()) != len(tt.expected) {
				t.Errorf("nodes = %v, want %d", nodeLines(g), len(tt.expected))
			}
			for _, n := range g.Nodes() {
				got, _ := n.Properties[graph.PropHypothetical].(bool)
				want, known := tt.expected[n.ID]
				if !known {
					t.Errorf("unexpected node %s", n.ID)
				}
				if got != want {
					t.Errorf("%s: hypothetical = %v, want %v", n.ID, got, want)
				}
			}
		})
	}
}

// nodeLines renders the graph's nodes as "<kind> <id>", in insertion order.
func nodeLines(g *graph.Graph) []string {
	var out []string
	for _, n := range g.Nodes() {
		out = append(out, fmt.Sprintf("%s %s", n.Kind, n.ID))
	}
	return out
}

// edgeLines renders the graph's edges as "<kind> <from> -> <to> <properties>",
// in insertion order. fmt prints a map with its keys sorted, so the properties
// render is stable.
func edgeLines(g *graph.Graph) []string {
	var out []string
	for _, e := range g.Edges() {
		out = append(out, fmt.Sprintf("%s %s -> %s %v", e.Kind, e.From, e.To, e.Properties))
	}
	return out
}
