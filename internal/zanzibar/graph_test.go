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
			},
			edges: []string{
				"PTD_WrittenBy document:roadmap#editor -> user:attacker map[]",
				"PTD_WrittenBy document:roadmap#viewer -> user:attacker map[]",
				"PTD_CanEscalateTo user:attacker -> document:roadmap map[patterns:[PTD-ZAN-007] permission:edit]",
				"PTD_CanEscalateTo user:attacker -> document:roadmap map[patterns:[PTD-ZAN-008] permission:view]",
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
			},
			edges: []string{
				"PTD_WrittenBy document:roadmap#viewer -> user:attacker map[]",
				"PTD_CanEscalateTo user:attacker -> document:roadmap map[patterns:[PTD-ZAN-003 PTD-ZAN-008] permission:view]",
			},
		},
		{
			name:  "a deny lifted by a delete writes as the attacker",
			model: bannable,
			relationships: []Relationship{
				rel("document:roadmap", "viewer", "user:attacker"),
				rel("document:roadmap", "banned", "user:attacker"),
			},
			writes: []*WriteRule{
				{Resource: "document", Relation: "banned", Operations: []Operation{Delete}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Any: true}},
			},
			nodes: []string{
				"PTD_Principal user:attacker",
				"PTD_Resource document:roadmap",
				"PTD_Attribute document:roadmap#banned",
			},
			edges: []string{
				"PTD_WrittenBy document:roadmap#banned -> user:attacker map[]",
				"PTD_CanEscalateTo user:attacker -> document:roadmap map[patterns:[PTD-ZAN-002] permission:access]",
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
	if err := AddEscalations(g, []GraphInput{{Sample: sample, WriteModel: wm}, {Sample: sample, WriteModel: wm}}); err != nil {
		t.Fatalf("AddEscalations: %v", err)
	}

	wantNodes := []string{
		"PTD_Principal user:attacker",
		"PTD_Resource document:roadmap",
		"PTD_Attribute document:roadmap#viewer",
	}
	if got := nodeLines(g); !slices.Equal(got, wantNodes) {
		t.Errorf("nodes:\n got %#v\nwant %#v", got, wantNodes)
	}
	// One PTD_WrittenBy, and one PTD_CanEscalateTo whose patterns name the
	// category once rather than twice.
	wantEdges := []string{
		"PTD_WrittenBy document:roadmap#viewer -> user:attacker map[]",
		"PTD_CanEscalateTo user:attacker -> document:roadmap map[patterns:[PTD-ZAN-008] permission:view]",
	}
	if got := edgeLines(g); !slices.Equal(got, wantEdges) {
		t.Errorf("edges:\n got %#v\nwant %#v", got, wantEdges)
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
