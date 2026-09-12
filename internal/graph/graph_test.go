package graph

import (
	"errors"
	"maps"
	"testing"
)

func TestSourceProperties(t *testing.T) {
	tests := []struct {
		name     string
		source   Source
		expected map[string]any
	}{
		{
			name:     "zero source carries no keys",
			source:   Source{},
			expected: map[string]any{},
		},
		{
			name:   "full provenance",
			source: Source{File: "policy-v1/authz.rego", Line: 24, Rule: "data.quill.authz.allow"},
			expected: map[string]any{
				"source_file": "policy-v1/authz.rego",
				"source_line": 24,
				"source_rule": "data.quill.authz.allow",
			},
		},
		{
			name:     "line zero is unset, not line zero",
			source:   Source{File: "policy-v1/authz.rego"},
			expected: map[string]any{"source_file": "policy-v1/authz.rego"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.source.Properties(); !maps.Equal(got, tt.expected) {
				t.Errorf("Properties() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGraphAddNode(t *testing.T) {
	tests := []struct {
		name        string
		nodes       []Node
		expectedErr error
	}{
		{
			name:        "empty id",
			nodes:       []Node{{Kind: NodeKindPrincipal}},
			expectedErr: ErrEmptyID,
		},
		{
			name:        "unknown kind",
			nodes:       []Node{{ID: "mallory", Kind: "PTD_User"}},
			expectedErr: ErrUnknownKind,
		},
		{
			name:        "zero kind",
			nodes:       []Node{{ID: "mallory"}},
			expectedErr: ErrUnknownKind,
		},
		{
			name:  "same id, same kind",
			nodes: []Node{{ID: "mallory", Kind: NodeKindPrincipal}, {ID: "mallory", Kind: NodeKindPrincipal}},
		},
		{
			name:        "same id, different kind",
			nodes:       []Node{{ID: "mallory", Kind: NodeKindPrincipal}, {ID: "mallory", Kind: NodeKindResource}},
			expectedErr: ErrKindConflict,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := New()
			var err error
			for _, n := range tt.nodes {
				if err = g.AddNode(n); err != nil {
					break
				}
			}
			if !errors.Is(err, tt.expectedErr) {
				t.Fatalf("AddNode() error = %v, want %v", err, tt.expectedErr)
			}
		})
	}
}

// A principal is met once per rule that mentions it, and each sighting may
// carry a property the previous one did not. Merging is what keeps the caller
// from having to collect everything before adding anything.
func TestGraphAddNodeMergesProperties(t *testing.T) {
	g := New()
	if err := g.AddNode(Node{ID: "mallory", Kind: NodeKindPrincipal, Properties: map[string]any{"name": "mallory", "tenant": "berq"}}); err != nil {
		t.Fatalf("first AddNode() error = %v", err)
	}
	if err := g.AddNode(Node{ID: "mallory", Kind: NodeKindPrincipal, Properties: map[string]any{"tenant": "dolm", "role": "viewer"}}); err != nil {
		t.Fatalf("second AddNode() error = %v", err)
	}

	n, ok := g.Node("mallory")
	if !ok {
		t.Fatal("Node(\"mallory\") not found")
	}
	expected := map[string]any{"name": "mallory", "tenant": "dolm", "role": "viewer"}
	if !maps.Equal(n.Properties, expected) {
		t.Errorf("properties = %v, want %v", n.Properties, expected)
	}
}

// The graph copies the properties it is given. Without that, a caller reusing
// one map across several nodes would rewrite nodes already added, and the
// damage would show up in the export rather than here.
func TestGraphAddNodeCopiesProperties(t *testing.T) {
	g := New()
	props := map[string]any{"name": "mallory"}
	if err := g.AddNode(Node{ID: "mallory", Kind: NodeKindPrincipal, Properties: props}); err != nil {
		t.Fatalf("AddNode() error = %v", err)
	}

	props["name"] = "dave"

	n, _ := g.Node("mallory")
	if n.Properties["name"] != "mallory" {
		t.Errorf("name = %v, want mallory: the caller's map is aliased", n.Properties["name"])
	}
}

// newEdgeTestGraph returns a graph holding the two nodes the edge tests link.
func newEdgeTestGraph(t *testing.T) *Graph {
	t.Helper()

	g := New()
	for _, n := range []Node{
		{ID: "rule:allow", Kind: NodeKindAction},
		{ID: "attr:department", Kind: NodeKindAttribute},
	} {
		if err := g.AddNode(n); err != nil {
			t.Fatalf("AddNode(%q) error = %v", n.ID, err)
		}
	}
	return g
}

func TestGraphAddEdge(t *testing.T) {
	tests := []struct {
		name        string
		edge        Edge
		expectedErr error
	}{
		{
			name: "between known nodes",
			edge: Edge{Kind: EdgeKindReads, From: "rule:allow", To: "attr:department"},
		},
		{
			name:        "unknown kind",
			edge:        Edge{Kind: "PTD_Uses", From: "rule:allow", To: "attr:department"},
			expectedErr: ErrUnknownKind,
		},
		{
			name:        "unknown start",
			edge:        Edge{Kind: EdgeKindReads, From: "rule:missing", To: "attr:department"},
			expectedErr: ErrDanglingEdge,
		},
		{
			name:        "unknown end",
			edge:        Edge{Kind: EdgeKindReads, From: "rule:allow", To: "attr:missing"},
			expectedErr: ErrDanglingEdge,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := newEdgeTestGraph(t)

			err := g.AddEdge(tt.edge)
			if !errors.Is(err, tt.expectedErr) {
				t.Fatalf("AddEdge() error = %v, want %v", err, tt.expectedErr)
			}
		})
	}
}

func TestGraphKeepsInsertionOrder(t *testing.T) {
	g := New()
	ids := []string{"mallory", "dave", "alice"}
	for _, id := range ids {
		if err := g.AddNode(Node{ID: id, Kind: NodeKindPrincipal}); err != nil {
			t.Fatalf("AddNode(%q) error = %v", id, err)
		}
	}
	// Adding a node again must not move it to the end: two runs over the same
	// bundle have to produce the same file.
	if err := g.AddNode(Node{ID: "mallory", Kind: NodeKindPrincipal, Properties: map[string]any{"role": "viewer"}}); err != nil {
		t.Fatalf("AddNode() error = %v", err)
	}

	nodes := g.Nodes()
	if len(nodes) != len(ids) {
		t.Fatalf("Nodes() length = %d, want %d", len(nodes), len(ids))
	}
	for i, id := range ids {
		if nodes[i].ID != id {
			t.Errorf("Nodes()[%d].ID = %q, want %q", i, nodes[i].ID, id)
		}
	}

	for _, id := range ids[1:] {
		if err := g.AddEdge(Edge{Kind: EdgeKindCanEscalateTo, From: "mallory", To: id}); err != nil {
			t.Fatalf("AddEdge() error = %v", err)
		}
	}
	edges := g.Edges()
	if len(edges) != 2 {
		t.Fatalf("Edges() length = %d, want 2", len(edges))
	}
	if edges[0].To != "dave" || edges[1].To != "alice" {
		t.Errorf("edge order = %q then %q, want dave then alice", edges[0].To, edges[1].To)
	}
}

func TestGraphEdgeCarriesProvenance(t *testing.T) {
	g := newEdgeTestGraph(t)

	source := Source{File: "policy-v1/authz.rego", Line: 26, Rule: "data.quill.authz.allow"}
	if err := g.AddEdge(Edge{Kind: EdgeKindReads, From: "rule:allow", To: "attr:department", Source: source}); err != nil {
		t.Fatalf("AddEdge() error = %v", err)
	}

	edges := g.Edges()
	if len(edges) != 1 {
		t.Fatalf("Edges() length = %d, want 1", len(edges))
	}
	if edges[0].Source != source {
		t.Errorf("Source = %+v, want %+v", edges[0].Source, source)
	}
}

// TestEnrichEdges covers what a pattern does when it learns something about a
// read after the read is already in the graph: the fact belongs on that edge,
// and a fact that reaches no edge at all has to be countable rather than lost.
func TestEnrichEdges(t *testing.T) {
	g := New()
	for id, kind := range map[string]NodeKind{
		"data.t.allow":    NodeKindRule,
		"data.t.deny":     NodeKindRule,
		"data.users[_].x": NodeKindAttribute,
	} {
		if err := g.AddNode(Node{ID: id, Kind: kind}); err != nil {
			t.Fatalf("AddNode(%s) error = %v", id, err)
		}
	}

	for _, from := range []string{"data.t.allow", "data.t.deny"} {
		if err := g.AddEdge(Edge{Kind: EdgeKindReads, From: from, To: "data.users[_].x"}); err != nil {
			t.Fatalf("AddEdge() error = %v", err)
		}
	}

	if reached := g.EnrichEdges(EdgeKindReads, "data.t.deny", "data.users[_].x", map[string]any{PropKeysChecked: 2}); reached != 1 {
		t.Errorf("edges reached = %d, want 1", reached)
	}

	for _, edge := range g.Edges() {
		_, enriched := edge.Properties[PropKeysChecked]
		if want := edge.From == "data.t.deny"; enriched != want {
			t.Errorf("edge from %s enriched = %v, want %v", edge.From, enriched, want)
		}
	}

	// A fact about a relation the graph does not hold is a defect in whoever
	// stated it, and the count is the only way that shows.
	if reached := g.EnrichEdges(EdgeKindReads, "data.t.allow", "data.other", map[string]any{PropKeysChecked: 1}); reached != 0 {
		t.Errorf("edges reached = %d, want none", reached)
	}
	if reached := g.EnrichEdges(EdgeKindReads, "data.t.allow", "data.users[_].x", nil); reached != 0 {
		t.Errorf("enriching with nothing reached %d edges, want none", reached)
	}
}
