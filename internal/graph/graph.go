// Package graph holds Petard's internal graph model: the one the taxonomy
// engine reasons over and the exporter serializes.
//
// The model is engine neutral by construction. No type from opa/v1/ast crosses
// this package boundary, and residual conditions from partial evaluation enter
// as strings that are already serialized. That constraint is the reason a
// second policy engine can reuse the model instead of forcing a rewrite of it,
// and it is cheap to keep only as long as nobody breaks it once.
package graph

import (
	"errors"
	"fmt"
	"maps"
	"slices"
)

var (
	// ErrEmptyID is returned for a node without an id.
	ErrEmptyID = errors.New("graph: node id is empty")

	// ErrUnknownKind is returned for a kind that is not one of the declared
	// ones, the zero value included.
	ErrUnknownKind = errors.New("graph: unknown kind")

	// ErrKindConflict is returned when an id already in the graph comes back
	// under a different kind.
	ErrKindConflict = errors.New("graph: id already used by another kind")

	// ErrDanglingEdge is returned for an edge whose endpoint is not a node.
	ErrDanglingEdge = errors.New("graph: edge endpoint is not in the graph")
)

// Source is the place in the Rego sources that a derived edge comes from.
//
// Petard reports edges an analyst has to be able to check, so an edge derived
// from code carries the file, the line and the rule that produced it:
// selecting it in BloodHound has to answer "which line of Rego grants this",
// not only "this exists". Edges that describe the world around OPA, WrittenBy
// first of all, leave Source at its zero value, because they come from the
// write model and not from any line of policy.
type Source struct {
	File string
	Line int

	// Rule is the ref of the rule, for instance data.quill.authz.allow.
	Rule string
}

// Properties renders the provenance under the property keys that reach the
// export, skipping the fields that are unset. A zero Source returns an empty
// map, so an edge with no provenance does not carry empty keys into the graph.
func (s Source) Properties() map[string]any {
	props := make(map[string]any, 3)
	if s.File != "" {
		props[PropSourceFile] = s.File
	}
	if s.Line > 0 {
		props[PropSourceLine] = s.Line
	}
	if s.Rule != "" {
		props[PropSourceRule] = s.Rule
	}
	return props
}

// Node is one vertex of the model, identified by an id that is stable across
// runs so that two analyses of the same bundle produce the same graph.
type Node struct {
	ID         string
	Kind       NodeKind
	Properties map[string]any
}

// Edge is one directed relation between two nodes, named by their ids.
type Edge struct {
	Kind EdgeKind
	From string
	To   string

	// Source is where in the Rego sources this edge comes from. Zero for edges
	// that are not derived from code.
	Source Source

	Properties map[string]any
}

// Graph is a set of nodes and edges kept in insertion order.
//
// The order is not a detail. The export is a file that gets diffed and
// re-uploaded, and a graph built by ranging over maps would look different at
// every run while describing exactly the same policy.
//
// The graph copies the properties it is given, but hands back its own maps:
// nodes and edges returned by the accessors are for reading, and mutating
// their properties reaches into the graph itself.
type Graph struct {
	nodes map[string]Node
	ids   []string
	edges []Edge
}

// New returns an empty graph.
func New() *Graph {
	return &Graph{nodes: make(map[string]Node)}
}

// AddNode adds n, or merges it into the node already held under the same id.
//
// Merging is deliberate rather than lenient: the same principal is met once
// per rule that mentions it, and each sighting may carry a property the others
// did not. Properties from n win on collision. The same id coming back under a
// different kind is not a merge but a bug in the caller, and returns
// ErrKindConflict.
func (g *Graph) AddNode(n Node) error {
	if n.ID == "" {
		return ErrEmptyID
	}
	if !n.Kind.IsValid() {
		return fmt.Errorf("%w: node %q has kind %q", ErrUnknownKind, n.ID, n.Kind)
	}

	existing, ok := g.nodes[n.ID]
	if !ok {
		n.Properties = maps.Clone(n.Properties)
		g.nodes[n.ID] = n
		g.ids = append(g.ids, n.ID)
		return nil
	}
	if existing.Kind != n.Kind {
		return fmt.Errorf("%w: %q is %q, not %q", ErrKindConflict, n.ID, existing.Kind, n.Kind)
	}

	if len(n.Properties) > 0 {
		if existing.Properties == nil {
			existing.Properties = make(map[string]any, len(n.Properties))
		}
		maps.Copy(existing.Properties, n.Properties)
		g.nodes[n.ID] = existing
	}
	return nil
}

// AddEdge adds e, once both of its endpoints are nodes of the graph.
//
// That check is not pedantry. The OpenGraph payload matches endpoints by id,
// so an edge pointing at an id that was never added creates a node on the
// BloodHound side with no kind and no properties: a typo would arrive looking
// like a finding.
func (g *Graph) AddEdge(e Edge) error {
	if !e.Kind.IsValid() {
		return fmt.Errorf("%w: edge kind %q", ErrUnknownKind, e.Kind)
	}
	if _, ok := g.nodes[e.From]; !ok {
		return fmt.Errorf("%w: %s edge starts at %q", ErrDanglingEdge, e.Kind, e.From)
	}
	if _, ok := g.nodes[e.To]; !ok {
		return fmt.Errorf("%w: %s edge ends at %q", ErrDanglingEdge, e.Kind, e.To)
	}

	e.Properties = maps.Clone(e.Properties)
	g.edges = append(g.edges, e)
	return nil
}

// EnrichEdges merges properties into every edge of the given kind between two
// nodes, and reports how many it reached.
//
// It exists because some of what the analysis knows about an edge is found
// after the edge is: that a read is absent for part of the data is a fact about
// a read, discovered by a pattern that runs once every read is known. The
// alternative would be for the pattern to build its own parallel edge, and the
// graph would then hold the same relation twice with half the truth on each.
//
// The count is the point of the return value: a pattern whose finding reaches
// no edge has matched something the graph does not contain, which is a defect
// worth noticing rather than a silent no-op.
func (g *Graph) EnrichEdges(kind EdgeKind, from, to string, properties map[string]any) int {
	if len(properties) == 0 {
		return 0
	}

	reached := 0
	for i, edge := range g.edges {
		if edge.Kind != kind || edge.From != from || edge.To != to {
			continue
		}
		if g.edges[i].Properties == nil {
			g.edges[i].Properties = make(map[string]any, len(properties))
		}
		maps.Copy(g.edges[i].Properties, properties)
		reached++
	}
	return reached
}

// Node returns the node held under id.
func (g *Graph) Node(id string) (Node, bool) {
	n, ok := g.nodes[id]
	return n, ok
}

// Nodes returns the nodes in insertion order.
func (g *Graph) Nodes() []Node {
	nodes := make([]Node, 0, len(g.ids))
	for _, id := range g.ids {
		nodes = append(nodes, g.nodes[id])
	}
	return nodes
}

// Edges returns the edges in insertion order.
func (g *Graph) Edges() []Edge {
	return slices.Clone(g.edges)
}
