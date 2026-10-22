package zanzibar

import (
	"cmp"
	"fmt"
	"maps"
	"slices"

	"github.com/saluc28/petard/internal/graph"
)

// GraphInput is one sample and the write model for its schema. A graph is built
// from several at once, since a set of paths can hold more than one validation
// file, and an escalation two of them both reach is one edge, not one per file.
type GraphInput struct {
	Sample     Sample
	WriteModel *WriteModel
}

// EscalationGraph is the escalation graph of a single sample, built into a fresh
// graph and handed back. It is for callers that have one sample and want the
// graph returned rather than a graph to add into; AddEscalations is the general
// form.
func EscalationGraph(s Sample, wm *WriteModel) (*graph.Graph, error) {
	g := graph.New()
	if err := AddEscalations(g, []GraphInput{{Sample: s, WriteModel: wm}}); err != nil {
		return nil, err
	}
	return g, nil
}

// AddEscalations adds the escalations the inputs allow into g (section 5.1 of
// the definitions): the attacker and the object it raises a permission on as
// nodes, a PTD_WrittenBy for each relation a witness writes, and a
// PTD_CanEscalateTo for the raise. It is the Zanzibar counterpart of the OPA
// taxonomy's AddEscalations, built from the same classifiedEscalations the
// findings are, so a report and a graph of one set of paths never disagree
// about what the engine found.
//
// The inputs are built together, so a raise two validation files both reach is
// one PTD_CanEscalateTo naming every category, not one edge per file. g may
// already hold another engine's graph: what is added goes in after whatever is
// there, and an id another engine used under a different kind fails loud with
// graph.ErrKindConflict rather than merging two unrelated things.
func AddEscalations(g *graph.Graph, inputs []GraphInput) error {
	var found []attackerEscalation
	for _, in := range inputs {
		found = append(found, classifiedEscalations(in.Sample, in.WriteModel)...)
	}

	// The closure visits states in a map's order, and across samples the key a
	// finding dedups on, by object type, is not unique, so sort by the concrete
	// attacker, object and permission as well. The export is diffed, so the
	// graph has to be built the same way on every run.
	slices.SortFunc(found, func(a, b attackerEscalation) int {
		if c := cmp.Compare(a.patternID, b.patternID); c != 0 {
			return c
		}
		if c := cmp.Compare(a.attacker.String(), b.attacker.String()); c != 0 {
			return c
		}
		if c := cmp.Compare(a.esc.Object.String(), b.esc.Object.String()); c != 0 {
			return c
		}
		return cmp.Compare(a.esc.Permission, b.esc.Permission)
	})

	b := &escalationBuilder{
		g:      g,
		writes: map[string]*writeEdge{},
		raises: map[string]*raiseEdge{},
	}
	for _, f := range found {
		if err := b.add(f); err != nil {
			return err
		}
	}
	return b.flush()
}

// escalationBuilder gathers the nodes and edges of an escalation graph. The
// edges are held back until every escalation has been seen, because two
// escalations share them: a relation written on the way to two raises is one
// PTD_WrittenBy, and a permission reachable by two decisive writes is one
// PTD_CanEscalateTo that names both categories, not a parallel edge for each.
type escalationBuilder struct {
	g      *graph.Graph
	writes map[string]*writeEdge
	raises map[string]*raiseEdge
}

// writeEdge is a PTD_WrittenBy under construction: the attribute a witness
// wrote, the principal that wrote it, and the endpoint it went through.
type writeEdge struct {
	attribute string
	writer    string
	via       string
}

// raiseEdge is a PTD_CanEscalateTo under construction: the attacker, the object
// it raises a permission on, and the categories of decisive write that get it
// there.
type raiseEdge struct {
	attacker   string
	object     string
	permission string
	patterns   []string
}

// add puts one escalation's nodes into the graph and records its edges. The
// nodes go in now, in the order the sorted escalations meet them, since an edge
// cannot be added before both of its endpoints are nodes; the edges wait for
// flush so the shared ones are merged rather than repeated.
func (b *escalationBuilder) add(f attackerEscalation) error {
	attacker := f.attacker
	if err := b.node(attacker.String(), graph.NodeKindPrincipal); err != nil {
		return err
	}
	if err := b.node(f.esc.Object.String(), graph.NodeKindResource); err != nil {
		return err
	}

	for _, step := range f.esc.Writes {
		if step.Creation != nil {
			// A creation and its tuples build the coalition's own objects, not a
			// write on a pre-existing attribute, so they are not an edge of the
			// attack path on the object under attack.
			continue
		}
		attribute := attributeID(step.Relationship)
		// A delete carries no writer (the closure records none for it), so the
		// principal that lifted the deny is the attacker that made the move.
		writer := step.Writer.Object
		if writer == (Object{}) {
			writer = attacker
		}
		if err := b.node(attribute, graph.NodeKindAttribute); err != nil {
			return err
		}
		if err := b.node(writer.String(), graph.NodeKindPrincipal); err != nil {
			return err
		}

		key := attribute + "\x00" + writer.String()
		if _, ok := b.writes[key]; !ok {
			b.writes[key] = &writeEdge{attribute: attribute, writer: writer.String(), via: writeVia(step)}
		}
	}

	key := attacker.String() + "\x00" + f.esc.Object.String() + "\x00" + f.esc.Permission
	raise, ok := b.raises[key]
	if !ok {
		raise = &raiseEdge{attacker: attacker.String(), object: f.esc.Object.String(), permission: f.esc.Permission}
		b.raises[key] = raise
	}
	raise.patterns = append(raise.patterns, f.patternID)
	return nil
}

// node adds an id under a kind, naming it after itself. The graph merges a node
// met twice, so a principal that writes and also escalates is added once.
func (b *escalationBuilder) node(id string, kind graph.NodeKind) error {
	if err := b.g.AddNode(graph.Node{
		ID:         id,
		Kind:       kind,
		Properties: map[string]any{graph.PropName: id},
	}); err != nil {
		return fmt.Errorf("zanzibar: adding the %s %s: %w", kind, id, err)
	}
	return nil
}

// flush adds the gathered edges, each kind in its own key order, so the graph
// is built the same way on every run whatever order the escalations arrived in.
func (b *escalationBuilder) flush() error {
	for _, key := range slices.Sorted(maps.Keys(b.writes)) {
		w := b.writes[key]
		edge := graph.Edge{Kind: graph.EdgeKindWrittenBy, From: w.attribute, To: w.writer}
		if w.via != "" {
			edge.Properties = map[string]any{graph.PropVia: w.via}
		}
		if err := b.g.AddEdge(edge); err != nil {
			return fmt.Errorf("zanzibar: adding the write of %s: %w", w.attribute, err)
		}
	}
	for _, key := range slices.Sorted(maps.Keys(b.raises)) {
		raise := b.raises[key]
		if err := b.g.AddEdge(graph.Edge{
			Kind: graph.EdgeKindCanEscalateTo,
			From: raise.attacker,
			To:   raise.object,
			Properties: map[string]any{
				graph.PropPermission: raise.permission,
				// Compacted: the same category can reach one raise from two
				// validation files, and the edge names it once.
				graph.PropPatterns: slices.Compact(slices.Sorted(slices.Values(raise.patterns))),
			},
		}); err != nil {
			return fmt.Errorf("zanzibar: adding the escalation to %s: %w", raise.object, err)
		}
	}
	return nil
}

// attributeID is how a written relation is named as a node: the resource and
// the relation, document:roadmap#viewer, the thing an escalation aims at and
// the question who can write it.
func attributeID(r Relationship) string {
	return r.Resource.String() + "#" + r.Relation
}

// writeVia is the endpoint a write goes through, as the write model's rule
// gives it, empty when the step is a delete the rule left without one.
func writeVia(step WriteStep) string {
	if step.Rule != nil {
		return step.Rule.Via
	}
	return ""
}
