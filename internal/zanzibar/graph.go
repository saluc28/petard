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
	if _, err := AddEscalations(g, []GraphInput{{Sample: s, WriteModel: wm}}); err != nil {
		return nil, err
	}
	return g, nil
}

// AddEscalations adds what the inputs say about who can do what into g (section 5.1
// of the definitions). A subject the relationships name becomes a principal when it has
// something to show: a PTD_CanPerform for what it holds as they stand, a PTD_CanEscalateTo
// for what it can raise by writing what the write model allows. The escalations the findings are
// built from go in as well, from attackers the analysis supposes and starting positions
// generated from the schema. Their nodes are marked hypothetical, since nobody names
// them, and they say what any account could reach.
//
// A PTD_WrittenBy goes on each relation a witness writes. BloodHound keeps one edge
// of a kind between two nodes (the unique key of the edge table at dawgs v0.6.0,
// drivers/pg/query/sql/schema_up.sql:146) and merges the properties of the others over
// it, so there is one edge per principal and object, and it lists every permission
// and every pattern.
//
// The inputs are built together, so a raise two validation files both reach is
// one PTD_CanEscalateTo naming every category, not one edge per file. g may
// already hold another engine's graph: what is added goes in after whatever is
// there, and an id another engine used under a different kind fails loud with
// graph.ErrKindConflict rather than merging two unrelated things.
//
// It says where it stopped short of weighing everything, for the caller to report.
func AddEscalations(g *graph.Graph, inputs []GraphInput) (Limits, error) {
	return addEscalations(g, inputs, maxHoldingChecks)
}

// addEscalations is AddEscalations with the checks asking what subjects hold given, for
// each input.
func addEscalations(g *graph.Graph, inputs []GraphInput, holdingChecks int) (Limits, error) {
	var found []attackerEscalation
	var holdings []holding
	var limits Limits
	for _, in := range inputs {
		classified, classifiedLimits := classifiedEscalations(in.Sample, in.WriteModel)
		subjects, subjectLimits := subjectEscalations(in.Sample, in.WriteModel, maxSubjectWork)
		found = append(append(found, classified...), subjects...)
		limits.Add(classifiedLimits)
		limits.Add(subjectLimits)
		held, heldLimits := subjectHoldings(in.Sample, holdingChecks)
		holdings = append(holdings, held...)
		limits.Add(heldLimits)
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
		nodes:  map[string]*builderNode{},
		writes: map[string]*writeEdge{},
		raises: map[string]*principalEdge{},
		holds:  map[string]*principalEdge{},
	}
	for _, f := range found {
		b.add(f)
	}
	for _, h := range holdings {
		b.hold(h)
	}
	return limits, b.flush()
}

// escalationBuilder gathers the nodes and edges of an escalation graph. They are
// held back until every escalation has been seen, because two escalations share
// them: a relation written on the way to two raises is one PTD_WrittenBy, and two
// permissions raised on one object are one PTD_CanEscalateTo that names both. A node
// waits too, since only the whole set says whether an object is a principal.
type escalationBuilder struct {
	g      *graph.Graph
	order  []string
	nodes  map[string]*builderNode
	writes map[string]*writeEdge
	raises map[string]*principalEdge
	holds  map[string]*principalEdge
}

// builderNode is a node under construction.
type builderNode struct {
	kind         graph.NodeKind
	hypothetical bool
}

// writeEdge is a PTD_WrittenBy under construction: the attribute a witness
// wrote, the principal that wrote it, and the endpoint it went through.
type writeEdge struct {
	attribute string
	writer    string
	via       string
}

// principalEdge is an edge under construction from a principal to an object: the
// permissions it holds or raises there and, for a raise, the patterns that read it.
type principalEdge struct {
	principal   string
	object      string
	permissions []string
	patterns    []string
}

// add records one escalation's nodes and edges.
func (b *escalationBuilder) add(f attackerEscalation) {
	attacker := f.attacker
	b.node(attacker.String(), graph.NodeKindPrincipal, f.hypothetical)
	b.node(f.esc.Object.String(), graph.NodeKindResource, f.position)

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
		b.node(attribute, graph.NodeKindAttribute, f.position)
		// A writer other than the attacker is an object the coalition made, which
		// nobody names either.
		b.node(writer.String(), graph.NodeKindPrincipal, f.hypothetical || writer != attacker)

		key := attribute + "\x00" + writer.String()
		if _, ok := b.writes[key]; !ok {
			b.writes[key] = &writeEdge{attribute: attribute, writer: writer.String(), via: writeVia(step)}
		}
	}

	raise := edgeOf(b.raises, attacker, f.esc.Object)
	raise.permissions = append(raise.permissions, f.esc.Permission)
	raise.patterns = append(raise.patterns, f.patternID)
}

// hold records what a real subject holds as the relationships stand.
func (b *escalationBuilder) hold(h holding) {
	b.node(h.subject.String(), graph.NodeKindPrincipal, false)
	b.node(h.object.String(), graph.NodeKindResource, false)
	held := edgeOf(b.holds, h.subject, h.object)
	held.permissions = append(held.permissions, h.permission)
}

// edgeOf is the edge under construction from a principal to an object, started if it
// is the first time the two meet.
func edgeOf(edges map[string]*principalEdge, principal, object Object) *principalEdge {
	key := principal.String() + "\x00" + object.String()
	if edges[key] == nil {
		edges[key] = &principalEdge{principal: principal.String(), object: object.String()}
	}
	return edges[key]
}

// node records an id under a kind. An object something is raised on can also be a
// subject that raises something, and a graph holds one node for it: it is a principal,
// since an edge can end at a principal and a resource starts nothing. A node is
// hypothetical only if nothing real ever named it.
func (b *escalationBuilder) node(id string, kind graph.NodeKind, hypothetical bool) {
	n, met := b.nodes[id]
	if !met {
		b.order = append(b.order, id)
		b.nodes[id] = &builderNode{kind: kind, hypothetical: hypothetical}
		return
	}
	if kind == graph.NodeKindPrincipal {
		n.kind = kind
	}
	n.hypothetical = n.hypothetical && hypothetical
}

// flush adds what was gathered, the nodes in the order they were met and each kind of
// edge in its own key order, so the graph is built the same way on every run whatever
// order the escalations arrived in.
func (b *escalationBuilder) flush() error {
	for _, id := range b.order {
		n := b.nodes[id]
		properties := map[string]any{graph.PropName: id}
		if n.hypothetical {
			properties[graph.PropHypothetical] = true
		}
		if err := b.g.AddNode(graph.Node{ID: id, Kind: n.kind, Properties: properties}); err != nil {
			return fmt.Errorf("zanzibar: adding the %s %s: %w", n.kind, id, err)
		}
	}
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
			From: raise.principal,
			To:   raise.object,
			Properties: map[string]any{
				graph.PropPermissions: sortedOnce(raise.permissions),
				// Once each: the same category can reach one raise from two
				// validation files, and the edge names it once.
				graph.PropPatterns: sortedOnce(raise.patterns),
			},
		}); err != nil {
			return fmt.Errorf("zanzibar: adding the escalation to %s: %w", raise.object, err)
		}
	}
	for _, key := range slices.Sorted(maps.Keys(b.holds)) {
		held := b.holds[key]
		if err := b.g.AddEdge(graph.Edge{
			Kind:       graph.EdgeKindCanPerform,
			From:       held.principal,
			To:         held.object,
			Properties: map[string]any{graph.PropPermissions: sortedOnce(held.permissions)},
		}); err != nil {
			return fmt.Errorf("zanzibar: adding what %s holds on %s: %w", held.principal, held.object, err)
		}
	}
	return nil
}

// sortedOnce is values in order, each once.
func sortedOnce(values []string) []string {
	return slices.Compact(slices.Sorted(slices.Values(values)))
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
