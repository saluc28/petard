package opaengine

import (
	"slices"
	"strings"
	"testing"

	"github.com/saluc28/petard/internal/graph"
)

// graphOnFixture is the graph of the hand written bundle, which every test here
// asks a different question of.
func graphOnFixture(t *testing.T) (*graph.Graph, *ReadSet) {
	t.Helper()

	bundle, err := Load([]string{fixtureDir(t, "policy-v1")}, ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	reads, err := Reads(bundle, Limits{})
	if err != nil {
		t.Fatalf("Reads() error = %v", err)
	}
	g, err := BuildGraph(reads)
	if err != nil {
		t.Fatalf("BuildGraph() error = %v", err)
	}
	return g, reads
}

// The graph is the declared output of this phase, and this is what it holds
// after reading the fixture: a node per rule that reads, one per thing read,
// and an edge for each read carrying where in the sources it happens. A value
// the policy did not compute is a thing read like any other, plus an edge to
// whoever answered for it.
func TestBuildGraphFromFixture(t *testing.T) {
	g, reads := graphOnFixture(t)

	var attributes []string
	for _, node := range g.Nodes() {
		if node.Kind == graph.NodeKindAttribute {
			attributes = append(attributes, node.ID)
		}
	}
	slices.Sort(attributes)

	expected := reads.Paths()
	for _, taint := range reads.Taints {
		expected = append(expected, taint.Ref)
	}
	slices.Sort(expected)
	expected = slices.Compact(expected)

	if !slices.Equal(attributes, expected) {
		t.Errorf("attribute nodes = %v, want the paths read plus the values believed %v", attributes, expected)
	}

	// One read edge per read and per taint, and one origin edge per taint.
	if got, want := len(g.Edges()), len(reads.Reads)+2*len(reads.Taints); got != want {
		t.Errorf("edges = %d, want %d", got, want)
	}
}

// An edge nobody can trace back to a line of Rego is an assertion. This is the
// property decided before any of this code existed, and the first place it is
// actually used.
func TestBuildGraphCarriesProvenance(t *testing.T) {
	g, _ := graphOnFixture(t)

	for _, edge := range g.Edges() {
		if edge.Source.File == "" || edge.Source.Line == 0 || edge.Source.Rule == "" {
			t.Errorf("edge %s -> %s has no source: %+v", edge.From, edge.To, edge.Source)
		}
		if edge.Kind != graph.EdgeKindReads {
			continue
		}
		if _, ok := edge.Properties[graph.PropProvenance]; !ok {
			t.Errorf("edge %s -> %s has no provenance", edge.From, edge.To)
		}
	}
}

// The endpoints the fixture names are the nodes the taint edges land on, and
// two rules asking the same host meet on one of them rather than on two.
func TestBuildGraphJoinsCallsToTheSameHost(t *testing.T) {
	g, _ := graphOnFixture(t)

	sources := map[string]int{}
	for _, edge := range g.Edges() {
		if edge.Kind == graph.EdgeKindTaintedBy {
			sources[edge.To]++
		}
	}

	const risk = "https://risk.petard-fixture.invalid/score"
	if sources[risk] < 2 {
		t.Errorf("the risk host is reached %d times, want the several calls to meet on one node: %v", sources[risk], sources)
	}
	if node, ok := g.Node(risk); !ok || node.Kind != graph.NodeKindPrincipal {
		t.Errorf("the external source is %v, want a principal", node.Kind)
	}
}

// A destination the request can steer is the worse of the two cases, so it gets
// a node rather than being dropped for want of a name, and the name says what is
// actually known: the call, not the host.
func TestBuildGraphNamesAComputedDestinationByItsCallSite(t *testing.T) {
	dir := writeSources(t, map[string]string{
		"policy.rego": `package t

# METADATA
# scope: document
# entrypoint: true
default allow := false

allow if {
	answer := http.send({"method": "GET", "url": input.host})
	answer.body.ok
}
`,
	})
	bundle, err := Load([]string{dir}, ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	reads, err := Reads(bundle, Limits{})
	if err != nil {
		t.Fatalf("Reads() error = %v", err)
	}
	g, err := BuildGraph(reads)
	if err != nil {
		t.Fatalf("BuildGraph() error = %v", err)
	}

	for _, edge := range g.Edges() {
		if edge.Kind != graph.EdgeKindTaintedBy {
			continue
		}
		if !strings.HasPrefix(edge.To, "http.send at ") {
			t.Errorf("computed destination named %q, want the call site", edge.To)
		}
		return
	}
	t.Error("the call whose destination is computed has no origin edge")
}

// A rule that the PEP asks for and one that only serves it are the same kind
// of thing, and the graph says which is which with a property rather than by
// splitting them apart.
func TestBuildGraphMarksDecisions(t *testing.T) {
	g, _ := graphOnFixture(t)

	// authz.allow is an entrypoint; is_member only serves it.
	decision, ok := g.Node("data.quill.authz.allow")
	if !ok {
		t.Fatal("the decision node is missing")
	}
	if decision.Properties[graph.PropIsDecision] != true {
		t.Error("the entrypoint is not marked as a decision")
	}

	helper, ok := g.Node("data.quill.authz.is_member")
	if !ok {
		t.Fatal("the helper node is missing")
	}
	if helper.Properties[graph.PropIsDecision] != false {
		t.Error("a rule the PEP does not ask for is marked as a decision")
	}
}

// The read inside is_member is the one whose provenance comes from elsewhere,
// so its edge is where the answer has to be readable without rerunning the
// analysis.
func TestBuildGraphKeepsTheProvenanceTerm(t *testing.T) {
	g, _ := graphOnFixture(t)

	for _, edge := range g.Edges() {
		if edge.From != "data.quill.authz.is_member" || edge.To != "data.users[_].profile.department" {
			continue
		}
		if got := edge.Properties[graph.PropProvenance]; got != "input" {
			t.Errorf("provenance = %v, want input", got)
		}
		if got := edge.Properties[graph.PropProvenanceTerm]; got != "input.user" {
			t.Errorf("provenance term = %v, want input.user", got)
		}
		return
	}
	t.Error("the read inside is_member has no edge")
}
