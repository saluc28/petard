package taxonomy

import (
	"errors"
	"slices"
	"testing"

	"github.com/saluc28/petard/internal/graph"
	"github.com/saluc28/petard/internal/opaengine"
)

// graphOn builds the model the way the command does, so that a test asks the
// same graph a reader of the report would get.
func graphOn(t *testing.T, a Analysis) *graph.Graph {
	t.Helper()

	g, err := opaengine.BuildGraph(a.Reads)
	if err != nil {
		t.Fatalf("BuildGraph() error = %v", err)
	}
	if _, err := AddWritePaths(g, a.Reads, a.Model); err != nil {
		t.Fatalf("AddWritePaths() error = %v", err)
	}
	if _, err := AddCapabilities(t.Context(), g, a); err != nil {
		t.Fatalf("AddCapabilities() error = %v", err)
	}
	return g
}

func edgesOfKind(g *graph.Graph, kind graph.EdgeKind) []graph.Edge {
	var edges []graph.Edge
	for _, edge := range g.Edges() {
		if edge.Kind == kind {
			edges = append(edges, edge)
		}
	}
	return edges
}

// The write model of the fixture declares five entries and only two of them
// name somebody the graph can hold. The other three say who by describing how
// to find them, and a node called "{owner}" would be a principal nobody is.
func TestAddWritePathsOnlyNamesRealEntities(t *testing.T) {
	a := fixtureAnalysis(t)

	g, err := opaengine.BuildGraph(a.Reads)
	if err != nil {
		t.Fatalf("BuildGraph() error = %v", err)
	}
	derived, err := AddWritePaths(g, a.Reads, a.Model)
	if err != nil {
		t.Fatalf("AddWritePaths() error = %v", err)
	}

	if derived != 3 {
		t.Errorf("writers left out = %d, want 3: two captures and one derived relation", derived)
	}

	var written []string
	for _, edge := range edgesOfKind(g, graph.EdgeKindWrittenBy) {
		written = append(written, edge.From+" -> "+edge.To)

		if edge.Properties[graph.PropVia] == nil {
			t.Errorf("the edge %s -> %s does not say how the write happens", edge.From, edge.To)
		}
		if edge.Properties[graph.PropWriteConfidence] != "asserted" {
			t.Errorf("write confidence = %v, want asserted", edge.Properties[graph.PropWriteConfidence])
		}
		if edge.Source.File != "" {
			t.Errorf("the edge %s -> %s carries a source, and no line of policy produced it", edge.From, edge.To)
		}
	}
	slices.Sort(written)

	expected := []string{
		"data.tenants[_].policy.require_mfa -> system:provisioning",
		"data.users[_].roles -> role:admin",
		"data.users[_].roles -> role:support",
	}
	if !slices.Equal(written, expected) {
		t.Errorf("write edges = %v, want %v", written, expected)
	}
}

// A capability is a measurement of today: the same policy against other
// documents gives a different set of these edges, and each one carries the
// condition that still has to hold plus how well the subject was recognized.
func TestAddCapabilitiesPointsAtTheResource(t *testing.T) {
	a := fixtureAnalysis(t)
	g := graphOn(t, a)

	capabilities := edgesOfKind(g, graph.EdgeKindCanPerform)
	if len(capabilities) == 0 {
		t.Fatal("no capability reached the graph")
	}

	resources := 0
	for _, edge := range capabilities {
		if edge.Properties[graph.PropCondition] == nil {
			t.Errorf("the capability %s -> %s has no condition", edge.From, edge.To)
		}
		if edge.Properties[graph.PropDecision] == nil {
			t.Errorf("the capability %s -> %s does not say out of which decision", edge.From, edge.To)
		}
		// The level the subject was recognized at travels with the claim, since
		// the claim is about a principal and that is who the level is about.
		if edge.Properties[graph.PropConfidence] != "D" {
			t.Errorf("confidence = %v, want D: the fixture names its subject by field names", edge.Properties[graph.PropConfidence])
		}

		node, ok := g.Node(edge.To)
		if !ok {
			t.Fatalf("the capability %s -> %s ends nowhere", edge.From, edge.To)
		}
		if node.Kind == graph.NodeKindResource {
			resources++
		}
	}

	if resources == 0 {
		t.Error("no capability names a resource, and the fixture constrains input.doc")
	}

	// mallory holds nothing today, which is the premise of the whole chain. A
	// capability edge out of her would mean the fixture stopped saying that.
	for _, edge := range capabilities {
		if edge.From == "mallory" {
			t.Errorf("mallory can already do something: %s -> %s", edge.From, edge.To)
		}
	}
}

// A capability measured against no documents is not a capability of zero, it is
// a question that was not asked.
func TestAddCapabilitiesNeedsData(t *testing.T) {
	a := fixtureAnalysis(t)
	a.Data = nil

	g, err := opaengine.BuildGraph(a.Reads)
	if err != nil {
		t.Fatalf("BuildGraph() error = %v", err)
	}
	if _, err := AddCapabilities(t.Context(), g, a); !errors.Is(err, ErrNeedsData) {
		t.Errorf("AddCapabilities() error = %v, want ErrNeedsData", err)
	}
}

// A way of granting that also needs a second factor, or an answer from a remote
// service, is not a capability somebody has. The fixture holds several, and the
// count is what keeps leaving them out from looking like finding none.
func TestAddCapabilitiesLeavesOutWhatAnEdgeCannotSay(t *testing.T) {
	a := fixtureAnalysis(t)

	g, err := opaengine.BuildGraph(a.Reads)
	if err != nil {
		t.Fatalf("BuildGraph() error = %v", err)
	}
	conditional, err := AddCapabilities(t.Context(), g, a)
	if err != nil {
		t.Fatalf("AddCapabilities() error = %v", err)
	}

	if conditional == 0 {
		t.Error("every way of granting became an edge, and the fixture holds decisions that also ask for mfa or for a remote answer")
	}
	for _, edge := range edgesOfKind(g, graph.EdgeKindCanPerform) {
		if edge.From == "mallory" {
			t.Errorf("mallory holds nothing today, yet an edge says %s -> %s under %v",
				edge.From, edge.To, edge.Properties[graph.PropCondition])
		}
	}
}
