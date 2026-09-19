package taxonomy

import (
	"slices"
	"strings"
	"testing"

	"github.com/saluc28/petard/internal/graph"
)

// patternsOn returns the ids of the patterns an element carries, findings and
// candidates together.
func patternsOn(properties map[string]any) []string {
	found, _ := properties[graph.PropPatterns].([]string)
	candidates, _ := properties[graph.PropCandidatePatterns].([]string)
	return append(slices.Clone(found), candidates...)
}

// Every pattern that reports something on the fixture leaves its id in the
// graph, on the element its fact is about, so that a saved query can ask for
// it. Half of them draw no edge of their own, and before the mark a query had
// no way to find what they said.
func TestEveryPatternLeavesItsMarkOnTheFixture(t *testing.T) {
	a := fixtureAnalysis(t)
	findings, err := Run(t.Context(), a)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	g, gaps, err := Assemble(t.Context(), a, findings)
	if err != nil {
		t.Fatalf("Assemble() error = %v", err)
	}
	if gaps.UnmatchedFindings != 0 {
		t.Errorf("%d findings reached nothing in the graph", gaps.UnmatchedFindings)
	}

	marked := map[string]bool{}
	for _, node := range g.Nodes() {
		for _, id := range patternsOn(node.Properties) {
			marked[id] = true
		}
	}
	for _, edge := range g.Edges() {
		for _, id := range patternsOn(edge.Properties) {
			marked[id] = true
		}
	}
	for _, finding := range findings.All() {
		if !marked[finding.PatternID] {
			t.Errorf("%s reports %q and left no mark in the graph", finding.PatternID, finding.Summary)
		}
	}
}

// Each fact lands where it is about, with what a reader of that element needs:
// the source that fails open says whether anything can still stop it, the rule
// with a vacuous every names the collection, the principal who holds a position
// says what it is worth, and an escalation says which pattern drew it.
func TestFindingsLandWhereTheirFactIs(t *testing.T) {
	a := fixtureAnalysis(t)
	findings, err := Run(t.Context(), a)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	g, _, err := Assemble(t.Context(), a, findings)
	if err != nil {
		t.Fatalf("Assemble() error = %v", err)
	}

	rule, found := g.Node("data.quill.review.allow_unguarded")
	if !found {
		t.Fatal("the rule holding the vacuous every has no node")
	}
	if domains, _ := rule.Properties[graph.PropEmptyDomains].([]string); !slices.Equal(domains, []string{"input.reviews"}) {
		t.Errorf("empty domains = %v, want input.reviews", domains)
	}
	if !slices.Contains(patternsOn(rule.Properties), EveryOverEmptyDomain) {
		t.Errorf("the rule carries %v, not %s", patternsOn(rule.Properties), EveryOverEmptyDomain)
	}

	dave, _ := g.Node("dave")
	if candidates, _ := dave.Properties[graph.PropCandidatePatterns].([]string); !slices.Contains(candidates, TransitiveGrantViaOwnership) {
		t.Errorf("dave holds the position worth taking and carries %v", candidates)
	}
	if positions, _ := dave.Properties[graph.PropPositions].([]string); len(positions) != 1 || !strings.HasPrefix(positions[0], "data.quill.authz.allow: ") {
		t.Errorf("positions = %v, want the one in data.quill.authz.allow", positions)
	}

	byPattern := map[string]string{}
	for _, edge := range edgesOfKind(g, graph.EdgeKindCanEscalateTo) {
		for _, id := range patternsOn(edge.Properties) {
			byPattern[id] = edge.From + " -> " + edge.To
		}
	}
	if byPattern[TransitiveGrantViaOwnership] != "mallory -> dave" || byPattern[WriteAllowedByAnotherDecision] != "carol -> alice" {
		t.Errorf("escalations by pattern = %v, want mallory -> dave from %s and carol -> alice from %s",
			byPattern, TransitiveGrantViaOwnership, WriteAllowedByAnotherDecision)
	}

	failing := 0
	for _, edge := range edgesOfKind(g, graph.EdgeKindReads) {
		if !slices.Contains(patternsOn(edge.Properties), FailOpenOnSourceUnavailable) {
			continue
		}
		failing++
		if edge.Properties[graph.PropMitigation] == nil {
			t.Errorf("the read %s -> %s fails open and does not say whether anything can stop it", edge.From, edge.To)
		}
	}
	if failing != 2 {
		t.Errorf("reads marked as failing open = %d, want the two of the fixture", failing)
	}
}
