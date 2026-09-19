package taxonomy

import (
	"maps"
	"path/filepath"
	"slices"
	"testing"
)

// The registry says where each pattern leaves its id in the exported graph, and
// a saved query rests on that sentence being true. So it is held against the
// engine: on the fixture, the kinds of node and edge a pattern marks are the
// ones its file declares, and every property the file promises is on at least
// one of them.
func TestRegistryMarksAreWhereTheEngineLeavesThem(t *testing.T) {
	patterns, err := LoadRegistry(filepath.Join("..", "..", "taxonomy-registry", "opa"))
	if err != nil {
		t.Fatalf("LoadRegistry() error = %v", err)
	}

	a := fixtureAnalysis(t)
	findings, err := Run(t.Context(), a)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	g, _, err := Assemble(t.Context(), a, findings)
	if err != nil {
		t.Fatalf("Assemble() error = %v", err)
	}

	// marked holds, per pattern and per kind, the properties of every element
	// the pattern left its id on.
	marked := map[string]map[string][]map[string]any{}
	note := func(kind string, properties map[string]any) {
		for _, id := range patternsOn(properties) {
			if marked[id] == nil {
				marked[id] = map[string][]map[string]any{}
			}
			marked[id][kind] = append(marked[id][kind], properties)
		}
	}
	for _, node := range g.Nodes() {
		note(string(node.Kind), node.Properties)
	}
	for _, edge := range g.Edges() {
		// The provenance becomes properties on the way out, the way the
		// payload carries it, and the registry speaks of the exported graph.
		exported := edge.Source.Properties()
		maps.Copy(exported, edge.Properties)
		note(string(edge.Kind), exported)
	}

	for _, pattern := range patterns {
		t.Run(pattern.ID, func(t *testing.T) {
			declared := map[string][]string{}
			for _, mark := range pattern.Graph.Marks {
				declared[mark.Kind] = mark.Properties
			}
			if len(declared) == 0 {
				t.Fatal("the file declares no marks")
			}

			kinds := slices.Sorted(maps.Keys(marked[pattern.ID]))
			if expected := slices.Sorted(maps.Keys(declared)); !slices.Equal(kinds, expected) {
				t.Fatalf("the engine marks %v on the fixture, the file declares %v", kinds, expected)
			}
			for kind, properties := range declared {
				for _, property := range properties {
					if !slices.ContainsFunc(marked[pattern.ID][kind], func(held map[string]any) bool {
						_, found := held[property]
						return found
					}) {
						t.Errorf("no %s the pattern marks carries %q", kind, property)
					}
				}
			}
		})
	}
}
