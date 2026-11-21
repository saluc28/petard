package zanzibar

import (
	"fmt"
	"testing"
	"time"
)

// BenchmarkStartingPositions measures the generation of starting positions, the
// step that dominates a large OpenFGA model's analysis (over a million positions
// on a deep hierarchy). The model nests a parent chain and an intersection, the
// shapes that drive the arrow and combine paths where the allocation is spent.
func BenchmarkStartingPositions(b *testing.B) {
	for _, depth := range []int{2, 3} {
		b.Run(fmt.Sprintf("depth=%d", depth), func(b *testing.B) {
			model := hierarchyModel(b)
			opts := Options{Now: time.Unix(0, 0), StartingDepth: depth}
			b.ReportAllocs()
			for b.Loop() {
				startingPositionsForSubjects(model, opts)
			}
		})
	}
}

// hierarchyModel is a folder that nests under a folder, with view and edit each
// inherited from the parent through an arrow, and manage the intersection of the
// two. The arrow recursion unfolds into chains (arrowSets), the intersection
// multiplies the ways to hold it (combine), and several subject-bearing relations
// make the pass generate positions for more than one attacker type.
func hierarchyModel(tb testing.TB) *Model {
	tb.Helper()
	folder := &Type{
		Name: "folder",
		Relations: []*Relation{
			{Name: "parent", Allowed: []Allowed{{Type: "folder"}}},
			{Name: "owner", Allowed: []Allowed{{Type: "user"}, {Type: "team", Relation: "member"}}},
			{Name: "viewer", Allowed: []Allowed{{Type: "user"}, {Type: "team", Relation: "member"}}},
			{Name: "editor", Allowed: []Allowed{{Type: "user"}}},
		},
		Permissions: []*Permission{
			{Name: "view", Expr: Union{Children: []Expr{
				Computed{Name: "viewer"},
				Computed{Name: "owner"},
				Arrow{Through: "parent", Target: "view"},
			}}},
			{Name: "edit", Expr: Union{Children: []Expr{
				Computed{Name: "editor"},
				Computed{Name: "owner"},
				Arrow{Through: "parent", Target: "edit"},
			}}},
			{Name: "manage", Expr: Intersection{Children: []Expr{
				Computed{Name: "view"},
				Computed{Name: "edit"},
			}}},
		},
	}
	team := &Type{
		Name:      "team",
		Relations: []*Relation{{Name: "member", Allowed: []Allowed{{Type: "user"}}}},
	}
	m, err := NewModel([]*Type{{Name: "user"}, team, folder}, nil)
	if err != nil {
		tb.Fatal(err)
	}
	return m
}
