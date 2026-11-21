package zanzibar

import (
	"fmt"
	"testing"
	"time"
)

// BenchmarkCheckTogether measures the reuse of safe verdicts across rebuilds
// against reweighing every pair after each demotion. The model is safe heavy: a
// run of grant relations a holder of super can write without raising anything,
// plus one a-and-b conflict that forces a demotion. After that demotion the reuse
// skips the many grant pairs already found safe, which the full recheck weighs
// again, so the gap grows with the number of grants.
func BenchmarkCheckTogether(b *testing.B) {
	for _, grants := range []int{6, 8} {
		model := safeHeavyModel(b, grants)
		wm := serviceGatedW(b)
		opts := Options{Now: time.Unix(0, 0)}
		rc := newReach(model, wm)
		byGate := positionsByGate(startingPositionsForSubjects(model, opts))
		base := phase1Proposals(b, model, wm, nil, byGate, rc, opts)

		b.Run(fmt.Sprintf("reuse/grants=%d", grants), func(b *testing.B) {
			for b.Loop() {
				p := cloneProposals(base)
				if _, err := checkTogether(model, wm, nil, p, byGate, rc, opts); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(fmt.Sprintf("full/grants=%d", grants), func(b *testing.B) {
			for b.Loop() {
				p := cloneProposals(base)
				if err := checkTogetherFullRecheck(model, wm, nil, p, byGate, rc, opts); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// safeHeavyModel is the one-conflict model with many grant relations added, each
// safe to gate on super since a holder of super already has the permission the
// grant feeds. The grants come before the a-and-b conflict, so they are confirmed
// safe before the demotion and the reuse skips them on the pass after it. w is
// service-gated by serviceGatedW, so gate is held only through a position.
func safeHeavyModel(tb testing.TB, grants int) *Model {
	tb.Helper()
	doc := &Type{
		Name: "doc",
		Relations: []*Relation{
			{Name: "w", Allowed: []Allowed{{Type: "user"}}},
			{Name: "super", Allowed: []Allowed{{Type: "user"}}},
		},
		Permissions: []*Permission{
			{Name: "gate", Expr: Computed{Name: "w"}},
			{Name: "admin", Expr: Computed{Name: "super"}},
		},
	}
	for i := range grants {
		doc.Relations = append(doc.Relations, &Relation{Name: fmt.Sprintf("grant%d", i), Allowed: []Allowed{{Type: "user", Wildcard: true}}})
		doc.Permissions = append(doc.Permissions, &Permission{Name: fmt.Sprintf("perm%d", i), Expr: Union{Children: []Expr{Computed{Name: fmt.Sprintf("grant%d", i)}, Computed{Name: "super"}}}})
	}
	doc.Relations = append(doc.Relations,
		&Relation{Name: "a", Allowed: []Allowed{{Type: "user"}}},
		&Relation{Name: "b", Allowed: []Allowed{{Type: "user"}}},
	)
	doc.Permissions = append(doc.Permissions,
		&Permission{Name: "p", Expr: Intersection{Children: []Expr{Computed{Name: "a"}, Computed{Name: "b"}}}},
	)
	m, err := NewModel([]*Type{{Name: "user"}, doc}, nil)
	if err != nil {
		tb.Fatal(err)
	}
	return m
}
