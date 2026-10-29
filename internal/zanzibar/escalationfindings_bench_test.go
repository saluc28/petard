package zanzibar

import (
	"fmt"
	"testing"
	"time"
)

// BenchmarkClassifiedEscalations measures the findings path on a type carrying
// many permissions where a write touches one relation. The reach scopes the
// targets to the permissions that one write could raise, so the work grows with
// the reachable permissions, not with every permission the type declares.
func BenchmarkClassifiedEscalations(b *testing.B) {
	for _, perms := range []int{10, 20, 40} {
		b.Run(fmt.Sprintf("perms=%d", perms), func(b *testing.B) {
			model := wideFlatModelB(b, perms)
			sample := Sample{
				Model:         model,
				Relationships: []Relationship{{Resource: Object{Type: "doc", ID: "d"}, Relation: "member", Subject: Subject{Object: Object{Type: "user", ID: "seed"}}}},
				Caveats:       stubCaveats{},
				Now:           time.Unix(0, 0),
			}
			wm := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: []*WriteRule{
				{Resource: "doc", Relation: "t0", Operations: []Operation{Create, Touch}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Any: true}, Wildcard: true},
			}}
			b.ReportAllocs()
			for b.Loop() {
				classifiedEscalations(sample, wm)
			}
		})
	}
}

// wideFlatModelB is wideFlatModel for a benchmark, which takes *testing.B.
func wideFlatModelB(b *testing.B, perms int) *Model {
	b.Helper()
	doc := &Type{
		Name:        "doc",
		Relations:   []*Relation{{Name: "member", Allowed: []Allowed{{Type: "user"}}}},
		Permissions: []*Permission{{Name: "use", Expr: Computed{Name: "member"}}},
	}
	for i := range perms {
		doc.Relations = append(doc.Relations, &Relation{Name: fmt.Sprintf("t%d", i), Allowed: []Allowed{{Type: "user", Wildcard: true}}})
		doc.Permissions = append(doc.Permissions, &Permission{Name: fmt.Sprintf("p%d", i), Expr: Computed{Name: fmt.Sprintf("t%d", i)}})
	}
	m, err := NewModel([]*Type{{Name: "user"}, doc}, nil)
	if err != nil {
		b.Fatal(err)
	}
	return m
}
