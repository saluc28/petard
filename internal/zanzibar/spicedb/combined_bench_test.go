package spicedb

import (
	"fmt"
	"strings"
	"testing"

	"github.com/saluc28/petard/internal/zanzibar"
)

// broadGrantSchema is a role whose `super` relation grants every permission,
// each permission also readable through its own grant relation. Super is a safe
// gate for every grant relation, since a holder of super already has the
// permission the grant feeds, so the combined check weighs a model that lets a
// holder of super write every grant at once from one starting position. Those
// writes commute and raise nothing, the shape that forced the bounded search to
// walk every subset of them on a large real schema.
func broadGrantSchema(grants int) string {
	var b strings.Builder
	b.WriteString("definition user {}\n\n")
	b.WriteString("definition role {\n")
	b.WriteString("\trelation super: user\n")
	b.WriteString("\tpermission admin = super\n")
	for i := range grants {
		fmt.Fprintf(&b, "\trelation grant%d: user:*\n", i)
		fmt.Fprintf(&b, "\tpermission perm%d = grant%d + super\n", i, i)
	}
	b.WriteString("}\n")
	return b.String()
}

// BenchmarkSafeGatesCombined measures the combined check on a schema where one
// starting position makes many writes available at once, the shape that forces
// the bounded search to walk every combination of them.
func BenchmarkSafeGatesCombined(b *testing.B) {
	for _, n := range []int{10, 20, 30} {
		b.Run(fmt.Sprintf("grants=%d", n), func(b *testing.B) {
			schema, err := Compile("bench.zed", nil, 0, broadGrantSchema(n))
			if err != nil {
				b.Fatal(err)
			}
			wm := &zanzibar.WriteModel{}
			opts := zanzibar.Options{}
			b.ReportAllocs()
			for b.Loop() {
				if _, _, err := zanzibar.SafeGates(schema.Model, wm, schema, opts); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// nonMonotoneGrantSchema is broadGrantSchema with one mixed relation. guard
// occurs positively in needguard and negatively in safe, so a coalition that
// can write it breaks exactness condition E1: the closure cannot saturate to a
// single greatest state and falls back to the bounded search over the orderings
// of the writes available at once. guard stays safe to gate on needguard, whose
// holder already reads it, so the combined proposal check keeps guard writable
// and stays non-E1. It reproduces, generally, the blow-up a large model with an
// exclusion forces on that check.
func nonMonotoneGrantSchema(grants int) string {
	var b strings.Builder
	b.WriteString("definition user {}\n\n")
	b.WriteString("definition role {\n")
	b.WriteString("\trelation super: user\n")
	b.WriteString("\tpermission admin = super\n")
	b.WriteString("\trelation guard: user\n")
	b.WriteString("\tpermission needguard = guard\n")
	b.WriteString("\tpermission safe = admin - guard\n")
	for i := range grants {
		fmt.Fprintf(&b, "\trelation grant%d: user:*\n", i)
		fmt.Fprintf(&b, "\tpermission perm%d = grant%d + super\n", i, i)
	}
	b.WriteString("}\n")
	return b.String()
}

// BenchmarkSafeGatesNonMonotone is the measure-first baseline for making the
// non-E1 proposal check scale. On this schema the combined check runs the
// bounded search in place of saturation, the path that hangs on a large real
// model with an exclusion.
func BenchmarkSafeGatesNonMonotone(b *testing.B) {
	for _, n := range []int{4, 6, 8} {
		b.Run(fmt.Sprintf("grants=%d", n), func(b *testing.B) {
			schema, err := Compile("bench.zed", nil, 0, nonMonotoneGrantSchema(n))
			if err != nil {
				b.Fatal(err)
			}
			wm := &zanzibar.WriteModel{}
			opts := zanzibar.Options{}
			b.ReportAllocs()
			for b.Loop() {
				if _, _, err := zanzibar.SafeGates(schema.Model, wm, schema, opts); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
