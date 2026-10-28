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
				if _, err := zanzibar.SafeGates(schema.Model, wm, schema, opts); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
