package spicedb

import (
	"fmt"
	"strings"
	"testing"

	"github.com/saluc28/petard/internal/zanzibar"
)

// wideRoleSchema is a schema shaped like a real RBAC role: one type carrying
// many permissions, each fed by its own relation to every principal at once. A
// run on such a schema with no write rules asks SafeGates for a gate on every
// relation, which is where the proposal work grows with the number of
// permissions. The member relation gives the schema a direct subject, so the
// starting positions a gate rests on are not empty.
func wideRoleSchema(perms int) string {
	var b strings.Builder
	b.WriteString("definition principal {}\n\n")
	b.WriteString("definition resource {\n")
	b.WriteString("\trelation member: principal\n")
	b.WriteString("\tpermission use = member\n")
	for i := range perms {
		fmt.Fprintf(&b, "\tpermission perm%d = t_perm%d\n", i, i)
		fmt.Fprintf(&b, "\trelation t_perm%d: principal:*\n", i)
	}
	b.WriteString("}\n")
	return b.String()
}

// BenchmarkSafeGates measures how the safe-gate proposals scale with the number
// of permissions on a type, the axis a real RBAC role grows along.
func BenchmarkSafeGates(b *testing.B) {
	for _, perms := range []int{10, 20, 40} {
		b.Run(fmt.Sprintf("perms=%d", perms), func(b *testing.B) {
			schema, err := Compile("bench.zed", nil, 0, wideRoleSchema(perms))
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
