package spicedb

import (
	"fmt"
	"strings"
	"testing"

	"github.com/saluc28/petard/internal/zanzibar"
)

// SafeGates weighs the relations on separate workers, so its output must not
// depend on how the workers interleave. A schema with many relations gives the
// workers something to race over; running it many times and comparing the
// proposals each time catches a result that shifts with scheduling, the way a
// lost write or an out-of-order collection would. The race detector in CI is
// the other half of this; this half needs no cgo and so runs everywhere.
func TestSafeGatesIsDeterministic(t *testing.T) {
	schema, err := Compile("det.zed", nil, 0, wideRoleSchema(20))
	if err != nil {
		t.Fatal(err)
	}
	wm := &zanzibar.WriteModel{}
	opts := zanzibar.Options{}

	first, err := zanzibar.SafeGates(schema.Model, wm, schema, opts)
	if err != nil {
		t.Fatalf("SafeGates: %v", err)
	}
	want := proposalsString(first)
	if !strings.Contains(want, "#") {
		t.Fatalf("the schema produced no proposals to compare:\n%s", want)
	}

	for i := range 25 {
		got, err := zanzibar.SafeGates(schema.Model, wm, schema, opts)
		if err != nil {
			t.Fatalf("SafeGates run %d: %v", i, err)
		}
		if have := proposalsString(got); have != want {
			t.Fatalf("run %d differs from the first:\nwant:\n%s\ngot:\n%s", i, want, have)
		}
	}
}

// proposalsString renders the output-relevant part of the proposals, in order,
// so two runs can be compared byte for byte: the relation, the safe gates, and
// the permissions that are not safe. The escalation witness is left out, since
// it is not what a report prints and need not be identical.
func proposalsString(proposals []zanzibar.GateProposal) string {
	var b strings.Builder
	for _, p := range proposals {
		fmt.Fprintf(&b, "%s#%s safe=%s unsafe=", p.Type, p.Relation, strings.Join(p.Safe, ","))
		for i, u := range p.Unsafe {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(u.Permission)
		}
		b.WriteByte('\n')
	}
	return b.String()
}
