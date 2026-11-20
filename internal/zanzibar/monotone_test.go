package zanzibar

import (
	"testing"
	"time"
)

// effectivelyMonotone has to tell a search that cannot reach the mixed relation,
// which saturation decides exactly, from one that can, which the bounded search
// must weigh. The decision rests on the gate of the mixed relation and the start.
func TestEffectivelyMonotone(t *testing.T) {
	opts := Options{Now: time.Unix(0, 0)}
	start := []Relationship{rel("role:target", "super", "user:attacker")}
	coalition := []Object{object("user:attacker")}

	check := func(t *testing.T, wm *WriteModel) bool {
		e := newEngine(nonMonotoneGrantModel(t, 3), wm, stubCaveats{}, start, coalition, opts)
		mixed := e.mixedWritableRelations()
		if !mixed[relRef{typ: "role", name: "guard"}] {
			t.Fatal("guard should be a mixed writable relation")
		}
		state, objects, err := e.saturateMonotone(mixed)
		if err != nil {
			t.Fatal(err)
		}
		mono, err := e.effectivelyMonotone(mixed, state, objects)
		if err != nil {
			t.Fatal(err)
		}
		return mono
	}

	// guard is gated on needguard, which needs guard: a holder of super alone can
	// never write it, so the search is monotone in effect.
	if !check(t, nonMonotoneGrantWrites(3)) {
		t.Error("guard gated on needguard is unreachable from super: should be effectively monotone")
	}
	// guard is gated on admin, which a holder of super has, so it is reachable and
	// the search is not monotone.
	if check(t, nonMonotoneGrantWritesReachable(3)) {
		t.Error("guard gated on admin is reachable from super: should not be effectively monotone")
	}
}

// A mixed relation already present at the start can be deleted, so the search is
// not monotone even when no rule could add the relation again.
func TestEffectivelyMonotoneStartTuple(t *testing.T) {
	opts := Options{Now: time.Unix(0, 0)}
	start := []Relationship{
		rel("role:target", "super", "user:attacker"),
		rel("role:target", "guard", "user:other"),
	}
	e := newEngine(nonMonotoneGrantModel(t, 3), nonMonotoneGrantWrites(3), stubCaveats{}, start, []Object{object("user:attacker")}, opts)
	mixed := e.mixedWritableRelations()
	state, objects, err := e.saturateMonotone(mixed)
	if err != nil {
		t.Fatal(err)
	}
	mono, err := e.effectivelyMonotone(mixed, state, objects)
	if err != nil {
		t.Fatal(err)
	}
	if mono {
		t.Error("a guard tuple at the start can be deleted: should not be effectively monotone")
	}
}

func TestGateMonotone(t *testing.T) {
	e := newEngine(gatedByMixedModel(t), &WriteModel{}, stubCaveats{}, nil, nil, Options{})
	// p = flag reads flag positively: monotone.
	if !e.gateMonotone("res", "p") {
		t.Error("p should be monotone")
	}
	// q = member - flag reads flag negatively: not monotone, a monotone move can
	// lower it.
	if e.gateMonotone("res", "q") {
		t.Error("q subtracts flag, should not be monotone")
	}
}
