package zanzibar

import (
	"slices"
	"strings"
	"testing"
	"time"
)

// The brute-force oracle is the correctness backbone of the closure. Closure
// reaches its answer by saturation, adding every available write each round
// until none is new. This walks the other way: it explores every sequence of
// single writes, up to a bound large enough to saturate the small schemas it
// runs on, and takes the union of the states it reaches. On the additive moves
// of this step the two must give the same tuples and the same coalition, and a
// fault in the search of either shows up here as a disagreement. The move
// relation the two share rests on the checker, which is held to SpiceDB in
// spicedb/schema_oracle_test.go.
func assertSaturated(t *testing.T, model *Model, wm *WriteModel, caveats CaveatEvaluator, start []Relationship, coalition []Object, reach *Reach) {
	t.Helper()
	e := newEngine(model, wm, caveats, start, coalition, Options{Now: time.Unix(0, 0)})
	// The diameter is bounded by the number of additions: every move adds a
	// tuple or an object, so this many moves reach anything reachable.
	bound := (len(reach.State) - len(start)) + (len(reach.Objects) - len(coalition)) + 1
	tuples, objects := bruteForce(t, e, bound)

	if !slices.Equal(sortedKeys(reach.State), sortedKeys(tuples.list())) {
		t.Errorf("closure and brute force disagree on tuples:\n closure: %v\n brute:   %v",
			sortedKeys(reach.State), sortedKeys(tuples.list()))
	}
	if !slices.Equal(sortedObjects(reach.Objects), sortedObjects(objects)) {
		t.Errorf("closure and brute force disagree on the coalition:\n closure: %v\n brute:   %v",
			sortedObjects(reach.Objects), sortedObjects(objects))
	}
}

// bruteForce explores every sequence of up to maxMoves single writes and
// returns the union of the tuples and of the coalition objects it reaches.
func bruteForce(t *testing.T, e *engine, maxMoves int) (*stateSet, []Object) {
	t.Helper()
	type node struct {
		state   *stateSet
		objects []Object
		depth   int
	}

	all := e.start.clone()
	allObjects := slices.Clone(e.coalition)

	visited := map[string]bool{}
	start := node{state: e.start.clone(), objects: slices.Clone(e.coalition)}
	queue := []node{start}
	visited[signature(start.state, start.objects)] = true

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, r := range cur.state.list() {
			all.add(r)
		}
		for _, o := range cur.objects {
			if !containsObject(allObjects, o) {
				allObjects = append(allObjects, o)
			}
		}
		if cur.depth >= maxMoves {
			continue
		}

		checker := NewChecker(e.model, cur.state.list(), e.caveats, e.opts.now())
		moves, err := e.available(checker, cur.state, cur.objects)
		if err != nil {
			t.Fatalf("available moves: %v", err)
		}
		for _, mv := range moves {
			next := node{state: cur.state.clone(), objects: slices.Clone(cur.objects), depth: cur.depth + 1}
			changed := false
			if mv.writesTuple() && next.state.add(mv.rel) {
				changed = true
			}
			if mv.creates != nil && !containsObject(next.objects, mv.created) {
				next.objects = append(next.objects, mv.created)
				changed = true
			}
			if !changed {
				continue
			}
			sig := signature(next.state, next.objects)
			if visited[sig] {
				continue
			}
			visited[sig] = true
			queue = append(queue, next)
		}
	}
	return all, allObjects
}

// signature identifies a state and a coalition for the visited set, so that two
// orderings that reach the same place are explored once.
func signature(state *stateSet, objects []Object) string {
	return strings.Join(sortedKeys(state.list()), ",") + "|" + strings.Join(sortedObjects(objects), ",")
}

func sortedKeys(rels []Relationship) []string {
	keys := keysOf(rels)
	slices.Sort(keys)
	return keys
}

func sortedObjects(objects []Object) []string {
	out := make([]string, 0, len(objects))
	for _, o := range objects {
		out = append(out, o.String())
	}
	slices.Sort(out)
	return out
}
