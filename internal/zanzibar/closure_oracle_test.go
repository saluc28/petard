package zanzibar

import (
	"slices"
	"testing"
	"time"
)

// The brute-force oracle is the correctness backbone of the closure. Closure,
// under E1, reaches its answer by saturation: it applies every available write
// each round until none changes the state, and claims the result is the one
// greatest element. This checks that claim the other way: it explores every
// reachable state, by every sequence of writes, and for every object and name
// takes the highest level the coalition reaches anywhere. If the saturated
// state is the greatest element, the two agree on every question. A fault in
// the search of either shows up here; the move relation they share rests on the
// checker, held to SpiceDB in spicedb/schema_oracle_test.go.
func assertSaturated(t *testing.T, model *Model, wm *WriteModel, caveats CaveatEvaluator, start []Relationship, coalition []Object, reach *Reach) {
	t.Helper()
	if !reach.Exact {
		t.Fatal("assertSaturated is for an exact closure; E1 did not hold")
	}
	e := newEngine(model, wm, caveats, start, coalition, Options{Now: time.Unix(0, 0)})
	explored, err := exploreAll(e)
	if err != nil {
		t.Fatalf("brute force: %v", err)
	}

	var objects []Object
	for _, es := range explored {
		for _, o := range es.objects {
			if !containsObject(objects, o) {
				objects = append(objects, o)
			}
		}
	}
	if !slices.Equal(sortedObjects(reach.Objects), sortedObjects(objects)) {
		t.Errorf("closure and brute force disagree on the coalition:\n closure: %v\n brute:   %v",
			sortedObjects(reach.Objects), sortedObjects(objects))
	}

	for _, query := range queries(model, explored) {
		want := No
		for _, es := range explored {
			checker := NewChecker(model, es.state.list(), caveats, e.opts.now())
			level, err := e.coalitionLevel(checker, query.resource, query.name, es.objects)
			if err != nil {
				t.Fatalf("brute force level of %s#%s: %v", query.resource, query.name, err)
			}
			want = or(want, level)
		}
		got, err := reach.Holds(query.resource, query.name)
		if err != nil {
			t.Fatalf("Holds %s#%s: %v", query.resource, query.name, err)
		}
		if got != want {
			t.Errorf("%s#%s: closure reaches %s, brute force reaches %s", query.resource, query.name, got, want)
		}
	}
}

type query struct {
	resource Object
	name     string
}

// queries is every object seen in the search paired with every permission of
// its type. The exactness E1 claims is about permissions, the access a
// coalition wants: every move only raises them. A relation is not queried, for
// the coalition lowers a negative one on purpose, deleting its own ban among
// them, and that is not a permission going down.
func queries(model *Model, explored []exploredState) []query {
	var objects []Object
	for _, es := range explored {
		for _, r := range es.state.list() {
			for _, o := range []Object{r.Resource, r.Subject.Object} {
				if o.ID != WildcardID && !containsObject(objects, o) {
					objects = append(objects, o)
				}
			}
		}
		for _, o := range es.objects {
			if o.ID != WildcardID && !containsObject(objects, o) {
				objects = append(objects, o)
			}
		}
	}
	var out []query
	for _, o := range objects {
		t := model.Type(o.Type)
		if t == nil {
			continue
		}
		for _, p := range t.Permissions {
			out = append(out, query{resource: o, name: p.Name})
		}
	}
	return out
}

// exploreAll walks the whole reachable state space, not a bounded prefix of it,
// so the oracle sees every state the coalition could ever reach. The space is
// finite, since the objects, relations and subjects are, so the walk ends.
func exploreAll(e *engine) ([]exploredState, error) {
	type node struct {
		state   *stateSet
		objects []Object
	}
	start := node{state: e.start.clone(), objects: slices.Clone(e.coalition)}
	queue := []node{start}
	visited := map[string]bool{signatureOf(start.state, start.objects): true}
	var explored []exploredState

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		explored = append(explored, exploredState(cur))

		checker := NewChecker(e.model, cur.state.list(), e.caveats, e.opts.now())
		moves, err := e.available(checker, cur.state, cur.objects)
		if err != nil {
			return nil, err
		}
		for _, mv := range moves {
			next := node{state: cur.state.clone(), objects: slices.Clone(cur.objects)}
			if !applyMove(next.state, &next.objects, mv) {
				continue
			}
			sig := signatureOf(next.state, next.objects)
			if visited[sig] {
				continue
			}
			visited[sig] = true
			queue = append(queue, next)
		}
	}
	return explored, nil
}

func sortedObjects(objects []Object) []string {
	out := make([]string, 0, len(objects))
	for _, o := range objects {
		out = append(out, o.String())
	}
	slices.Sort(out)
	return out
}
