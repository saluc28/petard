package zanzibar

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
)

// weighedState is a part of a sample the closure runs from, for one object: the tuples
// a check of that object can read, and those of one object of each other type.
type weighedState struct {
	object Object
	tuples []Relationship

	// reads are the objects a check of object can reach. What came along for a witness
	// to link in is not among them, unless a check reads it too.
	reads map[Object]bool

	// shape is the state with the ids of its objects taken out. Two states of one
	// shape raise the same permissions of the same types.
	shape string
}

// weighedStates splits a sample into a state for each object its relationships write
// on, in the order the objects sort.
//
// The search behind an escalation weighs every sequence of writes up to its bound, so
// its cost grows with the power of how many objects a coalition can write on: a store
// of twenty documents behind an open rule does not finish. A check of an object reads
// only the tuples on that object and on what they name, so a state that holds those
// answers it exactly as the whole sample does. No raise it finds is false: every object
// in it carries all its tuples, and a witness writes only on objects in it.
//
// The one object of each other type is what a witness can link in. What this gives up
// is a witness that needs more objects that already exist: another of the object's own
// type, or two of another type.
func weighedStates(s Sample) []weighedState {
	byResource := positionsOf(s.Relationships)
	objects := uniqueObjects(slices.Collect(maps.Keys(byResource)))

	reads := make(map[Object]map[Object]bool, len(objects))
	for _, o := range objects {
		reads[o] = readsOf(o, s.Relationships, byResource)
	}

	// The object of a type to link in is the one that brings the fewest tuples along,
	// and of those the first, so the state does not grow by a hub of the store and two
	// runs pick the same one.
	linked := map[string]Object{}
	for _, o := range objects {
		if current, ok := linked[o.Type]; !ok || len(reads[o]) < len(reads[current]) {
			linked[o.Type] = o
		}
	}

	states := make([]weighedState, 0, len(objects))
	for _, o := range objects {
		include := maps.Clone(reads[o])
		for _, other := range linked {
			if other.Type != o.Type {
				for read := range reads[other] {
					include[read] = true
				}
			}
		}
		var at []int
		for read := range include {
			at = append(at, byResource[read]...)
		}
		slices.Sort(at)
		tuples := make([]Relationship, 0, len(at))
		for _, i := range at {
			tuples = append(tuples, s.Relationships[i])
		}
		states = append(states, weighedState{object: o, tuples: tuples, reads: reads[o], shape: shapeOf(tuples)})
	}
	return states
}

// positionsOf says where the tuples on each object sit, so a part of a sample can be
// taken in the sample's order without walking the whole sample for each object.
func positionsOf(tuples []Relationship) map[Object][]int {
	positions := map[Object][]int{}
	for i, r := range tuples {
		positions[r.Resource] = append(positions[r.Resource], i)
	}
	return positions
}

// readsOf is the objects a check of o can reach: o, and whatever a tuple of one of them
// names as its subject, which is where a userset and an arrow go next.
func readsOf(o Object, tuples []Relationship, byResource map[Object][]int) map[Object]bool {
	seen := map[Object]bool{o: true}
	pending := []Object{o}
	for len(pending) > 0 {
		next := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		for _, i := range byResource[next] {
			r := tuples[i]
			if subject := r.Subject.Object; r.Subject.ID != WildcardID && !seen[subject] {
				seen[subject] = true
				pending = append(pending, subject)
			}
		}
	}
	return seen
}

// shapeOf writes a set of tuples with the ids of its objects replaced by the order they
// first appear in, so that two states that differ in nothing but names read alike. What
// a tuple carries stays, since a caveat and its context decide what a check answers.
func shapeOf(tuples []Relationship) string {
	names := map[Object]string{}
	name := func(o Object) string {
		if o.ID == WildcardID {
			return o.Type + ":*"
		}
		if _, ok := names[o]; !ok {
			names[o] = fmt.Sprintf("%s:%d", o.Type, len(names))
		}
		return names[o]
	}
	var b strings.Builder
	for _, r := range tuples {
		fmt.Fprintf(&b, "%s#%s@%s#%s", name(r.Resource), r.Relation, name(r.Subject.Object), r.Subject.Relation)
		if r.Caveat != nil {
			context, err := json.Marshal(r.Caveat.Context)
			if err != nil {
				// A context that does not marshal reads as nothing else: the state
				// is weighed on its own rather than taken for another.
				context = []byte(fmt.Sprintf("%p", r.Caveat))
			}
			fmt.Fprintf(&b, "[%s %s]", r.Caveat.Name, context)
		}
		if r.Expires != nil {
			fmt.Fprintf(&b, "!%d", r.Expires.UnixNano())
		}
		b.WriteByte('\n')
	}
	return b.String()
}
