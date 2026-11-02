package zanzibar

import (
	"cmp"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
)

// weighedState is a part of a sample the closure runs from, for one object: the tuples
// a check of that object can read, and those of what a creation can start from.
type weighedState struct {
	object Object
	tuples []Relationship

	// reads are the objects a check of object can reach. What came along for a creation
	// to start from is not among them, unless a check reads it too.
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
// A write names as its subject only what the coalition holds, and a gate is asked of the
// object written, so a witness can use an object the check does not read only by making
// a creation on it. What creationStarts picks comes along for that. It also says how many
// objects it let another stand for.
func weighedStates(s Sample, wm *WriteModel) ([]weighedState, int) {
	tuples := s.Relationships
	byResource := positionsOf(tuples)
	objects := uniqueObjects(slices.Collect(maps.Keys(byResource)))

	reads := make(map[Object]map[Object]bool, len(objects))
	for _, o := range objects {
		reads[o] = readsOf(o, tuples, byResource)
	}
	held := func(of map[Object]bool) []Relationship {
		var at []int
		for o := range of {
			at = append(at, byResource[o]...)
		}
		slices.Sort(at)
		out := make([]Relationship, 0, len(at))
		for _, i := range at {
			out = append(out, tuples[i])
		}
		return out
	}

	starts, leftOut := creationStarts(s, wm, objects, reads, held)
	states := make([]weighedState, 0, len(objects))
	for _, o := range objects {
		include := maps.Clone(reads[o])
		for _, start := range starts {
			maps.Copy(include, reads[start])
		}
		state := held(include)
		states = append(states, weighedState{object: o, tuples: state, reads: reads[o], shape: shapeOf(state)})
	}
	return states, leftOut
}

// creationStarts picks what a state brings along for a creation to start from: of each
// type a creation is made on, what it takes to hold one object of each shape, the fewest
// tuples first so a state does not grow by a hub of the store. Two objects of one shape
// give one witness under two names, as long as the witness does not rest on what else
// reads them. It says how many objects of those types another stands for.
func creationStarts(s Sample, wm *WriteModel, objects []Object, reads map[Object]map[Object]bool, held func(map[Object]bool) []Relationship) ([]Object, int) {
	types := map[string]bool{}
	if wm != nil {
		for _, rule := range wm.Creates {
			for _, on := range rule.On {
				types[on.Type] = true
			}
		}
	}
	if len(types) == 0 {
		return nil, 0
	}

	bySize := slices.Clone(objects)
	slices.SortStableFunc(bySize, func(a, b Object) int { return cmp.Compare(len(reads[a]), len(reads[b])) })
	shapes := map[string]bool{}
	shapeOfObject := map[Object]string{}
	var starts []Object
	for _, o := range bySize {
		brings := false
		for read := range reads[o] {
			if !types[read.Type] {
				continue
			}
			shape, known := shapeOfObject[read]
			if !known {
				shape = read.Type + "\x00" + shapeOf(held(reads[read]))
				shapeOfObject[read] = shape
			}
			if !shapes[shape] {
				shapes[shape] = true
				brings = true
			}
		}
		if brings {
			starts = append(starts, o)
		}
	}
	return starts, len(shapeOfObject) - len(shapes)
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
