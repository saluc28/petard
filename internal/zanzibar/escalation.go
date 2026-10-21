package zanzibar

import "slices"

// WriteStep is one write of a witness: the tuple written or deleted, the rule
// or creation that allowed it, and the coalition subject that made it. The
// steps in order are the attack path, and the last is the decisive write, the
// one after which the permission rises.
type WriteStep struct {
	Relationship Relationship
	Delete       bool

	// Rule is the write rule that allowed the step, nil when the step is a
	// creation or one of the tuples a creation writes.
	Rule *WriteRule

	// Creation is the creation rule, set when the step makes an object or writes
	// one of its tuples.
	Creation *CreationRule

	// Writer is the coalition subject that made a rule write.
	Writer Subject
}

// Escalation is a permission a coalition can raise on an object that existed
// before it started, with the shortest witness that does it. It is what the
// findings of the engine are built on: the decisive write classifies the
// finding (section 7.1 of the definitions).
type Escalation struct {
	Object     Object
	Permission string
	Before     Level
	After      Level

	// Writes is the shortest witness, the writes in order, the last of which is
	// the decisive write.
	Writes []WriteStep

	// moves is the same witness as the moves the closure applies, kept so the
	// state before a write can be replayed exactly when a finding needs it.
	moves []move
}

// Decisive is the write after which the permission rose, the last of the
// witness. It is only defined when Writes is not empty.
func (e Escalation) Decisive() (WriteStep, bool) {
	if len(e.Writes) == 0 {
		return WriteStep{}, false
	}
	return e.Writes[len(e.Writes)-1], true
}

// Escalations finds every permission a coalition can raise on a pre-existing
// object, from a starting state under a write model, each with the shortest
// witness that produces the raise. A raise reachable by writes of different
// kinds yields one escalation per decisive write, so a later pass can classify
// each by that write (section 7.1 of the definitions).
//
// The search is breadth first up to the write bound, so every witness is a
// shortest one and a raise is found with the fewest writes that reach it. A
// witness made only of writes a rule marks intended, joining a public group
// among them, is a raise the write model allows by design and is left out.
func Escalations(model *Model, wm *WriteModel, caveats CaveatEvaluator, start []Relationship, coalition []Object, opts Options) ([]Escalation, error) {
	e := newEngine(model, wm, caveats, start, coalition, opts)

	targets := e.preExistingTargets()
	before := make(map[string]Level, len(targets))
	checker0 := NewChecker(model, start, caveats, opts.now())
	raised := make(map[string]target, len(targets))
	for _, q := range targets {
		lvl, err := e.coalitionLevel(checker0, q.resource, q.name, coalition)
		if err != nil {
			return nil, err
		}
		before[q.key()] = lvl
		raised[q.key()] = q
	}
	return e.witnesses(raised, before, opts.maxWrites())
}

// witnesses walks the states reachable in up to bound writes and returns, for
// each raised target and each distinct decisive write, the shortest witness.
// Breadth first, so the first path to reach a state is a shortest one.
func (e *engine) witnesses(raised map[string]target, before map[string]Level, bound int) ([]Escalation, error) {
	type node struct {
		state   *stateSet
		objects []Object
		path    []move
	}
	start := node{state: e.start.clone(), objects: slices.Clone(e.coalition)}
	queue := []node{start}
	visited := map[string]bool{signatureOf(start.state, start.objects): true}
	seen := map[string]bool{}
	var out []Escalation

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		checker := NewChecker(e.model, cur.state.list(), e.caveats, e.opts.now())

		if len(cur.path) > 0 {
			decisive := cur.path[len(cur.path)-1]
			for key, q := range raised {
				sig := key + "|" + decisiveSig(decisive)
				if seen[sig] {
					continue
				}
				level, err := e.coalitionLevel(checker, q.resource, q.name, cur.objects)
				if err != nil {
					return nil, err
				}
				if level <= before[key] {
					continue
				}
				seen[sig] = true
				if allIntended(cur.path) {
					continue
				}
				out = append(out, Escalation{
					Object:     q.resource,
					Permission: q.name,
					Before:     before[key],
					After:      level,
					Writes:     steps(cur.path),
					moves:      slices.Clone(cur.path),
				})
			}
		}

		if len(cur.path) >= bound {
			continue
		}
		moves, err := e.available(checker, cur.state, cur.objects)
		if err != nil {
			return nil, err
		}
		for _, mv := range moves {
			next := node{state: cur.state.clone(), objects: slices.Clone(cur.objects), path: append(slices.Clone(cur.path), mv)}
			if !applyMove(next.state, &next.objects, mv) {
				continue
			}
			sign := signatureOf(next.state, next.objects)
			if visited[sign] {
				continue
			}
			visited[sign] = true
			queue = append(queue, next)
		}
	}
	return out, nil
}

// target is an object and a permission on it, the question whether the coalition
// can raise it.
type target struct {
	resource Object
	name     string
}

func (q target) key() string { return q.resource.String() + "#" + q.name }

// preExistingTargets is every object of the starting state the coalition did
// not create, paired with each permission of its type. These are the objects a
// raise is measured on: owning or using what the coalition itself made is not a
// raise (section 1 of the definitions).
func (e *engine) preExistingTargets() []target {
	var objects []Object
	for _, r := range e.start.list() {
		for _, o := range []Object{r.Resource, r.Subject.Object} {
			if o.ID != WildcardID && !containsObject(e.coalition, o) && !containsObject(objects, o) {
				objects = append(objects, o)
			}
		}
	}
	var out []target
	for _, o := range objects {
		t := e.model.Type(o.Type)
		if t == nil {
			continue
		}
		for _, p := range t.Permissions {
			out = append(out, target{resource: o, name: p.Name})
		}
	}
	return out
}

// steps turns a path of moves into the public witness.
func steps(path []move) []WriteStep {
	out := make([]WriteStep, 0, len(path))
	for _, mv := range path {
		out = append(out, WriteStep{
			Relationship: mv.rel,
			Delete:       mv.del,
			Rule:         mv.rule,
			Creation:     mv.creates,
			Writer:       mv.writer,
		})
	}
	return out
}

// decisiveSig distinguishes the decisive writes of two witnesses of the same
// target, so that a raise reachable by different writes is recorded once per
// write rather than once overall. The writer is part of it: the same tuple
// written for oneself and written for another coalition subject are different
// decisive writes, one a self-write and the other a delegation.
func decisiveSig(mv move) string {
	switch {
	case mv.creates != nil && !mv.writesTuple():
		return "create:" + mv.created.String()
	case mv.del:
		return "del:" + tupleKey(mv.rel) + "@by:" + mv.writer.String()
	default:
		return "add:" + tupleKey(mv.rel) + "@by:" + mv.writer.String()
	}
}

// allIntended reports whether every write of a path is one a rule marks intended,
// in which case the raise is one the write model allows by design.
func allIntended(path []move) bool {
	for _, mv := range path {
		switch {
		case mv.rule != nil:
			if !mv.rule.Intended {
				return false
			}
		case mv.creates != nil:
			if !mv.creates.Intended {
				return false
			}
		default:
			return false
		}
	}
	return len(path) > 0
}
