package zanzibar

// This file decides, for a scoped proposal search on a model that is not E1,
// whether the search is monotone in effect: whether no relation that breaks E1
// can actually be written or deleted in it. When it cannot, the reachable states
// are monotone, so saturation reaches their greatest element and the candidate
// prune is exact, the same as under E1. This is the common case of the proposal
// pass, where the gate under test does not let the coalition touch the mixed
// relation, and it is what keeps the pass from walking every ordering of the
// commuting writes a position makes available at once.
//
// E1 is a property of the whole model: one writable mixed relation turns it off
// for every search. Reachability is a property of the single search, and most
// searches never reach the mixed relation, so they are exact under saturation
// even though the model is not E1.

// mixedWritableRelations is the relations the coalition can write that are
// mixed, the ones that break E1. A search that can reach none of them is
// monotone in effect.
func (e *engine) mixedWritableRelations() map[relRef]bool {
	writable, _ := writableRelations(e.model, e.wm)
	out := map[relRef]bool{}
	for _, rr := range writable {
		if e.pol.at(relKey{Type: rr.typ, Relation: rr.name}).mixed() {
			out[rr] = true
		}
	}
	return out
}

// effectivelyMonotone reports whether no mixed relation can be written or
// deleted in the search, given the greatest state saturation of the monotone
// moves reaches and the objects it controls there. It is sound by being
// conservative: it returns false whenever a mixed move might become available at
// a state the monotone saturation does not pass through. It is the cheap static
// test and the state test together, split so the caller can skip the saturation
// when the static test already rules the search out.
func (e *engine) effectivelyMonotone(mixed map[relRef]bool, state *stateSet, objects []Object) (bool, error) {
	if !e.mixedRulesAllowMonotone(mixed) {
		return false, nil
	}
	reachable, err := e.mixedMoveAvailable(mixed, state, objects)
	if err != nil {
		return false, err
	}
	return !reachable, nil
}

// mixedRulesAllowMonotone is the cheap, state-free half of the test: whether the
// model and the start even leave room for the search to be monotone. It reads no
// state, so the caller runs it before the saturation and skips that work when it
// fails, which is the common case on a model where a mixed relation is reachable.
//
// It fails when a mixed tuple is in the start state (it could be deleted), when a
// creation writes a mixed relation (its gates are not weighed here), or when a
// rule that writes a mixed relation is open to anyone or gated or
// subject-constrained on a test that is not monotone. A monotone test only rises
// as monotone moves are made, so one that fails at the greatest monotone state
// fails in every reachable state; a test that can fall, through an exclusion,
// might hold at a middle state the saturation does not pass through.
func (e *engine) mixedRulesAllowMonotone(mixed map[relRef]bool) bool {
	for _, r := range e.start.list() {
		if mixed[relRef{typ: r.Resource.Type, name: r.Relation}] {
			return false
		}
	}
	for _, c := range e.wm.Creates {
		for _, cw := range c.Writes {
			if mixed[creationWriteRef(c, cw)] {
				return false
			}
		}
	}
	for _, w := range e.wm.Writes {
		if !mixed[relRef{typ: w.Resource, name: w.Relation}] {
			continue
		}
		if w.Gate.Service != "" {
			continue
		}
		if w.Gate.Anyone || !e.gateMonotone(w.Resource, w.Gate.Holds) {
			return false
		}
		if w.Subject.Holds != "" && !e.gateMonotone(w.Resource, w.Subject.Holds) {
			return false
		}
	}
	return true
}

// mixedMoveAvailable reports whether a mixed move is available at the greatest
// monotone state. With every mixed rule gated monotone (mixedRulesAllowMonotone),
// a mixed move not available there is available in no monotone-reachable state.
func (e *engine) mixedMoveAvailable(mixed map[relRef]bool, state *stateSet, objects []Object) (bool, error) {
	checker := NewChecker(e.model, state.list(), e.caveats, e.opts.now())
	moves, err := e.available(checker, state, objects)
	if err != nil {
		return false, err
	}
	for _, mv := range moves {
		if mixed[relRef{typ: mv.rel.Resource.Type, name: mv.rel.Relation}] {
			return true, nil
		}
	}
	return false, nil
}

// creationWriteRef is the relation a creation write targets: the created type for
// a write to the created object, the named type for a write to an On object. A
// write of no fixed type (the creator) cannot be scoped, so a run that has one is
// never scoped and never reaches here.
func creationWriteRef(c *CreationRule, cw CreationWrite) relRef {
	if cw.Resource == CreatedPlaceholder {
		return relRef{typ: c.Creates, name: cw.Relation}
	}
	return relRef{typ: cw.Resource, name: cw.Relation}
}

// gateMonotone reports whether a gate names a monotone permission or relation:
// its value only rises as the coalition makes monotone moves. A name that reads
// some relation negatively, through an exclusion, or that walks one with an all
// arrow, is not monotone, since a monotone move can then lower it, and the state
// where it holds can be one the monotone saturation does not pass through.
func (e *engine) gateMonotone(typ, name string) bool {
	if name == "" {
		return true
	}
	pol := &polarities{model: e.model, rel: map[relKey]*occurrence{}, visited: map[visitKey]bool{}}
	pol.resolve(typ, name, positive)
	for _, o := range pol.rel {
		if o.neg || o.mixedAll {
			return false
		}
	}
	return true
}
