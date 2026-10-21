package zanzibar

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"
)

// Default bounds, measured on the corpus and overridable per run (section 10 of
// the definitions). StartingDepth and CreatedCopies are read by later steps;
// MaxWrites bounds the brute-force search the oracle runs and the search the
// engine falls back to when exactness condition E1 does not hold.
const (
	// DefaultMaxWrites is how many writes the bounded search looks ahead.
	DefaultMaxWrites = 4

	// DefaultStartingDepth is how deep a recursive permission is unfolded when
	// a starting position is generated from the schema.
	DefaultStartingDepth = 2

	// DefaultCreatedCopies is how many objects a creation rule is kept at when
	// its exactness condition E2 does not hold.
	DefaultCreatedCopies = 2
)

// Options tune a closure run. The zero value takes the defaults above.
type Options struct {
	// MaxWrites bounds the look-ahead of the bounded search. Zero takes
	// DefaultMaxWrites.
	MaxWrites int

	// CreatedCopies is how many objects a creation rule is kept at when it
	// writes a negative tuple and E2 does not hold. Zero takes
	// DefaultCreatedCopies.
	CreatedCopies int

	// StartingDepth is how deep a recursive permission is unfolded when a
	// starting position is generated from the schema. Zero takes
	// DefaultStartingDepth.
	StartingDepth int

	// Now is the time expirations are read at. The zero value takes the current
	// time when the run starts.
	Now time.Time
}

func (o Options) maxWrites() int {
	if o.MaxWrites <= 0 {
		return DefaultMaxWrites
	}
	return o.MaxWrites
}

func (o Options) createdCopies() int {
	if o.CreatedCopies <= 0 {
		return DefaultCreatedCopies
	}
	return o.CreatedCopies
}

func (o Options) startingDepth() int {
	if o.StartingDepth <= 0 {
		return DefaultStartingDepth
	}
	return o.StartingDepth
}

func (o Options) now() time.Time {
	if o.Now.IsZero() {
		return time.Now()
	}
	return o.Now
}

// Reach is the result of a closure: the most access the coalition can bring
// about. State is the tuples the coalition can make true, Objects the subjects
// it ends up controlling.
type Reach struct {
	// State is the tuples the coalition can make true. When Exact, it is the
	// fixpoint: the starting state with every write the coalition can make
	// applied. When not Exact, it is the union of the tuples seen across the
	// bounded search, and is informational.
	State []Relationship

	// Objects are the subjects the coalition controls, its own subjects and
	// every object a creation rule let it make.
	Objects []Object

	// Exact is true when exactness conditions E1 and E2 both held, so the
	// reachable states have one greatest element and Holds answers it without a
	// bound or a caveat. The fields below say which condition fell short when it
	// is false.
	Exact bool

	// Bound is how many writes the search looked ahead when a move could lower a
	// permission, zero on the saturation path. Mixed names the relations that
	// broke E1.
	Bound int
	Mixed []MixedRelation

	// CreatedMerged names, by the type they create, the recursive creation rules
	// whose objects were merged to one each. The result is sound but may report
	// a raise only a merged object allows.
	CreatedMerged []string

	// CreatedCopies is how many objects a creation that writes a negative tuple
	// was kept at, zero when none did; the result is then exact up to that many
	// created objects.
	CreatedCopies int

	engine   *engine
	explored []exploredState
}

// exploredState is one state the search reached, with the coalition it held
// there. Under E1 there is one, the fixpoint; without E1 there is one per state
// the bounded search reached.
type exploredState struct {
	state   *stateSet
	objects []Object
}

// Holds is the most a coalition subject reaches for a permission or relation on
// an object. Under E1 it reads the one greatest state; without E1 it is the
// highest over every state the bounded search reached, so a raise a mix of
// writes opens is still found, within the bound.
func (r *Reach) Holds(resource Object, name string) (Level, error) {
	best := No
	for _, es := range r.explored {
		checker := NewChecker(r.engine.model, es.state.list(), r.engine.caveats, r.engine.opts.now())
		level, err := r.engine.coalitionLevel(checker, resource, name, es.objects)
		if err != nil {
			return No, err
		}
		best = or(best, level)
		if best == Yes {
			break
		}
	}
	return best, nil
}

// Closure computes the most access a coalition can bring about from a starting
// state, under a write model.
//
// When exactness condition E1 holds, every write the coalition would make only
// raises a permission: it adds a relation only where the relation occurs
// positively and deletes one only where it occurs negatively. The reachable
// states then have one greatest element, and the closure saturates to it,
// adding and removing every such tuple while any change is still reachable. The
// order of the writes does not change the result.
//
// When E1 fails, a relation the coalition can write is mixed, so no single
// state dominates. The closure then searches every sequence of up to Bound
// writes and reports the raises found as exact up to that bound, with Mixed
// naming the relations that forced it.
//
// The coalition is its starting subjects together with every object a creation
// rule lets it make. A write is available when the rule's gate holds for one of
// those subjects on the resource and the subject written or removed is one the
// coalition can name. Service gates are never held by the coalition, and a
// relation with no rule is not writable, so the model stays closed: a rule left
// out is a missed write, never an invented one.
func Closure(model *Model, wm *WriteModel, caveats CaveatEvaluator, start []Relationship, coalition []Object, opts Options) (*Reach, error) {
	e := newEngine(model, wm, caveats, start, coalition, opts)

	e1ok, mixed := CheckE1(model, wm)
	e2ok, e2fail := CheckE2(model, wm)
	merged, negative := splitE2(e2fail)

	// Saturation reaches the one greatest element only while every move raises a
	// permission. A mixed relation (E1) or a creation that writes a negative
	// tuple (E2) can lower one, and then no single state dominates.
	if e1ok && !negative {
		state, objects, err := e.saturate()
		if err != nil {
			return nil, err
		}
		return &Reach{
			State:         state.list(),
			Objects:       objects,
			Exact:         e1ok && e2ok,
			CreatedMerged: merged,
			engine:        e,
			explored:      []exploredState{{state: state, objects: objects}},
		}, nil
	}

	bound := e.opts.maxWrites()
	explored, err := e.explore(bound)
	if err != nil {
		return nil, err
	}
	union := e.start.clone()
	var unionObjects []Object
	for _, es := range explored {
		for _, r := range es.state.list() {
			union.add(r)
		}
		for _, o := range es.objects {
			if !containsObject(unionObjects, o) {
				unionObjects = append(unionObjects, o)
			}
		}
	}
	copies := 0
	if negative {
		copies = e.opts.createdCopies()
	}
	return &Reach{
		State:         union.list(),
		Objects:       unionObjects,
		Exact:         false,
		Bound:         bound,
		Mixed:         mixed,
		CreatedMerged: merged,
		CreatedCopies: copies,
		engine:        e,
		explored:      explored,
	}, nil
}

// splitE2 separates the recursive failures, whose rules are merged, from the
// negative-write failures, which force a bounded search. It returns the merged
// rules by created type and whether any rule writes a negative tuple.
func splitE2(failures []E2Failure) (merged []string, negative bool) {
	for _, f := range failures {
		if f.Reason == "recursive" {
			merged = append(merged, f.Creates)
		} else {
			negative = true
		}
	}
	return merged, negative
}

// saturate applies every available write each round until none changes the
// state, which under E1 is the one greatest element the coalition can reach.
func (e *engine) saturate() (*stateSet, []Object, error) {
	state := e.start.clone()
	objects := slices.Clone(e.coalition)

	for {
		checker := NewChecker(e.model, state.list(), e.caveats, e.opts.now())
		moves, err := e.available(checker, state, objects)
		if err != nil {
			return nil, nil, err
		}
		grew := false
		for _, mv := range moves {
			if applyMove(state, &objects, mv) {
				grew = true
			}
		}
		if !grew {
			break
		}
	}
	return state, objects, nil
}

// explore walks every sequence of up to maxMoves writes and returns each state
// it reaches. It is the bounded search E1's failure falls back to: no single
// state dominates, so the raises are read across all of them, up to the bound.
func (e *engine) explore(maxMoves int) ([]exploredState, error) {
	type node struct {
		state   *stateSet
		objects []Object
		depth   int
	}
	start := node{state: e.start.clone(), objects: slices.Clone(e.coalition)}
	queue := []node{start}
	visited := map[string]bool{signatureOf(start.state, start.objects): true}
	var explored []exploredState

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		explored = append(explored, exploredState{state: cur.state, objects: cur.objects})
		if cur.depth >= maxMoves {
			continue
		}
		checker := NewChecker(e.model, cur.state.list(), e.caveats, e.opts.now())
		moves, err := e.available(checker, cur.state, cur.objects)
		if err != nil {
			return nil, err
		}
		for _, mv := range moves {
			next := node{state: cur.state.clone(), objects: slices.Clone(cur.objects), depth: cur.depth + 1}
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

// applyMove changes a state by one move and reports whether anything changed.
func applyMove(state *stateSet, objects *[]Object, mv move) bool {
	changed := false
	switch {
	case mv.del:
		changed = state.remove(mv.rel)
	case mv.writesTuple():
		changed = state.add(mv.rel)
	}
	if mv.creates != nil && !containsObject(*objects, mv.created) {
		*objects = append(*objects, mv.created)
		changed = true
	}
	return changed
}

// engine holds what a closure and its brute-force oracle both read. The two
// share these primitives, the move set and how a move changes a state, and
// differ only in how they search: the closure saturates, the oracle in
// closure_oracle_test.go walks every sequence of moves. A fault in the search
// shows up as a disagreement; a fault in a primitive is caught against SpiceDB,
// which the checker is held to in spicedb/schema_oracle_test.go.
type engine struct {
	model     *Model
	wm        *WriteModel
	caveats   CaveatEvaluator
	start     *stateSet
	coalition []Object
	opts      Options
	pol       *polarities
	e2modes   []creationMode
}

func newEngine(model *Model, wm *WriteModel, caveats CaveatEvaluator, start []Relationship, coalition []Object, opts Options) *engine {
	s := newStateSet()
	for _, r := range start {
		s.add(r)
	}
	pol := analyzePolarities(model, wm)
	modes, _ := e2plan(model, wm, pol, opts.createdCopies())
	return &engine{
		model:     model,
		wm:        wm,
		caveats:   caveats,
		start:     s,
		coalition: slices.Clone(coalition),
		opts:      opts,
		pol:       pol,
		e2modes:   modes,
	}
}

// move is one write the coalition can make: a tuple to add, with the rule that
// allowed it and the subject that made it, or a creation that also brings a new
// object into the coalition.
type move struct {
	rel     Relationship
	rule    *WriteRule
	creates *CreationRule
	created Object
	writer  Subject

	// del is true when the move removes rel rather than adding it, the move
	// that lifts a deny by deleting a tuple that occurs negatively.
	del bool
}

// writesTuple reports whether a move adds a tuple. A pure creation move brings
// an object into the coalition and writes none.
func (m move) writesTuple() bool { return m.rel.Relation != "" && !m.del }

// available is every move the coalition can make in a state, over the objects
// it controls. It is the shared primitive: the closure applies all of them each
// round, the oracle applies them one at a time.
//
// A relation is added only where it occurs positively and deleted only where it
// occurs negatively, the two directions that raise a permission; the other
// direction only lowers one, so it is never a move. A relation that occurs in
// both, which E1 rules out of an exact run, offers both.
func (e *engine) available(checker *Checker, state *stateSet, objects []Object) ([]move, error) {
	var moves []move
	domain := e.domain(state, objects)
	tuples := state.list()

	for _, rule := range e.wm.Writes {
		relation := e.relation(rule.Resource, rule.Relation)
		if relation == nil {
			continue
		}
		occ := e.pol.at(relKey{Type: rule.Resource, Relation: rule.Relation})
		canAdd := writes(rule.Operations) && occ.pos
		canDelete := deletes(rule.Operations) && (occ.neg || occ.mixedAll)
		if !canAdd && !canDelete {
			continue
		}
		for _, resource := range domain[rule.Resource] {
			held, err := e.gateHolds(checker, rule.Gate, resource, objects)
			if err != nil {
				return nil, err
			}
			if !held {
				continue
			}
			if canAdd {
				for _, writer := range objects {
					for _, subject := range e.subjects(rule, relation, writer, objects) {
						rel := Relationship{Resource: resource, Relation: rule.Relation, Subject: subject}
						if !state.has(rel) {
							moves = append(moves, move{rel: rel, rule: rule, writer: Subject{Object: writer}})
						}
					}
				}
			}
			if canDelete {
				for _, rel := range tuples {
					if rel.Resource == resource && rel.Relation == rule.Relation && mayDelete(rule.Subject, rel.Subject, objects) {
						moves = append(moves, move{rel: rel, rule: rule, del: true})
					}
				}
			}
		}
	}

	creationMoves, err := e.creations(checker, state, objects, domain)
	if err != nil {
		return nil, err
	}
	return append(moves, creationMoves...), nil
}

// mayDelete says whether the coalition can delete a tuple of the given subject
// under a rule. The subject has to be one the coalition controls, since
// deleting a tuple that denies somebody else raises nothing for the coalition,
// and the rule has to allow that subject form. A holds constraint on the
// subject is left to a later step, so it deletes nothing rather than something
// the coalition may not reach.
func mayDelete(spec SubjectSpec, s Subject, objects []Object) bool {
	controllable := s.ID == WildcardID || containsObject(objects, s.Object)
	if !controllable {
		return false
	}
	switch {
	case spec.Any:
		return true
	case spec.Self:
		return s.Relation == "" && containsObject(objects, s.Object)
	case spec.Holds != "":
		return false
	case len(spec.Types) > 0:
		return slices.Contains(spec.Types, subjectForm(s))
	}
	return false
}

// subjectForm names a stored subject the way a write rule names an allowed one:
// user, team#member or user:*.
func subjectForm(s Subject) string {
	switch {
	case s.ID == WildcardID:
		return s.Type + ":*"
	case s.Relation != "":
		return s.Type + "#" + s.Relation
	default:
		return s.Type
	}
}

// creations is every creation move the coalition can make: one object per
// creation rule and per choice of its On objects, with the tuples the rule
// writes. One object per such choice is the exact materialization while
// exactness condition E2 holds. A recursive rule is merged to one object per
// rule, and a rule that writes a negative tuple is kept at k objects per choice,
// the two fallbacks E2 names.
func (e *engine) creations(checker *Checker, state *stateSet, objects []Object, domain map[string][]Object) ([]move, error) {
	var moves []move
	for i, rule := range e.wm.Creates {
		mode := e.e2modes[i]
		combos, err := e.onCombos(checker, rule, objects, domain)
		if err != nil {
			return nil, err
		}
		for _, combo := range combos {
			for n := range mode.copies {
				created := Object{Type: rule.Creates, ID: createdID(i, combo.sig, n, mode.merged)}
				added := !containsObject(objects, created)
				if added {
					// The creation itself brings the object into the coalition.
					moves = append(moves, move{creates: rule, created: created})
				}
				// The tuples the rule writes are moves of their own, so a rule
				// with several writes adds each. They are offered even when the
				// object is already in the coalition, since a merged object
				// gathers the writes of every choice that folds into it.
				for _, w := range rule.Writes {
					rel, ok := e.fillCreationWrite(w, created, combo.ons)
					if !ok || state.has(rel) {
						continue
					}
					moves = append(moves, move{rel: rel, creates: rule, created: created})
				}
			}
		}
	}
	return moves, nil
}

// onCombo is one choice of the objects a creation is made in, with a signature
// that names the created object so that two choices make two objects.
type onCombo struct {
	ons map[string]Object
	sig string
}

// onCombos is every choice of On objects a creation can be made on: for each On
// type, the objects of that type the creation's gate holds on, combined across
// the On types. A rule with no On has one choice when its gate is anyone, and
// none otherwise. A gate that holds a permission needs an On object to hold on,
// so a rule with no On and such a gate makes nothing.
func (e *engine) onCombos(checker *Checker, rule *CreationRule, objects []Object, domain map[string][]Object) ([]onCombo, error) {
	if len(rule.On) == 0 {
		if rule.Gate.Anyone {
			return []onCombo{{}}, nil
		}
		return nil, nil
	}
	combos := []onCombo{{ons: map[string]Object{}}}
	for _, on := range rule.On {
		var candidates []Object
		for _, candidate := range domain[on.Type] {
			held, err := e.gateHolds(checker, on.Gate, candidate, objects)
			if err != nil {
				return nil, err
			}
			if held {
				candidates = append(candidates, candidate)
			}
		}
		if len(candidates) == 0 {
			return nil, nil
		}
		var next []onCombo
		for _, combo := range combos {
			for _, candidate := range candidates {
				ons := maps.Clone(combo.ons)
				ons[on.Type] = candidate
				next = append(next, onCombo{ons: ons, sig: joinSig(combo.sig, candidate)})
			}
		}
		combos = next
	}
	return combos, nil
}

// fillCreationWrite turns a creation write into a tuple, its placeholders filled
// with the created object, the creator and the On objects. The creator is the
// coalition, written as its first subject.
func (e *engine) fillCreationWrite(w CreationWrite, created Object, ons map[string]Object) (Relationship, bool) {
	resource, ok := e.fillObject(w.Resource, created, ons)
	if !ok {
		return Relationship{}, false
	}
	subject, ok := e.fillSubject(w.Subject, created, ons)
	if !ok {
		return Relationship{}, false
	}
	return Relationship{Resource: resource, Relation: w.Relation, Subject: subject}, true
}

func (e *engine) fillObject(ref string, created Object, ons map[string]Object) (Object, bool) {
	switch ref {
	case CreatedPlaceholder:
		return created, true
	case CreatorPlaceholder:
		if len(e.coalition) == 0 {
			return Object{}, false
		}
		return e.coalition[0], true
	}
	if on, ok := ons[ref]; ok {
		return on, true
	}
	return Object{}, false
}

func (e *engine) fillSubject(ref string, created Object, ons map[string]Object) (Subject, bool) {
	obj, ok := e.fillObject(ref, created, ons)
	if !ok {
		return Subject{}, false
	}
	return Subject{Object: obj}, true
}

// gateHolds says whether a gate holds for the coalition on a resource. A service
// gate never holds, since no end user drives a service. A held gate holds when
// a coalition subject reaches the permission at all, Conditional included: the
// coalition may be able to satisfy the caveat, and reading a conditional gate as
// closed would miss a raise (section 5.4, precision only).
func (e *engine) gateHolds(checker *Checker, gate Gate, resource Object, objects []Object) (bool, error) {
	if gate.Service != "" {
		return false, nil
	}
	if gate.Anyone {
		return true, nil
	}
	level, err := e.coalitionLevel(checker, resource, gate.Holds, objects)
	if err != nil {
		return false, err
	}
	return level >= Conditional, nil
}

// coalitionLevel is the highest level any coalition subject reaches for a name
// on a resource, over the objects the coalition controls at the time. A check
// that names what the model does not declare is an error the caller sees; a
// wildcard subject is never asked, since the coalition holds access through its
// own subjects.
func (e *engine) coalitionLevel(checker *Checker, resource Object, name string, objects []Object) (Level, error) {
	best := No
	for _, o := range objects {
		if o.ID == WildcardID {
			continue
		}
		result, err := checker.Check(resource, name, Subject{Object: o}, nil)
		if err != nil {
			return No, err
		}
		best = or(best, result.Level)
		if best == Yes {
			break
		}
	}
	return best, nil
}

// subjects is every subject the coalition can write for a rule on a relation,
// over the objects it controls. A subject the coalition cannot name is left
// out, so a write the closure makes is always one the coalition could make.
func (e *engine) subjects(rule *WriteRule, relation *Relation, writer Object, objects []Object) []Subject {
	var out []Subject
	for _, allowed := range relation.Allowed {
		// A wildcard is a separate axis from the subject list: the dedicated
		// wildcard flag allows it, not naming its type among the subjects.
		if allowed.Wildcard {
			if rule.Wildcard {
				appendSubject(&out, Subject{Object: Object{Type: allowed.Type, ID: WildcardID}})
			}
			continue
		}
		if !subjectAllowed(rule.Subject, allowed, writer) {
			continue
		}
		switch allowed.Relation {
		case "":
			// subjectAllowed has already held a self subject to the writer's
			// own type, so the writer is a subject of this form.
			if rule.Subject.Self {
				appendSubject(&out, Subject{Object: writer})
				continue
			}
			for _, o := range objects {
				if o.Type == allowed.Type {
					appendSubject(&out, Subject{Object: o})
				}
			}
		default:
			// A userset subject: subjectAllowed never lets self reach here.
			for _, o := range objects {
				if o.Type == allowed.Type {
					appendSubject(&out, Subject{Object: o, Relation: allowed.Relation})
				}
			}
		}
	}
	return out
}

// subjectAllowed filters an allowed subject form against what the rule lets the
// writer write. Self and a holds constraint keep only the forms this step
// handles; a holds constraint on the subject is left to a later step, so it
// produces no subject rather than one that may not hold the permission.
func subjectAllowed(spec SubjectSpec, allowed Allowed, writer Object) bool {
	switch {
	case spec.Any:
		return true
	case spec.Self:
		return allowed.Relation == "" && !allowed.Wildcard && allowed.Type == writer.Type
	case spec.Holds != "":
		return false
	case len(spec.Types) > 0:
		return slices.Contains(spec.Types, allowedName(allowed))
	}
	return false
}

func allowedName(a Allowed) string {
	if a.Wildcard {
		return a.Type + ":*"
	}
	if a.Relation != "" {
		return a.Type + "#" + a.Relation
	}
	return a.Type
}

// domain is every object the coalition may write on or name, by type: the
// objects of the state and the objects the coalition controls, which already
// hold every object a creation rule has made, since a creation puts its object
// into the coalition. Wildcards are subjects, not objects, so they are not
// here.
func (e *engine) domain(state *stateSet, objects []Object) map[string][]Object {
	byType := map[string][]Object{}
	add := func(o Object) {
		if o.ID == WildcardID {
			return
		}
		if !slices.Contains(byType[o.Type], o) {
			byType[o.Type] = append(byType[o.Type], o)
		}
	}
	for _, r := range state.list() {
		add(r.Resource)
		add(r.Subject.Object)
	}
	for _, o := range objects {
		add(o)
	}
	return byType
}

func (e *engine) relation(typeName, relation string) *Relation {
	t := e.model.Type(typeName)
	if t == nil {
		return nil
	}
	return t.Relation(relation)
}

// writes reports whether a set of operations adds a tuple, create or touch.
func writes(ops []Operation) bool {
	return slices.Contains(ops, Create) || slices.Contains(ops, Touch)
}

func containsObject(objects []Object, o Object) bool { return slices.Contains(objects, o) }

func appendSubject(out *[]Subject, s Subject) {
	if !slices.Contains(*out, s) {
		*out = append(*out, s)
	}
}

// createdID is the identifier of an object a creation rule makes. A merged
// rule has one object whatever the choice, so the signature and copy are left
// off; otherwise the choice of On objects and the copy number keep two objects
// of the same rule apart.
func createdID(ruleIndex int, comboSig string, copy int, merged bool) string {
	if merged {
		return fmt.Sprintf("created-%d", ruleIndex)
	}
	id := fmt.Sprintf("created-%d", ruleIndex)
	if comboSig != "" {
		id += "-" + comboSig
	}
	if copy > 0 {
		id += fmt.Sprintf("-copy%d", copy)
	}
	return id
}

// joinSig extends a choice signature with one more object, its colon turned to
// a dash so the signature stays a plain identifier.
func joinSig(sig string, o Object) string {
	part := o.Type + "-" + o.ID
	if sig == "" {
		return part
	}
	return sig + "_" + part
}

// stateSet is a set of relationships with a stable order, keyed so that the
// same tuple is not held twice.
type stateSet struct {
	order []Relationship
	keys  map[string]bool
}

func newStateSet() *stateSet {
	return &stateSet{keys: map[string]bool{}}
}

// add puts a relationship in the set and reports whether it was new.
func (s *stateSet) add(r Relationship) bool {
	key := tupleKey(r)
	if s.keys[key] {
		return false
	}
	s.keys[key] = true
	s.order = append(s.order, r)
	return true
}

func (s *stateSet) has(r Relationship) bool { return s.keys[tupleKey(r)] }

// remove takes a relationship out of the set and reports whether it was there.
func (s *stateSet) remove(r Relationship) bool {
	key := tupleKey(r)
	if !s.keys[key] {
		return false
	}
	delete(s.keys, key)
	s.order = slices.DeleteFunc(s.order, func(x Relationship) bool { return tupleKey(x) == key })
	return true
}

func (s *stateSet) list() []Relationship { return slices.Clone(s.order) }

func (s *stateSet) clone() *stateSet {
	c := &stateSet{order: slices.Clone(s.order), keys: make(map[string]bool, len(s.keys))}
	for k, v := range s.keys {
		c.keys[k] = v
	}
	return c
}

// tupleKey identifies a tuple for the set. It carries the caveat name and the
// expiration flag, not the caveat context: a tuple the coalition writes with a
// writer-filled caveat is the same move whatever satisfiable value it chooses.
func tupleKey(r Relationship) string {
	key := r.Resource.String() + "#" + r.Relation + "@" + r.Subject.String()
	if r.Caveat != nil {
		key += "[" + r.Caveat.Name + "]"
	}
	if r.Expires != nil {
		key += "!exp"
	}
	return key
}

// signatureOf identifies a state and a coalition, so that two sequences of
// writes that reach the same place are explored once. It sorts both, since the
// set is what matters and not the order writes happened to arrive in.
func signatureOf(state *stateSet, objects []Object) string {
	keys := make([]string, 0, len(state.order))
	for _, r := range state.order {
		keys = append(keys, tupleKey(r))
	}
	slices.Sort(keys)
	names := make([]string, 0, len(objects))
	for _, o := range objects {
		names = append(names, o.String())
	}
	slices.Sort(names)
	return strings.Join(keys, ",") + "|" + strings.Join(names, ",")
}
