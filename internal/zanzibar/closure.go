package zanzibar

import (
	"fmt"
	"slices"
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

	// Now is the time expirations are read at. The zero value takes the current
	// time when the run starts.
	Now time.Time
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
	// State is the tuples of the reachable fixpoint, the starting state with
	// every tuple the coalition can write added.
	State []Relationship

	// Objects are the subjects the coalition controls at the fixpoint, its own
	// subject and every object a creation rule let it make.
	Objects []Object

	engine *engine
}

// Holds is the level the coalition reaches for a permission or relation on an
// object: the highest any of its subjects reaches, over the fixpoint state.
func (r *Reach) Holds(resource Object, name string) (Level, error) {
	checker := NewChecker(r.engine.model, r.State, r.engine.caveats, r.engine.opts.now())
	return r.engine.coalitionLevel(checker, resource, name, r.Objects)
}

// Closure computes the most access a coalition can bring about from a starting
// state, under a write model. It adds every tuple the coalition can write while
// any new one is still reachable, which is the least fixpoint of the write
// rules: on the additive moves of this step every move only grants, so the
// order writes are made in does not change the fixpoint, and the saturation
// below reaches it.
//
// The coalition is its starting subjects together with every object a creation
// rule lets it make. A write is available when the rule's gate holds for one of
// those subjects on the resource and the subject written is one the coalition
// can name. Service gates are never held by the coalition, and a relation with
// no rule is not writable, so the model stays closed: a rule left out is a
// missed write, never an invented one.
func Closure(model *Model, wm *WriteModel, caveats CaveatEvaluator, start []Relationship, coalition []Object, opts Options) (*Reach, error) {
	e := newEngine(model, wm, caveats, start, coalition, opts)
	state := e.start.clone()
	objects := slices.Clone(e.coalition)

	for {
		checker := NewChecker(e.model, state.list(), e.caveats, e.opts.now())
		moves, err := e.available(checker, state, objects)
		if err != nil {
			return nil, err
		}
		grew := false
		for _, mv := range moves {
			if mv.writesTuple() && state.add(mv.rel) {
				grew = true
			}
			if mv.creates != nil && !containsObject(objects, mv.created) {
				objects = append(objects, mv.created)
				grew = true
			}
		}
		if !grew {
			break
		}
	}

	return &Reach{State: state.list(), Objects: objects, engine: e}, nil
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
}

func newEngine(model *Model, wm *WriteModel, caveats CaveatEvaluator, start []Relationship, coalition []Object, opts Options) *engine {
	s := newStateSet()
	for _, r := range start {
		s.add(r)
	}
	return &engine{
		model:     model,
		wm:        wm,
		caveats:   caveats,
		start:     s,
		coalition: slices.Clone(coalition),
		opts:      opts,
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
}

// writesTuple reports whether a move adds a tuple. A pure creation move brings
// an object into the coalition and writes none.
func (m move) writesTuple() bool { return m.rel.Relation != "" }

// available is every move the coalition can make in a state, over the objects
// it controls. It is the shared primitive: the closure applies all of them each
// round, the oracle applies them one at a time.
func (e *engine) available(checker *Checker, state *stateSet, objects []Object) ([]move, error) {
	var moves []move
	domain := e.domain(state, objects)

	for _, rule := range e.wm.Writes {
		if !writes(rule.Operations) {
			// Delete moves are the business of exactness condition E1 and are
			// added with it; an additive closure only adds.
			continue
		}
		relation := e.relation(rule.Resource, rule.Relation)
		if relation == nil {
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
			for _, writer := range objects {
				for _, subject := range e.subjects(rule, relation, writer, objects) {
					rel := Relationship{Resource: resource, Relation: rule.Relation, Subject: subject}
					if state.has(rel) {
						continue
					}
					moves = append(moves, move{rel: rel, rule: rule, writer: Subject{Object: writer}})
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

// creations is every creation move the coalition can make: one object per
// creation rule, with the tuples the rule writes. One object per rule is the
// exact choice while the rule's exactness condition E2 holds, which the engine
// checks with condition E2; the recursive and k-copy fallbacks are added there.
func (e *engine) creations(checker *Checker, state *stateSet, objects []Object, domain map[string][]Object) ([]move, error) {
	var moves []move
	for i, rule := range e.wm.Creates {
		created := Object{Type: rule.Creates, ID: createdID(i)}
		if containsObject(objects, created) {
			// The object this rule makes is already in the coalition; its writes
			// were taken when it joined.
			continue
		}
		ons, held, err := e.creationGate(checker, rule, objects, domain)
		if err != nil {
			return nil, err
		}
		if !held {
			continue
		}
		// The creation itself brings the object into the coalition; each tuple
		// the rule writes is a move of its own, so a rule with several writes
		// adds each and the fixpoint carries them all.
		moves = append(moves, move{creates: rule, created: created})
		for _, w := range rule.Writes {
			rel, ok := e.fillCreationWrite(w, created, ons)
			if !ok || state.has(rel) {
				continue
			}
			moves = append(moves, move{rel: rel, creates: rule, created: created})
		}
	}
	return moves, nil
}

// creationGate says whether the coalition can make an object of a rule, and on
// which On objects. A rule with no On is gated on its own, and a gate that
// holds a permission then holds on nothing, so only an anyone gate makes it. A
// rule with On needs its gate to hold on one object of each On type.
func (e *engine) creationGate(checker *Checker, rule *CreationRule, objects []Object, domain map[string][]Object) (map[string]Object, bool, error) {
	if len(rule.On) == 0 {
		return nil, rule.Gate.Anyone, nil
	}
	ons := make(map[string]Object, len(rule.On))
	for _, on := range rule.On {
		found := false
		for _, candidate := range domain[on.Type] {
			held, err := e.gateHolds(checker, on.Gate, candidate, objects)
			if err != nil {
				return nil, false, err
			}
			if held {
				ons[on.Type] = candidate
				found = true
				break
			}
		}
		if !found {
			return nil, false, nil
		}
	}
	return ons, true, nil
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
		if !subjectAllowed(rule.Subject, allowed, writer) {
			continue
		}
		switch {
		case allowed.Wildcard:
			if rule.Wildcard {
				appendSubject(&out, Subject{Object: Object{Type: allowed.Type, ID: WildcardID}})
			}
		case allowed.Relation == "":
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
// objects of the state, the objects the coalition controls, and the objects
// creation rules can make. Wildcards are subjects, not objects, so they are not
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
	for i, rule := range e.wm.Creates {
		add(Object{Type: rule.Creates, ID: createdID(i)})
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

// createdID is the identifier of the object a creation rule makes, one per rule
// so that two rules do not collide.
func createdID(ruleIndex int) string {
	return fmt.Sprintf("created-%d", ruleIndex)
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
