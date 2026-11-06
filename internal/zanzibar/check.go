package zanzibar

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"time"
)

// Level is how far a permission holds: not at all, only when a caveat is true,
// or unconditionally. The order is the order of the constants, so that a
// conjunction is the lower of two levels and a disjunction the higher, which is
// the three valued logic SpiceDB applies to partially evaluated caveats
// (internal/caveats/run.go at v1.56.2).
type Level int

const (
	// No is a permission that does not hold.
	No Level = iota

	// Conditional is a permission that holds when some caveat is true, and
	// the context known so far does not say whether it is.
	Conditional

	// Yes is a permission that holds.
	Yes
)

// String names the level the way a report prints it.
func (l Level) String() string {
	switch l {
	case No:
		return "no"
	case Conditional:
		return "conditional"
	case Yes:
		return "yes"
	}
	return fmt.Sprintf("Level(%d)", int(l))
}

func and(a, b Level) Level { return min(a, b) }
func or(a, b Level) Level  { return max(a, b) }

// connective is how a list of levels combines: any of them, as a union and an
// arrow do, or all of them, as an intersection and an arrow with all do.
// decided is the level after which the rest of the list cannot change the
// result.
type connective struct {
	start, decided Level
	combine        func(a, b Level) Level
}

var (
	anyOf = connective{start: No, decided: Yes, combine: or}
	allOf = connective{start: Yes, decided: No, combine: and}
)

func not(a Level) Level {
	switch a {
	case Yes:
		return No
	case No:
		return Yes
	}
	return Conditional
}

// CaveatEvaluator evaluates the caveats of a model. The front end that lowered
// the model provides it, because each product compiles caveat expressions in a
// CEL environment of its own.
type CaveatEvaluator interface {
	// Evaluate says whether the caveat of that name holds with context: Yes
	// or No when context fills every parameter the expression needs to
	// decide, Conditional when it does not. The context is the one the check
	// supplied with the one the relationship carries written over it.
	Evaluate(name string, context map[string]any) (Level, error)
}

// ErrUnknown is returned for a check that names a type, a relation or a
// permission the model does not declare.
var ErrUnknown = errors.New("zanzibar: not declared")

// ErrWildcardSubject is returned for a check whose subject is a wildcard, which
// SpiceDB refuses as well (internal/graph/check.go:179 at v1.56.2): a wildcard
// is something a relationship grants to, not somebody who asks.
var ErrWildcardSubject = errors.New("zanzibar: a wildcard cannot be checked as a subject")

// ErrTooDeep is returned for a check that has to follow relationships more
// than maxDepth levels deep. The relationships come from files the engine is
// pointed at, and a chain long enough would otherwise exhaust the stack, which
// in Go ends the process rather than failing the check. SpiceDB stops much
// earlier, at a dispatch depth of 50 by default (pkg/cmd/server/server.go:100
// at v1.56.2).
var ErrTooDeep = errors.New("zanzibar: relationships nest too deep")

// maxDepth is how many checks may be open at once, one inside the other.
const maxDepth = 10_000

// Result is the answer to a check.
type Result struct {
	Level Level

	// Cycle is true when answering went through a loop in the relationships,
	// a folder inside itself, and cut it. The level is then the least one the
	// relationships support, which is what the engine reasons with, and No
	// where an exclusion subtracts a loop the product meets (Model.Walk). SpiceDB
	// does not cut loops: it follows them to its dispatch depth limit and fails,
	// unless another way already granted.
	Cycle bool
}

// cuts is what answering a question found of the loops on its way.
type cuts uint8

const (
	// cutLoop is a loop cut on the way: the answer rests on the provisional No a
	// cut answers with, and is not remembered.
	cutLoop cuts = 1 << iota

	// cutMet is a loop the product meets as well.
	cutMet

	// cutMetIfCaveat is a loop the product meets only if a caveat it stops at, and
	// that nothing decides yet, holds.
	cutMetIfCaveat

	// cutFails is a loop the product follows to its depth limit, failing the
	// check, unless a way that grants ends the walk before it gets there
	// (Walk.AnswersLoops).
	cutFails
)

// Checker answers checks over a fixed set of relationships. It remembers what
// it answered, and is not safe for concurrent use.
type Checker struct {
	model   *Model
	caveats CaveatEvaluator
	stored  map[storedKey][]Relationship

	settled     map[checkKey]Level
	inProgress  map[checkKey]bool
	caveatCache map[string]Level

	// request is the context the check being answered supplied, and
	// requestKey its encoding, which keeps answers given with one context
	// apart from answers given with another.
	request    map[string]any
	requestKey string

	// waits is true where SpiceDB waits for every result of what it is
	// answering: the base and the subtracted side of an exclusion, and the
	// operands of an intersection (internal/graph/check.go:1142, :1198 and :1207
	// at v1.57.0). A way that grants does not end the walk there, so a loop on
	// another way fails the check.
	waits bool
}

type storedKey struct {
	resource Object
	relation string
}

type checkKey struct {
	resource Object
	name     string
	subject  Subject
	request  string
}

// NewChecker indexes relationships for checks against model. A relationship
// that expired at now or before does not count, as SpiceDB does not return
// it. caveats may be nil when no relationship carries one.
func NewChecker(model *Model, relationships []Relationship, caveats CaveatEvaluator, now time.Time) *Checker {
	c := &Checker{
		model:       model,
		caveats:     caveats,
		stored:      make(map[storedKey][]Relationship),
		settled:     make(map[checkKey]Level),
		inProgress:  make(map[checkKey]bool),
		caveatCache: make(map[string]Level),
	}
	for _, r := range relationships {
		if r.Expires != nil && !r.Expires.After(now) {
			continue
		}
		key := storedKey{resource: r.Resource, relation: r.Relation}
		c.stored[key] = append(c.stored[key], r)
	}
	return c
}

// Check says how far subject holds name, a relation or a permission, on
// resource. context is what the check supplies for caveats, nil when it
// supplies nothing; a relationship's own context is written over it, as SpiceDB
// does (internal/caveats/run.go:222-230 at v1.56.2).
func (c *Checker) Check(resource Object, name string, subject Subject, context map[string]any) (Result, error) {
	if t := c.model.Type(resource.Type); t == nil || !t.Declares(name) {
		return Result{}, fmt.Errorf("%w: %s#%s", ErrUnknown, resource.Type, name)
	}
	if subject.ID == WildcardID {
		return Result{}, fmt.Errorf("%w: %s", ErrWildcardSubject, subject)
	}
	key, err := json.Marshal(context)
	if err != nil {
		return Result{}, fmt.Errorf("zanzibar: context of the check: %w", err)
	}
	c.request, c.requestKey = context, string(key)
	c.waits = false
	level, cycle, err := c.check(resource, name, subject)
	if cycle&cutFails != 0 {
		// The product fails the check, which grants nothing.
		level = No
	}
	return Result{Level: level, Cycle: cycle != 0}, err
}

// check answers one question and says what it found of the loops on the way.
//
// A question already being answered higher up is answered No: a proof that
// needs itself is no proof, and any proof that exists has one without the
// loop, so the least level is still found. What was computed while a loop was
// cut is not remembered, because it rests on that provisional No.
func (c *Checker) check(resource Object, name string, subject Subject) (Level, cuts, error) {
	key := checkKey{resource: resource, name: name, subject: subject, request: c.requestKey}
	if level, ok := c.settled[key]; ok {
		return level, 0, nil
	}
	if c.inProgress[key] {
		if !c.model.Walk.meetsLoopAt(resource.Type, name, subject) {
			return No, cutLoop, nil
		}
		if c.model.Walk.AnswersLoops {
			return No, cutLoop | cutMet, nil
		}
		return No, cutLoop | cutMet | cutFails, nil
	}

	t := c.model.Type(resource.Type)
	if t == nil || !t.Declares(name) {
		// An arrow reaching an object of a type without its target: SpiceDB
		// dispatches nothing to it, and it grants nothing.
		return No, 0, nil
	}
	if subject.Relation == name && subject.Object == resource {
		// The members of a relation of an object are members of it, whatever
		// is stored (internal/graph/check.go:765-779 at v1.56.2).
		return Yes, 0, nil
	}
	if len(c.inProgress) >= maxDepth {
		return No, 0, fmt.Errorf("%w: more than %d levels below %s#%s", ErrTooDeep, maxDepth, resource, name)
	}
	c.inProgress[key] = true
	defer delete(c.inProgress, key)

	var (
		level Level
		cycle cuts
		err   error
	)
	if p := t.Permission(name); p != nil {
		level, cycle, err = c.eval(resource, p.Expr, subject)
	} else {
		level, cycle, err = c.direct(resource, name, subject)
	}
	if err != nil {
		return No, 0, err
	}
	if cycle == 0 {
		c.settled[key] = level
	}
	return level, cycle, nil
}

// send answers name on another object, or on the same one under another name, as SpiceDB
// answers a check it dispatches: over again, without waiting for every result. That is
// what it does with a check of one object (internal/graph/check.go:224-227 at v1.57.0),
// and what zed validate answers for several objects of a type sent on together, as
// TestCheckALoopWhereSpiceDBWaitsForEveryResult holds.
func (c *Checker) send(resource Object, name string, subject Subject) (Level, cuts, error) {
	waits := c.waits
	c.waits = false
	defer func() { c.waits = waits }()
	return c.check(resource, name, subject)
}

// waitForAll marks what is answered until the returned function runs as answered
// waiting for every result, for a product that fails on a loop it meets.
func (c *Checker) waitForAll() func() {
	waits := c.waits
	c.waits = waits || !c.model.Walk.AnswersLoops
	return func() { c.waits = waits }
}

// endsAt says whether a way that grants ends the walk where it is answering: it does where
// the product does not wait for every result (internal/graph/check.go:430 and :1106 at
// v1.57.0). Ending there, the product never meets a loop on another way, so a failure on
// one is forgotten.
func (c *Checker) endsAt(level Level) bool {
	return level == Yes && !c.waits
}

// direct answers a relation from the relationships stored against it.
func (c *Checker) direct(resource Object, relation string, subject Subject) (Level, cuts, error) {
	level, cycle := No, cuts(0)
	for _, r := range c.stored[storedKey{resource: resource, relation: relation}] {
		if r.Subject.Relation != "" {
			stops, err := c.stopsAt(r)
			if err != nil {
				return No, 0, err
			}
			if stops {
				continue
			}
		}
		got, cut, err := c.holds(r.Subject, subject)
		if err != nil {
			return No, 0, err
		}
		cut, err = c.pastCaveat(r, cut)
		if err != nil {
			return No, 0, err
		}
		cycle |= cut
		if got == No {
			continue
		}
		carried, err := c.carried(r)
		if err != nil {
			return No, 0, err
		}
		level = or(level, and(got, carried))
		if c.endsAt(level) {
			break
		}
	}
	if c.endsAt(level) {
		cycle &^= cutFails
	}
	return level, cycle, nil
}

// holds says whether the subject a relationship names includes subject.
func (c *Checker) holds(stored, subject Subject) (Level, cuts, error) {
	switch {
	case stored == subject:
		return Yes, 0, nil
	case stored.ID == WildcardID && stored.Relation == "":
		// A wildcard stands for objects, not for usersets.
		if subject.Type == stored.Type && subject.Relation == "" && subject.ID != WildcardID {
			return Yes, 0, nil
		}
		return No, 0, nil
	case stored.Relation != "":
		return c.send(stored.Object, stored.Relation, subject)
	}
	return No, 0, nil
}

// stopsAt says whether the product leaves a relationship unfollowed because its
// caveat does not hold.
func (c *Checker) stopsAt(r Relationship) (bool, error) {
	if !c.model.Walk.StopsAtFailedCaveat || r.Caveat == nil {
		return false, nil
	}
	carried, err := c.carried(r)
	return carried == No, err
}

// pastCaveat is what a loop cut past a relationship comes to. A product that stops at
// a caveat that fails meets that loop only if the caveat holds, so while nothing
// decides the caveat it may not meet it at all.
func (c *Checker) pastCaveat(r Relationship, cut cuts) (cuts, error) {
	if cut&cutMet == 0 || !c.model.Walk.StopsAtFailedCaveat || r.Caveat == nil {
		return cut, nil
	}
	carried, err := c.carried(r)
	if err != nil || carried != Conditional {
		return cut, err
	}
	return cut&^cutMet | cutMetIfCaveat, nil
}

// carried is the level the caveat of a relationship allows, Yes when it
// carries none. The caveat sees the context of the check with the context the
// relationship carries written over it.
func (c *Checker) carried(r Relationship) (Level, error) {
	if r.Caveat == nil {
		return Yes, nil
	}
	if c.caveats == nil {
		return No, fmt.Errorf("zanzibar: %s carries caveat %s and nothing evaluates caveats", r, r.Caveat.Name)
	}
	context := maps.Clone(c.request)
	if context == nil {
		context = make(map[string]any, len(r.Caveat.Context))
	}
	maps.Copy(context, r.Caveat.Context)
	encoded, err := json.Marshal(context)
	if err != nil {
		return No, fmt.Errorf("zanzibar: context of %s: %w", r, err)
	}
	cacheKey := r.Caveat.Name + string(encoded)
	if level, ok := c.caveatCache[cacheKey]; ok {
		return level, nil
	}
	level, err := c.caveats.Evaluate(r.Caveat.Name, context)
	if err != nil {
		return No, fmt.Errorf("zanzibar: caveat of %s: %w", r, err)
	}
	c.caveatCache[cacheKey] = level
	return level, nil
}

// eval answers a permission expression on resource.
func (c *Checker) eval(resource Object, expr Expr, subject Subject) (Level, cuts, error) {
	switch e := expr.(type) {
	case Union:
		return c.combine(resource, e.Children, subject, anyOf)

	case Intersection:
		defer c.waitForAll()()
		return c.combine(resource, e.Children, subject, allOf)

	case Exclusion:
		defer c.waitForAll()()
		level, cycle, err := c.eval(resource, e.Base, subject)
		if err != nil || level == No || cycle&cutFails != 0 {
			return No, cycle, err
		}
		for _, child := range e.Subtracted {
			got, cut, err := c.eval(resource, child, subject)
			if err != nil {
				return No, 0, err
			}
			cycle |= cut
			// A subtracted side that met a loop has not shown the subject out of
			// it: its No is the provisional one a cut answers with, which proves
			// nothing once it is negated. So the exclusion grants nothing, which
			// is the answer OpenFGA gives when it meets the loop
			// (internal/graph/check.go:358-360 at v1.22.1). SpiceDB fails such a
			// check at its depth limit instead, which grants nothing either.
			if cut&cutMet != 0 {
				return No, cycle, nil
			}
			// One it meets only if a caveat holds may or may not prove nothing,
			// which is what conditional says.
			if cut&cutMetIfCaveat != 0 {
				got = or(got, Conditional)
			}
			level = and(level, not(got))
			if level == No {
				break
			}
		}
		return level, cycle, nil

	case Computed:
		return c.send(resource, e.Name, subject)

	case Arrow:
		return c.arrow(resource, e, subject)

	case Stored:
		return c.direct(resource, e.Name, subject)

	case Self:
		if subject.Relation == "" && subject.Object == resource {
			return Yes, 0, nil
		}
		return No, 0, nil

	case Nil:
		return No, 0, nil
	}
	return No, 0, fmt.Errorf("zanzibar: expression %T", expr)
}

// combine evaluates expressions in order and combines their levels, stopping
// once the rest cannot change the result.
func (c *Checker) combine(resource Object, children []Expr, subject Subject, how connective) (Level, cuts, error) {
	level, cycle := how.start, cuts(0)
	for _, child := range children {
		got, cut, err := c.eval(resource, child, subject)
		if err != nil {
			return No, 0, err
		}
		level, cycle = how.combine(level, got), cycle|cut
		if level == how.decided && (how.decided == No || c.endsAt(level)) {
			break
		}
	}
	if how.decided == Yes && c.endsAt(level) {
		cycle &^= cutFails
	}
	return level, cycle, nil
}

// arrow walks a relation and asks the target on every object it reaches.
func (c *Checker) arrow(resource Object, a Arrow, subject Subject) (Level, cuts, error) {
	walked := c.stored[storedKey{resource: resource, relation: a.Through}]
	how := anyOf
	if a.All {
		if len(walked) == 0 {
			// internal/graph/check.go:842-844 at v1.56.2: nothing to walk is
			// nobody, unlike an every over an empty domain in Rego.
			return No, 0, nil
		}
		how = allOf
	}

	level, cycle := how.start, cuts(0)
	for _, r := range walked {
		got, cut, err := c.across(r, a.Target, subject)
		if err != nil {
			return No, 0, err
		}
		level, cycle = how.combine(level, got), cycle|cut
		if level == how.decided && (how.decided == No || c.endsAt(level)) {
			break
		}
	}
	if how.decided == Yes && c.endsAt(level) {
		cycle &^= cutFails
	}
	return level, cycle, nil
}

// across asks the target of an arrow on the object a walked relationship reaches. A
// relationship walked with a caveat passes the caveat on.
func (c *Checker) across(r Relationship, target string, subject Subject) (Level, cuts, error) {
	stops, err := c.stopsAt(r)
	if stops || err != nil {
		return No, 0, err
	}
	got, cut, err := c.send(r.Subject.Object, target, subject)
	if err != nil {
		return No, 0, err
	}
	cut, err = c.pastCaveat(r, cut)
	if err != nil {
		return No, 0, err
	}
	if got != No {
		carried, err := c.carried(r)
		if err != nil {
			return No, 0, err
		}
		got = and(got, carried)
	}
	return got, cut, nil
}
