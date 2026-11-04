package zanzibar

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
)

// namedObjects are the objects the relationships of a sample name.
func namedObjects(s Sample) map[Object]bool {
	named := make(map[Object]bool, 2*len(s.Relationships))
	for _, r := range s.Relationships {
		named[r.Resource] = true
		named[r.Subject.Object] = true
	}
	return named
}

// freeObject is an object the analysis supposes: an attacker that holds nothing it did
// not write, the object of a position, one a coalition makes. It takes a name no
// relationship of the sample uses, with a number after it when one does, so that a real
// object that happens to have the name lends it nothing and is not credited with what
// the supposed one reaches.
func freeObject(taken map[Object]bool, typ, id string) Object {
	object := Object{Type: typ, ID: id}
	for n := 1; taken[object]; n++ {
		object.ID = fmt.Sprintf("%s-%d", id, n)
	}
	return object
}

// realSubjects are the objects the relationships of a sample name as their subject,
// in the order they sort. A userset is left out, since its members are who hold what
// it grants, and so is a wildcard, which names nobody.
func realSubjects(tuples []Relationship) []Object {
	var out []Object
	for _, r := range tuples {
		if r.Subject.Relation == "" && r.Subject.ID != WildcardID {
			out = append(out, r.Subject.Object)
		}
	}
	return uniqueObjects(out)
}

func uniqueObjects(objects []Object) []Object {
	slices.SortFunc(objects, func(a, b Object) int { return cmp.Compare(a.String(), b.String()) })
	return slices.Compact(objects)
}

// maxSubjectWork is how much weighing what real subjects can raise may take, counted in
// the tuples of the state of each subject weighed and of each state its search goes
// through. It takes about a minute.
const maxSubjectWork = 30000000

// maxSupposedWork is how much weighing the states of a sample for an attacker the analysis
// supposes may take, for each type of attacker, counted in the tuples of each state its
// search goes through. It takes about a minute, and only a store of many shapes behind an
// open rule comes near it.
const maxSupposedWork = 30000000

// maxHoldingChecks is how many checks asking what real subjects hold may take. It takes
// a few tens of seconds, and only a wildcard or a large team on many objects comes near it.
const maxHoldingChecks = 5000000

// holding is a permission a real subject holds on an object as the relationships
// stand.
type holding struct {
	subject, object Object
	permission      string
}

// subjectHoldings are the permissions the real subjects of a sample hold on the
// objects its relationships name. Only an unconditional yes is a holding: one that
// waits on a condition holds for some checks and not for others, and one that cut a
// loop rests on a walk the product may not finish. A subject holding something on
// itself says nothing about who can reach what, and is left out.
//
// A yes rests on a tuple the check reads, naming the subject or a wildcard of its type,
// so only those subjects are asked of an object. A store of many subjects and many
// objects would take hours to ask whole. Past the work given, the objects left are not
// asked, and are counted.
func subjectHoldings(s Sample, work int) ([]holding, Limits) {
	var limits Limits
	if s.Model == nil {
		return nil, limits
	}
	tuples := s.Relationships
	byResource := positionsOf(tuples)
	objects := uniqueObjects(slices.Collect(maps.Keys(byResource)))

	subjects := realSubjects(tuples)
	named := make(map[Object]bool, len(subjects))
	byType := map[string][]Object{}
	for _, subject := range subjects {
		named[subject] = true
		byType[subject.Type] = append(byType[subject.Type], subject)
	}

	checker := NewChecker(s.Model, tuples, s.Caveats, s.Now)
	var out []holding
	for i, object := range objects {
		if work <= 0 {
			limits.HoldingsLeftOut = len(objects) - i
			break
		}
		typ := s.Model.Type(object.Type)
		if typ == nil {
			continue
		}
		var asked []Object
		for read := range readsOf(object, tuples, byResource) {
			if named[read] {
				asked = append(asked, read)
			}
			for _, at := range byResource[read] {
				if subject := tuples[at].Subject; subject.ID == WildcardID {
					asked = append(asked, byType[subject.Type]...)
				}
			}
		}
		for _, subject := range uniqueObjects(asked) {
			if subject == object {
				continue
			}
			for _, p := range typ.Permissions {
				work--
				got, err := checker.Check(object, p.Name, Subject{Object: subject}, nil)
				if err == nil && got.Level == Yes && !got.Cycle {
					out = append(out, holding{subject: subject, object: object, permission: p.Name})
				}
			}
		}
	}
	return out, limits
}

// subjectEscalations are the escalations the real subjects of a sample can reach from
// the relationships as they stand, each a coalition of its own. It says what
// classifiedEscalations does not: which of the subjects the store names can raise what.
// Nothing is deduplicated across subjects, since two of them raising one permission are
// two facts.
//
// A subject is weighed on the objects whose checks read a tuple naming it, which is
// where what it holds can open something. What it holds on an object a witness can link
// to or start from reaches further, onto objects that do not name it, and reachedFrom
// weighs that. On any other object it starts like any other account, and what such an
// account can raise hangs off the attacker the analysis supposes.
//
// A store where many subjects share large states would take hours to weigh whole, so the
// work has a limit, spent on the smallest states first: they are the most subjects for
// the work. What is left out is counted, so the graph does not read as complete.
func subjectEscalations(s Sample, wm *WriteModel, work int) ([]attackerEscalation, Limits) {
	var limits Limits
	if s.Model == nil || wm == nil {
		return nil, limits
	}
	opts := Options{Now: s.Now, maxStates: maxSearchStates, cut: &limits.SearchesStopped, work: &work, taken: namedObjects(s)}
	scope := newReach(s.Model, wm).scopeOf(s.Model, wm)

	states, _ := weighedStates(s, wm)
	slices.SortStableFunc(states, func(a, b weighedState) int { return cmp.Compare(len(a.tuples), len(b.tuples)) })

	var out []attackerEscalation
	for _, state := range states {
		for _, subject := range realSubjects(state.tuples) {
			if !state.reads[subject] {
				continue
			}
			work -= len(state.tuples)
			if work < 0 {
				limits.SubjectsLeftOut++
				continue
			}
			classified, err := classifyScoped(s.Model, wm, s.Caveats, state.tuples, []Object{subject}, scope, opts)
			if err != nil {
				// As in classifiedEscalations: a state the caveat environment cannot
				// evaluate yields nothing for this subject, and says nothing of the rest.
				continue
			}
			for _, c := range classified {
				if id := c.Category.patternID(); id != "" && c.Object == state.object {
					out = append(out, attackerEscalation{attacker: subject, esc: c, patternID: id})
				}
			}
		}
	}
	return append(out, reachedFrom(s, wm, states, scope, opts, &work, &limits)...), limits
}

// reachedFrom is what a subject raises by carrying what it holds on objects a witness
// can link to or start from onto an object that does not name it: Vic views a folder,
// and may move any document into it. The smallest state of each type stands for the
// type, weighed with the objects that name the subject brought along. What an account
// with nothing raises there is left to the attacker the analysis supposes, so only what
// the subject's own holdings add is its own.
func reachedFrom(s Sample, wm *WriteModel, states []weighedState, scope map[permRef]bool, opts Options, work *int, limits *Limits) []attackerEscalation {
	tuples := s.Relationships
	byResource := positionsOf(tuples)
	types := startTypes(s.Model, wm)
	holds := map[Object]map[Object]bool{}
	for _, x := range uniqueObjects(slices.Collect(maps.Keys(byResource))) {
		if !types[x.Type] {
			continue
		}
		reads := readsOf(x, tuples, byResource)
		for _, subject := range realSubjects(heldBy(tuples, byResource, reads)) {
			if holds[subject] == nil {
				holds[subject] = map[Object]bool{}
			}
			maps.Copy(holds[subject], reads)
		}
	}
	if len(holds) == 0 {
		return nil
	}

	var out []attackerEscalation
	ofType := map[string]bool{}
	for _, state := range states {
		if ofType[state.object.Type] {
			continue
		}
		ofType[state.object.Type] = true
		anyone := map[string]map[string]bool{}
		for _, subject := range uniqueObjects(slices.Collect(maps.Keys(holds))) {
			if state.reads[subject] {
				continue
			}
			include := maps.Clone(holds[subject])
			for _, r := range state.tuples {
				include[r.Resource] = true
			}
			start := heldBy(tuples, byResource, include)
			*work -= len(start)
			if *work < 0 {
				limits.SubjectsLeftOut++
				continue
			}
			if anyone[subject.Type] == nil {
				anyone[subject.Type] = raisedByNobody(s, wm, state, scope, opts, subject.Type)
			}
			classified, err := classifyScoped(s.Model, wm, s.Caveats, start, []Object{subject}, scope, opts)
			if err != nil {
				continue
			}
			for _, c := range classified {
				id := c.Category.patternID()
				if id != "" && c.Object == state.object && !anyone[subject.Type][id+"|"+c.Permission] {
					out = append(out, attackerEscalation{attacker: subject, esc: c, patternID: id})
				}
			}
		}
	}
	return out
}

// raisedByNobody is what an account of a type that holds nothing raises on the object of
// a state, by pattern and permission.
func raisedByNobody(s Sample, wm *WriteModel, state weighedState, scope map[permRef]bool, opts Options, typ string) map[string]bool {
	raised := map[string]bool{}
	attacker := freeObject(opts.taken, typ, "attacker")
	classified, err := classifyScoped(s.Model, wm, s.Caveats, state.tuples, []Object{attacker}, scope, opts)
	if err != nil {
		return raised
	}
	for _, c := range classified {
		if id := c.Category.patternID(); id != "" && c.Object == state.object {
			raised[id+"|"+c.Permission] = true
		}
	}
	return raised
}
