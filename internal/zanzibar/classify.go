package zanzibar

import "slices"

// Category is the kind of a finding, the abstract property the decisive write
// violates. The escalation engine labels a witness with one; it is not a
// separate detector (section 7.1 of the definitions).
type Category string

const (
	// CategoryFailOpenOnAbsence is a deny lifted by deleting the tuple that
	// denies, a relation under an exclusion.
	CategoryFailOpenOnAbsence Category = "FAIL-OPEN-ON-ABSENCE"

	// CategorySelfAssertedExemption is a conditional grant made unconditional by
	// fixing a caveat parameter the check was meant to bring. The closure does
	// not write caveat context, so SelfAssertedExemptions finds it instead, and
	// the classifier never returns this one.
	CategorySelfAssertedExemption Category = "SELF-ASSERTED-EXEMPTION"

	// CategoryGlobalSwitch is a grant to every object of a type, written as a
	// wildcard subject.
	CategoryGlobalSwitch Category = "GLOBAL-SWITCH"

	// CategoryTransitiveGrant links an object to one the coalition controls,
	// through the relation an arrow walks.
	CategoryTransitiveGrant Category = "TRANSITIVE-GRANT"

	// CategoryAssumableIdentity writes the coalition into a userset the object
	// already grants to.
	CategoryAssumableIdentity Category = "ASSUMABLE-IDENTITY"

	// CategoryDelegationNotNarrowed is one coalition subject writing for another
	// a grant it does not hold itself.
	CategoryDelegationNotNarrowed Category = "DELEGATION-NOT-NARROWED"

	// CategorySplitGrant writes the coalition into the object, behind a gate that
	// is a permission the coalition held.
	CategorySplitGrant Category = "SPLIT-GRANT"

	// CategoryAttrSelfWrite writes the coalition into the object, behind a gate
	// that needs no permission on it.
	CategoryAttrSelfWrite Category = "ATTR-SELF-WRITE"
)

// ClassifiedEscalation is an escalation with the category its decisive write
// falls into, and the write that classification read the category from.
type ClassifiedEscalation struct {
	Escalation
	Category Category

	// DecisiveWrite is the write the category was read from. It is the last
	// write of the witness in the usual case, but when that write is a creation,
	// which only builds the coalition's own object, it is the rule write in the
	// witness that links the pre-existing object instead, the write the category
	// describes. A report names this write, so its heading and its "written by"
	// line agree even when the witness order left a setup creation at the end.
	DecisiveWrite WriteStep
}

// Classify finds the escalations a coalition can reach and labels each by its
// decisive write. A target reachable by writes of different kinds yields one
// finding per category, each with its shortest witness. The caveat category is
// not returned here: a caveat context write is not one of the closure's moves,
// and SelfAssertedExemptions reports it from the write model instead.
func Classify(model *Model, wm *WriteModel, caveats CaveatEvaluator, start []Relationship, coalition []Object, opts Options) ([]ClassifiedEscalation, error) {
	escs, err := Escalations(model, wm, caveats, start, coalition, opts)
	if err != nil {
		return nil, err
	}
	e := newEngine(model, wm, caveats, start, coalition, opts)

	best := map[string]ClassifiedEscalation{}
	var order []string
	for _, esc := range escs {
		category, decisive, ok, err := e.classify(esc)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		key := esc.Object.String() + "#" + esc.Permission + "#" + string(category)
		existing, seen := best[key]
		if !seen || len(esc.Writes) < len(existing.Writes) {
			if !seen {
				order = append(order, key)
			}
			best[key] = ClassifiedEscalation{Escalation: esc, Category: category, DecisiveWrite: decisive}
		}
	}

	out := make([]ClassifiedEscalation, 0, len(order))
	for _, key := range order {
		out = append(out, best[key])
	}
	return out, nil
}

// classify labels an escalation by the first row of the section 7.1 table its
// decisive write matches, and returns that write. The decisive write is the
// last of the witness, except that a creation only builds the coalition's own
// object and matches no row: when the last write is a creation, the category is
// read instead from the rule write in the witness that links the pre-existing
// object, and that write is returned so a report names it. The rows are checked
// in order, so the first match wins and the categories need not be mutually
// exclusive.
func (e *engine) classify(esc Escalation) (Category, WriteStep, bool, error) {
	step, ok := esc.Decisive()
	if !ok {
		return "", WriteStep{}, false, nil
	}
	if step.Creation == nil {
		cat, ok, err := e.classifyStep(esc, step, len(esc.Writes)-1)
		return cat, step, ok, err
	}
	// The last write is a creation, which brings one of the coalition's own
	// objects into being and is none of the eight kinds. A raise on a
	// pre-existing object is reached through a rule write that links it to that
	// object; the witness holds such a write, but the order can leave a setup
	// creation at the end when the controlled object took more than one write to
	// build. Scan back from the last so the write nearest the raise is labeled.
	for i := len(esc.Writes) - 1; i >= 0; i-- {
		w := esc.Writes[i]
		if w.Creation != nil {
			continue
		}
		cat, ok, err := e.classifyStep(esc, w, i)
		if err != nil {
			return "", WriteStep{}, false, err
		}
		if ok {
			return cat, w, true, nil
		}
	}
	return "", WriteStep{}, false, nil
}

// classifyStep reads the category one write of a witness falls into, at its
// position i so the writer's holdings, for a delegation, are read on the state
// just before it.
func (e *engine) classifyStep(esc Escalation, step WriteStep, i int) (Category, bool, error) {
	rel := step.Relationship
	subject := rel.Subject
	created := createdObjects(esc.moves)

	switch {
	// A delete under E1 removes a tuple that occurs only negatively, so it lifts
	// a deny by exclusion.
	case step.Delete:
		return CategoryFailOpenOnAbsence, true, nil

	case subject.ID == WildcardID:
		return CategoryGlobalSwitch, true, nil

	case e.arrowThroughs(rel.Resource.Type)[rel.Relation] && e.controls(subject, step.Writer, created):
		return CategoryTransitiveGrant, true, nil

	case e.grantsToUserset(esc.Object.Type, rel.Resource.Type, rel.Relation) && e.controls(subject, step.Writer, created):
		return CategoryAssumableIdentity, true, nil
	}

	// One coalition subject writing for another a grant the writer does not hold
	// itself is a delegation. Reading what the writer held takes a check, which
	// can fail, so this case stands apart from the switch where its error can
	// travel rather than be read as "the writer held it".
	if subject.Object != step.Writer.Object {
		lacks, err := e.writerLacks(esc, step, i)
		if err != nil {
			return "", false, err
		}
		if lacks {
			return CategoryDelegationNotNarrowed, true, nil
		}
	}

	switch {
	case rel.Resource == esc.Object && e.controls(subject, step.Writer, created) && step.Rule != nil && step.Rule.Gate.Holds != "":
		return CategorySplitGrant, true, nil

	case rel.Resource == esc.Object && e.controls(subject, step.Writer, created) && step.Rule != nil && step.Rule.Gate.Anyone:
		return CategoryAttrSelfWrite, true, nil
	}
	return "", false, nil
}

// controls reports whether a written subject is one the coalition controls: the
// writer itself, a starting coalition member, or an object a creation made on
// the witness.
func (e *engine) controls(subject, writer Subject, created map[Object]bool) bool {
	if subject.Relation != "" || subject.ID == WildcardID {
		return false
	}
	return subject.Object == writer.Object || containsObject(e.coalition, subject.Object) || created[subject.Object]
}

// createdObjects is the set of objects a witness made: the object each creation
// move brought into the coalition. A witness can only write a created object it
// made earlier on the same path, so its own moves are the complete set. Reading
// it this way, rather than from the shape of the identifier createdID gives a
// created object, never mistakes an input object named like a synthetic one for
// a created one.
func createdObjects(moves []move) map[Object]bool {
	created := map[Object]bool{}
	for _, mv := range moves {
		if mv.creates != nil {
			created[mv.created] = true
		}
	}
	return created
}

// arrowThroughs is the relations an arrow walks in the permissions of a type.
// The left side of an arrow is always a relation of the current object, so a
// write of one of these extends what an arrow reaches.
func (e *engine) arrowThroughs(typeName string) map[string]bool {
	t := e.model.Type(typeName)
	if t == nil {
		return nil
	}
	result := map[string]bool{}
	seen := map[string]bool{}
	var walk func(expr Expr)
	walk = func(expr Expr) {
		switch ex := expr.(type) {
		case Union:
			for _, c := range ex.Children {
				walk(c)
			}
		case Intersection:
			for _, c := range ex.Children {
				walk(c)
			}
		case Exclusion:
			walk(ex.Base)
			for _, s := range ex.Subtracted {
				walk(s)
			}
		case Computed:
			if p := t.Permission(ex.Name); p != nil && !seen[ex.Name] {
				seen[ex.Name] = true
				walk(p.Expr)
			}
		case Arrow:
			result[ex.Through] = true
		}
	}
	for _, p := range t.Permissions {
		walk(p.Expr)
	}
	return result
}

// grantsToUserset reports whether an object type has a relation that admits a
// userset subject of usersetType#usersetRel, which is what the coalition joins.
func (e *engine) grantsToUserset(objectType, usersetType, usersetRel string) bool {
	t := e.model.Type(objectType)
	if t == nil {
		return false
	}
	for _, r := range t.Relations {
		for _, a := range r.Allowed {
			if a.Type == usersetType && a.Relation == usersetRel {
				return true
			}
		}
	}
	return false
}

// writerLacks reports whether the writer did not itself hold what it wrote for
// another, read on the state just before write i of the witness. A delegation
// is a grant the writer passes on without holding it.
func (e *engine) writerLacks(esc Escalation, step WriteStep, i int) (bool, error) {
	state := e.start.clone()
	objects := slices.Clone(e.coalition)
	for _, mv := range esc.moves[:i] {
		applyMove(state, &objects, mv)
	}
	checker := NewChecker(e.model, state.list(), e.caveats, e.opts.now())
	result, err := checker.Check(step.Relationship.Resource, step.Relationship.Relation, step.Writer, nil)
	if err != nil {
		return false, err
	}
	return result.Level == No, nil
}
