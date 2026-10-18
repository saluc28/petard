package zanzibar

import "fmt"

// E2Failure names a creation rule that breaks exactness condition E2, and why.
type E2Failure struct {
	// Creates is the type the rule makes, which identifies the rule in the
	// report.
	Creates string
	Reason  string
}

// String writes the failure as the creation and its reason, for the report.
func (f E2Failure) String() string {
	return fmt.Sprintf("creation of %s (%s)", f.Creates, f.Reason)
}

// creationMode is how the closure materializes a creation rule under E2. One
// object per choice of On objects is exact while E2 holds; the two fields are
// the fallbacks when it does not.
type creationMode struct {
	// merged collapses a recursive rule to one object per rule, so that a
	// folder created inside a created folder does not nest without end. It is
	// sound and may report a raise only the merged object allows.
	merged bool

	// copies is how many objects the rule is kept at. It is one while E2 holds,
	// and DefaultCreatedCopies when the rule writes a tuple that occurs
	// negatively, where one copy could hide how two of them interact.
	copies int
}

// e2plan decides, per creation rule, how to materialize it, and collects the
// failures of E2. A rule whose created type can nest inside itself, directly or
// through other rules, is recursive and merged; a rule that writes a tuple of a
// relation that occurs negatively keeps k copies.
func e2plan(model *Model, wm *WriteModel, pol *polarities, copies int) ([]creationMode, []E2Failure) {
	modes := make([]creationMode, len(wm.Creates))
	cyclic := cyclicCreatedTypes(wm)
	var failures []E2Failure
	for i, rule := range wm.Creates {
		modes[i] = creationMode{copies: 1}
		if recursive(rule, cyclic) {
			modes[i].merged = true
			failures = append(failures, E2Failure{Creates: rule.Creates, Reason: "recursive"})
		}
		if rel := negativeWrite(rule, pol); rel != "" {
			modes[i].copies = copies
			failures = append(failures, E2Failure{Creates: rule.Creates, Reason: "writes the negative relation " + rel})
		}
	}
	return modes, failures
}

// CheckE2 reports whether exactness condition E2 holds: creation rules are not
// recursive and every tuple a creation writes occurs only positively. When it
// fails the returned failures name the rules and why, so the bound is never
// silent (section 5.3 of the definitions). Under E2 one object per rule and per
// choice of its On objects is exact, because positive Datalog is preserved
// under the homomorphism that maps many such objects onto one.
func CheckE2(model *Model, wm *WriteModel) (bool, []E2Failure) {
	_, failures := e2plan(model, wm, analyzePolarities(model, wm), DefaultCreatedCopies)
	return len(failures) == 0, failures
}

// recursive reports whether a rule can create an object inside one it created,
// which is so when its created type, or a type it creates in, lies on a cycle
// of the containment graph.
func recursive(rule *CreationRule, cyclic map[string]bool) bool {
	if cyclic[rule.Creates] {
		return true
	}
	for _, on := range rule.On {
		if cyclic[on.Type] {
			return true
		}
	}
	return false
}

// negativeWrite returns a relation the creation writes that occurs negatively,
// or empty when every tuple it writes occurs only positively. A negative write
// can lower a permission, so the creation is no longer a one-way move.
func negativeWrite(rule *CreationRule, pol *polarities) string {
	for _, w := range rule.Writes {
		typ := writeResourceType(rule, w)
		if typ == "" {
			continue
		}
		if pol.at(relKey{Type: typ, Relation: w.Relation}).neg {
			return typ + "#" + w.Relation
		}
	}
	return ""
}

// writeResourceType resolves the type a creation write lands on: the created
// object's type, or an On type. A write onto the creator is not onto a resource
// of the schema and has no type here.
func writeResourceType(rule *CreationRule, w CreationWrite) string {
	if w.Resource == CreatedPlaceholder {
		return rule.Creates
	}
	for _, on := range rule.On {
		if on.Type == w.Resource {
			return on.Type
		}
	}
	return ""
}

// cyclicCreatedTypes is the set of types that can nest inside themselves through
// creation rules. A rule that creates T on U places a T inside a U, an edge
// U to T; a type that reaches itself along these edges can be created inside
// an object of its own making.
func cyclicCreatedTypes(wm *WriteModel) map[string]bool {
	edges := map[string][]string{}
	for _, rule := range wm.Creates {
		for _, on := range rule.On {
			edges[on.Type] = append(edges[on.Type], rule.Creates)
		}
	}
	cyclic := map[string]bool{}
	for from := range edges {
		if reaches(edges, from, from, map[string]bool{}) {
			cyclic[from] = true
		}
	}
	return cyclic
}

// reaches reports whether target is reachable from, following the edges, without
// revisiting a node.
func reaches(edges map[string][]string, from, target string, seen map[string]bool) bool {
	for _, next := range edges[from] {
		if next == target {
			return true
		}
		if !seen[next] {
			seen[next] = true
			if reaches(edges, next, target, seen) {
				return true
			}
		}
	}
	return false
}
