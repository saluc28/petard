package opaengine

import (
	"slices"

	"github.com/open-policy-agent/opa/v1/ast"
)

// This file holds two readings of the idiom a decision answers with when it
// returns its violations too, {"allowed": count(violations) == 0, ...}: which
// side the violations are on, and which part of the rule the answer depends on.

// askedEmpty returns the terms of a body that it only asks to be empty: a
// collection the policy builds, counted and compared with zero, or compared
// with an empty collection.
//
// For a partial set or a partial object that is what not asks of each of its
// elements. The rule exists even when nothing is in it, so its count is zero
// exactly when no body of it holds, and a decision that grants on
// count(violations) == 0 denies through every violation the way one written
// with not does. Counting anything else is not a negation: a document that is
// missing has no count at all, and the comparison fails with it.
//
// The compiler writes the idiom in three steps, a variable bound to the rule, a
// count of the variable and a comparison of the count, and the negation lands
// on the first, which is where the walk follows the rule. The comparison is an
// equality where the answer is a value and a unification where it is a
// condition, and both are read.
func (r *refReader) askedEmpty(body ast.Body) map[*ast.Term]bool {
	zero := map[ast.Var]bool{}
	var asked []*ast.Term
	for _, expr := range body {
		if !expr.IsCall() || (!expr.IsEquality() && expr.Operator().String() != ast.Equal.Name) {
			continue
		}
		operands := expr.Operands()
		if len(operands) < 2 {
			continue
		}
		for _, pair := range [][2]*ast.Term{{operands[0], operands[1]}, {operands[1], operands[0]}} {
			if v, isVar := varOf(pair[0]); isVar && isZero(pair[1]) {
				zero[v] = true
			}
			if isEmptyCollection(pair[1]) {
				asked = append(asked, pair[0])
			}
		}
	}
	for _, expr := range body {
		if !expr.IsCall() || expr.Operator().String() != ast.Count.Name {
			continue
		}
		if operands := expr.Operands(); len(operands) == 2 {
			if v, isVar := varOf(operands[1]); isVar && zero[v] {
				asked = append(asked, operands[0])
			}
		}
	}

	empty := map[*ast.Term]bool{}
	for _, term := range asked {
		for _, collection := range r.collectionsNamed(term, body) {
			empty[collection] = true
		}
	}
	return empty
}

// collectionsNamed returns the references to a collection the policy builds
// that a term stands for: the term itself, or what an equality of the body binds
// it to.
func (r *refReader) collectionsNamed(term *ast.Term, body ast.Body) []*ast.Term {
	if ref, isRef := term.Value.(ast.Ref); isRef {
		if r.alwaysDefined(ref) {
			return []*ast.Term{term}
		}
		return nil
	}
	v, isVar := varOf(term)
	if !isVar {
		return nil
	}
	var named []*ast.Term
	for _, expr := range body {
		if !expr.IsEquality() {
			continue
		}
		operands := expr.Operands()
		for _, pair := range [][2]*ast.Term{{operands[0], operands[1]}, {operands[1], operands[0]}} {
			if bound, isVar := varOf(pair[0]); isVar && bound == v {
				if ref, isRef := pair[1].Value.(ast.Ref); isRef && r.alwaysDefined(ref) {
					named = append(named, pair[1])
				}
			}
		}
	}
	return named
}

// alwaysDefined reports whether a reference names a collection the policy
// builds and that exists even with nothing in it: a partial set, or a partial
// object.
func (r *refReader) alwaysDefined(ref ast.Ref) bool {
	rules := r.compiler.GetRulesExact(ref)
	if len(rules) == 0 {
		return false
	}
	for _, rule := range rules {
		if rule.Head.RuleKind() != ast.MultiValue && rule.Head.Ref().IsGround() {
			return false
		}
	}
	return true
}

// isZero reports whether a term is the number zero.
func isZero(term *ast.Term) bool {
	n, isNumber := term.Value.(ast.Number)
	if !isNumber {
		return false
	}
	i, isInt := n.Int()
	return isInt && i == 0
}

// isEmptyCollection reports whether a term is an empty set, array or object
// written out.
func isEmptyCollection(term *ast.Term) bool {
	switch value := term.Value.(type) {
	case ast.Set:
		return value.Len() == 0
	case *ast.Array:
		return value.Len() == 0
	case ast.Object:
		return value.Len() == 0
	default:
		return false
	}
}

// fieldExprs returns the expressions of a rule's body that the value of one
// field of what it returns depends on, by index, or nil when every expression
// counts.
//
// The expressions left out are the ones that only build another field, and
// only where leaving them out cannot change whether the rule holds: a variable
// bound to a comprehension, which always has a value, that no other expression
// and not this field uses. In {"allowed": count(v) == 0, "violations": [x | some
// x in v]} that is the list of violations, which reaches the same rule as the
// count does but without the negation, and would otherwise hide on which side
// of the answer the violations are. Anything that can fail stays, whatever it
// computes, since a rule that fails has no fields at all.
//
// The object itself is assembled by one expression that names every field, and
// only the field asked about counts there.
func fieldExprs(rule *ast.Rule, field ast.Ref) map[int]bool {
	body := rule.Body
	assembling := map[int]bool{}
	value := rule.Head.Value
	for _, key := range field {
		object, at, found := objectOf(value, body)
		if !found {
			return nil
		}
		if at >= 0 {
			assembling[at] = true
		}
		if value = object.Get(key); value == nil {
			return nil
		}
	}

	needed := value.Vars()
	kept := map[int]bool{}
	comprehensions := map[int]ast.Var{}
	for i, expr := range body {
		switch v, isComprehension := boundToComprehension(expr); {
		case assembling[i]:
			kept[i] = true
		case isComprehension:
			comprehensions[i] = v
		default:
			kept[i] = true
			needed.Update(expr.Vars(ast.VarVisitorParams{}))
		}
	}
	for grew := true; grew; {
		grew = false
		for i, v := range comprehensions {
			if !kept[i] && needed.Contains(v) {
				kept[i] = true
				needed.Update(body[i].Vars(ast.VarVisitorParams{}))
				grew = true
			}
		}
	}
	if len(kept) == len(body) {
		return nil
	}
	return kept
}

// objectOf returns the object a term is, when it is one written out or a
// variable an equality of the body binds to one, and the index of that
// equality, -1 when there is none.
func objectOf(term *ast.Term, body ast.Body) (ast.Object, int, bool) {
	if object, isObject := term.Value.(ast.Object); isObject {
		return object, -1, true
	}
	v, isVar := varOf(term)
	if !isVar {
		return nil, -1, false
	}
	for i, expr := range body {
		if !expr.IsEquality() {
			continue
		}
		operands := expr.Operands()
		for _, pair := range [][2]*ast.Term{{operands[0], operands[1]}, {operands[1], operands[0]}} {
			if bound, isVar := varOf(pair[0]); isVar && bound == v {
				if object, isObject := pair[1].Value.(ast.Object); isObject {
					return object, i, true
				}
			}
		}
	}
	return nil, -1, false
}

// boundToComprehension returns the variable an equality binds to a
// comprehension, and reports whether the expression is one.
func boundToComprehension(expr *ast.Expr) (ast.Var, bool) {
	if !expr.IsEquality() {
		return "", false
	}
	operands := expr.Operands()
	for _, pair := range [][2]*ast.Term{{operands[0], operands[1]}, {operands[1], operands[0]}} {
		if v, isVar := varOf(pair[0]); isVar && ast.IsComprehension(pair[1].Value) {
			return v, true
		}
	}
	return "", false
}

// decisionsAt returns the decisions that depend on what sits in one expression
// of a rule's body: every decision that reaches the rule, less those that are a
// field of what the rule returns and do not depend on that expression.
func (r *refReader) decisionsAt(rule *ast.Rule, top int, reach map[*ast.Rule]decisionPaths) []ReachedDecision {
	decisions := reachedDecisions(reach[rule])
	fields := r.within[rule]
	if len(fields) == 0 {
		return decisions
	}
	return slices.DeleteFunc(decisions, func(decision ReachedDecision) bool {
		kept, sliced := fields[decision.Name]
		return sliced && !kept[top]
	})
}
