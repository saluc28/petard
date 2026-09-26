package opaengine

import (
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
)

// GrantContent is what a decision grants a principal, read from the residual
// conditions as the constraint each one puts on the request rather than as a
// count of them.
//
// It exists because counting the conditions cannot tell a real escalation from
// a wider count. A decision that grants any action on any resource is written
// in one condition; joining a policy that grants a single action adds a second
// condition, and by the count the principal now reaches more. By the content
// they reach nothing new, because the single action was already covered by the
// any. Comparing content is what separates the two.
type GrantContent struct {
	conditions []grantCondition

	// always is the decision holding whatever the request turns out to be:
	// nothing is left to cover, and nothing can be reached beyond it.
	always bool

	// whole is false when the residual was cut short by a bound, so a condition
	// that would cover another may be missing from the list.
	whole bool
}

// grantCondition is one way a decision grants, as the constraint it puts on
// each part of the request. A field it does not name is unconstrained, which is
// the most permissive a field can be.
type grantCondition struct {
	fields map[string]fieldConstraint

	// opaque names the fields the condition constrains in a way this does not
	// read, so their real constraint is unknown. A field is tracked one at a
	// time because a gain shown on a field that is read stays certain however
	// unreadable another field of the same condition is.
	opaque map[string]bool

	// opaqueOther is true when the condition constrains the request somewhere
	// this could not attribute to a field, so no coverage through it is certain.
	opaqueOther bool
}

// fieldConstraint is what one condition allows one field of the request to be.
type fieldConstraint struct {
	// any is true when any value satisfies the field: it is read but pinned to
	// nothing, or matched against the empty prefix.
	any bool

	// values are the values an equality pins the field to, or, when member is
	// true, the values a collection must contain.
	values map[string]bool
	member bool

	// prefixes are the prefixes the field must start with, from a wildcard
	// match. A field satisfies the condition when it equals one of the values
	// or starts with one of the prefixes.
	prefixes map[string]bool
}

// GrantContentOf reads a residual set as the content of what it grants.
func GrantContentOf(rs *ResidualSet) GrantContent {
	content := GrantContent{always: rs.Always, whole: !rs.Truncated}
	for _, condition := range rs.Conditions {
		content.conditions = append(content.conditions, readGrantCondition(condition.Query))
	}
	return content
}

// readGrantCondition reads one residual condition into the constraint it puts
// on each field of the request. What it cannot read, it records as opaque, so a
// later comparison knows which fields it may not reason about.
func readGrantCondition(query string) grantCondition {
	condition := grantCondition{fields: map[string]fieldConstraint{}, opaque: map[string]bool{}}
	body, err := ast.ParseBody(query)
	if err != nil {
		condition.opaqueOther = true
		return condition
	}
	for _, expr := range body {
		condition.apply(expr)
	}
	return condition
}

// apply reads one expression into the condition: an equality as a value or
// membership, a wildcard match as a prefix, and anything else that constrains
// the request as opaque on the fields it touches. An expression that does not
// constrain the request is ignored.
func (c *grantCondition) apply(expr *ast.Expr) {
	if expr.IsEquality() {
		if operands := expr.Operands(); len(operands) == 2 {
			if field, member, isInput := inputField(operands[0]); isInput {
				c.bind(field, member, operands[1])
				return
			}
			if field, member, isInput := inputField(operands[1]); isInput {
				c.bind(field, member, operands[0])
				return
			}
			// Neither side is a part of the request. Input read inside a call,
			// as split(input.action, ":"), derives a value rather than
			// constraining one, and the field it reads is constrained, if at
			// all, by another expression of the same condition.
			return
		}
	}

	if field, prefix, ok := prefixMatch(expr); ok {
		c.bindPrefix(field, prefix)
		return
	}

	// A part of the request used as a truth test, input.mfa, or compared by a
	// builtin this does not read, constrains it in a way this cannot turn into
	// values. A negated equality refuses a value rather than allowing one. Mark
	// the fields it touches opaque; a constraint this cannot attribute to a
	// field leaves the whole condition unreadable.
	touched := inputFieldsOf(expr)
	if len(touched) == 0 {
		return
	}
	for _, field := range touched {
		c.opaque[field] = true
	}
}

// bind records what an equality says one field of the request may be: a value,
// a membership, or anything at all when the other side is a variable. An input
// field pinned to a computed value this cannot name is recorded opaque.
func (c *grantCondition) bind(field string, member bool, other *ast.Term) {
	constraint := c.fields[field]
	constraint.member = constraint.member || member

	if _, isVar := other.Value.(ast.Var); isVar {
		constraint.any = true
		c.fields[field] = constraint
		return
	}
	if scalar, isScalar := scalarOf(other); isScalar {
		if constraint.values == nil {
			constraint.values = map[string]bool{}
		}
		constraint.values[scalar] = true
		c.fields[field] = constraint
		return
	}
	c.opaque[field] = true
}

// bindPrefix records a wildcard match on a field. The empty prefix, which a
// match against "*" leaves behind, allows any value.
func (c *grantCondition) bindPrefix(field, prefix string) {
	constraint := c.fields[field]
	if prefix == "" {
		constraint.any = true
		c.fields[field] = constraint
		return
	}
	if constraint.prefixes == nil {
		constraint.prefixes = map[string]bool{}
	}
	constraint.prefixes[prefix] = true
	c.fields[field] = constraint
}

// prefixMatch reads a startswith on a field of the request, as a wildcard match
// of a policy leaves behind, and returns the field and the prefix.
func prefixMatch(expr *ast.Expr) (field, prefix string, ok bool) {
	if expr.Negated || !expr.IsCall() {
		return "", "", false
	}
	operator := expr.Operator()
	if operator == nil || operator.String() != "startswith" {
		return "", "", false
	}
	operands := expr.Operands()
	if len(operands) != 2 {
		return "", "", false
	}
	name, member, isInput := inputField(operands[0])
	if !isInput || member {
		return "", "", false
	}
	literal, isScalar := scalarOf(operands[1])
	if !isScalar {
		return "", "", false
	}
	return name, literal, true
}

// inputField reports the field of the request a term reads, and whether it
// reads it as a collection whose elements are searched, input.projects[_],
// rather than as a value, input.action.
func inputField(term *ast.Term) (string, bool, bool) {
	ref, isRef := term.Value.(ast.Ref)
	if !isRef || !isInputRooted(ref) || len(ref) < 2 {
		return "", false, false
	}
	if _, isVar := ref[len(ref)-1].Value.(ast.Var); isVar {
		return normalize(ref[:len(ref)-1]), true, true
	}
	return normalize(ref), false, true
}

// inputFieldsOf returns the fields of the request an expression reads, so that
// a constraint this cannot read is charged to the fields it is about and no
// others.
func inputFieldsOf(expr *ast.Expr) []string {
	var fields []string
	seen := map[string]bool{}
	add := func(field string) {
		if !seen[field] {
			seen[field] = true
			fields = append(fields, field)
		}
	}
	if term, ok := expr.Terms.(*ast.Term); ok {
		if field, _, isInput := inputField(term); isInput {
			add(field)
		}
	}
	ast.WalkRefs(expr, func(ref ast.Ref) bool {
		if !isInputRooted(ref) || len(ref) < 2 {
			return false
		}
		if last := ref[len(ref)-1]; isVar(last) {
			add(normalize(ref[:len(ref)-1]))
		} else {
			add(normalize(ref))
		}
		return false
	})
	return fields
}

func isVar(term *ast.Term) bool {
	_, ok := term.Value.(ast.Var)
	return ok
}

// coverage is how one condition stands to another: it covers it, the covered
// one escapes it with a request it does not grant, or the two cannot be told
// apart because one reads a field the other constrains opaquely.
type coverage int

const (
	unknownCoverage coverage = iota
	covers
	escapes
)

// Beyond reports whether this decision grants a request the other does not, and
// whether the answer is certain.
//
// It is certain and true when some way this decision grants escapes every one
// of the other's, each comparison having been one it could make. It is certain
// and false when every way is covered. It is not certain when a comparison could
// not be made or the residual was cut short, and then the caller reports a
// candidate rather than a finding: a gain that cannot be proven is not claimed.
func (g GrantContent) Beyond(other GrantContent) (beyond, certain bool) {
	if other.always {
		return false, true
	}
	if g.always {
		return true, true
	}

	uncertain := !g.whole || !other.whole
	for _, condition := range g.conditions {
		escaped := true
		for _, o := range other.conditions {
			switch coverageOf(o, condition) {
			case covers:
				escaped = false
			case unknownCoverage:
				escaped = false
				uncertain = true
			}
			if !escaped {
				break
			}
		}
		// Escapes every one of the other's conditions, and the other is all in
		// hand: a bound that cut them short may have dropped the one that covers
		// this.
		if escaped && other.whole {
			return true, true
		}
	}
	return false, !uncertain
}

// coverageOf reports how the covering condition stands to the covered one:
// whether every request the covered condition grants is also granted by the
// covering one.
//
// The covering condition has to be at least as permissive on every field it
// pins: a field it leaves open covers any value, and a field it pins covers only
// a covered condition that pins the same field no wider. A field either reads
// opaquely stops the comparison, unless the covered condition already escapes on
// a field both read.
func coverageOf(covering, covered grantCondition) coverage {
	if covered.opaqueOther {
		return unknownCoverage
	}

	for field, want := range covering.fields {
		if want.any {
			continue
		}
		if covering.opaque[field] || covered.opaque[field] {
			return unknownCoverage
		}
		have, named := covered.fields[field]
		if !named {
			// The covered condition allows values the covering one forbids.
			return escapes
		}
		if have.member != want.member {
			return unknownCoverage
		}
		if !within(have, want) {
			return escapes
		}
	}

	// Every field the covering condition pins is covered. It covers the other
	// only if it constrains nothing else opaquely, which would narrow it below
	// what was compared.
	if covering.opaqueOther || len(covering.opaque) > 0 {
		return unknownCoverage
	}
	return covers
}

// within reports whether every value the covered constraint allows is allowed
// by the covering one.
func within(covered, covering fieldConstraint) bool {
	if covering.any {
		return true
	}
	if covered.any {
		return false
	}
	if covering.member {
		// A membership grants when the collection holds each named value, so
		// the covered condition is within only if it requires at least what the
		// covering one does.
		return subset(covering.values, covered.values)
	}
	for value := range covered.values {
		if !allows(covering, value) {
			return false
		}
	}
	for prefix := range covered.prefixes {
		// A whole prefix is covered only by a prefix of it: everything starting
		// with the longer one starts with the shorter. A finite set of values
		// cannot cover the infinite set a prefix allows.
		if !prefixCovered(covering, prefix) {
			return false
		}
	}
	return true
}

// allows reports whether a value satisfies a constraint: it is one of the
// values, or it starts with one of the prefixes.
func allows(constraint fieldConstraint, value string) bool {
	if constraint.values[value] {
		return true
	}
	for prefix := range constraint.prefixes {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

// prefixCovered reports whether a constraint covers everything a prefix allows,
// which holds only when it has a prefix of it.
func prefixCovered(constraint fieldConstraint, prefix string) bool {
	for covering := range constraint.prefixes {
		if strings.HasPrefix(prefix, covering) {
			return true
		}
	}
	return false
}

// subset reports whether every value of a is a value of b.
func subset(a, b map[string]bool) bool {
	for value := range a {
		if !b[value] {
			return false
		}
	}
	return true
}
