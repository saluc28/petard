package opaengine

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
)

// This file finds where a decision holds a part of the request against a value
// the policy writes itself: input.session.teams[_] == "DevOps", "admin" in
// input.roles, not input.emergency. A read of data says which document a
// decision depends on; a check says which values of the request it grants or
// refuses on, and who can put that value in the request is a question the
// policy cannot answer, the same way it cannot say who writes a document.

// Check is one place a decision compares a part of the request with a value
// written in the policy.
type Check struct {
	// Request is the part of the request, as a path with every dynamic segment
	// written [_]: input.session.teams[_].
	Request string

	// Value is what it is held against, as Rego: "DevOps", {"prod", "staging"}.
	// It is empty when the expression is the part of the request itself, which
	// holds when that part is there and is not false.
	Value string

	// Operator says how the two are held against each other. See CheckEqual.
	Operator CheckOperator

	// Rule is the rule the expression sits in, File and Line where.
	Rule string
	File string
	Line int

	// Block identifies the physical rule the expression sits in, as the file and
	// line of that rule's head. Two allow blocks in one package share a Rule
	// path, so Block is what tells the checks of one write endpoint from the
	// checks of another written just below it.
	Block string

	// UnderNegation is true when the expression sits under an odd number of
	// negations inside its rule, as not input.emergency does.
	UnderNegation bool

	// Decisions are the entrypoints the check reaches, sorted by name.
	Decisions []CheckedDecision
}

// CheckOperator is how a check holds the request against its value.
type CheckOperator string

const (
	// CheckEqual is the request compared with the value whole:
	// input.session.teams[_] == "DevOps".
	CheckEqual CheckOperator = "=="

	// CheckIn is the request searched in the value:
	// input.environment in {"prod", "staging"}.
	CheckIn CheckOperator = "in"

	// CheckContains is the value searched in the request:
	// "DevOps" in input.session.teams.
	CheckContains CheckOperator = "contains"

	// CheckTrue is the request on its own, asked to be there and not false:
	// input.emergency.
	CheckTrue CheckOperator = ""

	// CheckSubstring is the request searched for a value anywhere inside it:
	// contains(input.path, "/admin"). A value that embeds the one the policy
	// writes passes, which equality would not let through.
	CheckSubstring CheckOperator = "substring"

	// CheckPrefix is the request matched at its start:
	// startswith(input.path, "/admin/").
	CheckPrefix CheckOperator = "prefix"

	// CheckSuffix is the request matched at its end:
	// endswith(input.name, ".read").
	CheckSuffix CheckOperator = "suffix"

	// CheckGlob is the request matched against a glob:
	// glob.match("/do/**", [], input.path).
	CheckGlob CheckOperator = "glob"

	// CheckRegex is the request matched against an unanchored regex:
	// regex.match("admin", input.path). An anchored pattern is a whole-string
	// test and is not read as a loose match.
	CheckRegex CheckOperator = "regex"
)

// Loose reports whether the operator matches a part of the request more loosely
// than equality or membership, so a value the policy did not write can satisfy
// it. These are the forms PTD-OPA-012 reads, and the ones PTD-OPA-009 and
// PTD-OPA-010 missed while only == and in counted as checks.
func (o CheckOperator) Loose() bool {
	switch o {
	case CheckSubstring, CheckPrefix, CheckSuffix, CheckGlob, CheckRegex:
		return true
	default:
		return false
	}
}

// MidString reports whether the match accepts the written value embedded
// anywhere in the request, not only as the whole value, a prefix or a suffix. A
// substring and an unanchored regex are the forms a crafted value slips through,
// the confused deputy PTD-OPA-012 reports as a finding rather than a candidate.
func (o CheckOperator) MidString() bool {
	return o == CheckSubstring || o == CheckRegex
}

// Expression writes the check back as Rego, the way a report prints it.
func (c Check) Expression() string {
	switch c.Operator {
	case CheckEqual:
		return c.Request + " == " + c.Value
	case CheckIn:
		return c.Request + " in " + c.Value
	case CheckContains:
		return c.Value + " in " + c.Request
	case CheckSubstring:
		return "contains(" + c.Request + ", " + c.Value + ")"
	case CheckPrefix:
		return "startswith(" + c.Request + ", " + c.Value + ")"
	case CheckSuffix:
		return "endswith(" + c.Request + ", " + c.Value + ")"
	case CheckGlob:
		return "glob.match(" + c.Value + ", _, " + c.Request + ")"
	case CheckRegex:
		return "regex.match(" + c.Value + ", " + c.Request + ")"
	default:
		return c.Request
	}
}

// CheckedDecision is one decision a check reaches, and what the check holding
// does to it.
type CheckedDecision struct {
	Name string

	// Grants is true when, on some way from the decision down to the check,
	// the check holding moves the decision towards granting. It is the side
	// the parity of every negation on the way gives, the one on the expression
	// included, and a decision declared to deny starts on the side that denies.
	Grants bool

	// Exception is true when it does so by lifting a refusal: on that way the
	// check crosses a negation, so it holds inside something that would refuse,
	// as an exemption does. not input.emergency in a rule a decision asks not
	// to hold is one, and so is a match against a list of exemptions a
	// violation asks not to hold. input.action == "read" in a rule that grants
	// is not: it says what is asked for, and nothing it lifts would refuse.
	// Meeting a condition of a rule that refuses reads the same way, a
	// container that sets its limits in an admission review, and only who sets
	// the part of the request tells the two apart.
	Exception bool
}

// foundTruth is a part of the request met as an expression of its own.
type foundTruth struct {
	exprSite
	term *ast.Term
}

// markTruth records an expression that is one term, for the checks: when the
// term turns out to be a part of the request, the expression asks that part to
// be true.
func (r *refReader) markTruth(term *ast.Term, sc scope) {
	switch term.Value.(type) {
	case ast.Ref, ast.Var:
	default:
		return
	}
	r.foundTruths = append(r.foundTruths, foundTruth{exprSite: r.site(sc, term.Loc()), term: term})
}

// checks judges every comparison and every lone term met while walking, and
// keeps the ones that hold a part of the request against a value the policy
// writes, with the decisions each reaches.
func (r *refReader) checks(limits Limits) ([]Check, map[string]string, []string) {
	var checks []Check
	var warnings []string
	pathShapes := map[string]string{}
	keep := func(at exprSite, request string, value *ast.Term, operator CheckOperator) {
		check := Check{
			Request:       request,
			Operator:      operator,
			Rule:          rulePath(at.rule).String(),
			UnderNegation: at.negated,
			Decisions:     r.checkedDecisions(at),
		}
		if len(check.Decisions) == 0 {
			return
		}
		if value != nil {
			check.Value = value.String()
		}
		location := at.location
		if location == nil {
			location = at.rule.Loc()
		}
		if location != nil {
			check.File, check.Line = location.File, location.Row
		}
		check.Block = blockID(at.rule)
		checks = append(checks, check)
	}

	for _, compared := range r.foundComparisons {
		budget := &callBudget{limits: limits}
		// An equality is symmetric and either side can be the request. A
		// search is not, and either side can be the request there too: the
		// request searched for a value, or searched in a list of values. The
		// element is on the left of a search.
		orientations := []struct {
			request, value *ast.Term
			operator       CheckOperator
		}{
			{compared.left, compared.right, CheckEqual},
			{compared.right, compared.left, CheckEqual},
		}
		if compared.member {
			orientations[0].operator, orientations[1].operator = CheckIn, CheckContains
		}
		for _, oriented := range orientations {
			request, isRequest := r.requestOf(compared.rule, oriented.request, compared.bindings, budget)
			if !isRequest {
				continue
			}
			// A request path held against an array is the shape of an endpoint,
			// even when the array holds variables and so is no constant: the
			// literals are the fixed segments and the variables the ones the
			// request fills. It is what a write endpoint's path is, so it is kept
			// apart from the constant checks, by the block it sits in.
			if strings.HasSuffix(request, ".path") {
				if array, isArray := oriented.value.Value.(*ast.Array); isArray {
					if shape, ok := r.pathShape(array, compared.bindings); ok {
						pathShapes[blockID(compared.rule)] = shape
					}
				}
			}
			value, isConstant := constantOf(oriented.value, compared.bindings)
			if !isConstant {
				continue
			}
			keep(compared.exprSite, request, value, oriented.operator)
		}
		warnings = append(warnings, budget.warnings...)
	}

	for _, truth := range r.foundTruths {
		budget := &callBudget{limits: limits}
		if request, isRequest := r.requestOf(truth.rule, truth.term, truth.bindings, budget); isRequest {
			keep(truth.exprSite, request, nil, CheckTrue)
		}
		warnings = append(warnings, budget.warnings...)
	}

	for _, match := range r.foundMatches {
		budget := &callBudget{limits: limits}
		request, isRequest := r.requestOf(match.rule, match.request, match.bindings, budget)
		if isRequest {
			if value, isConstant := constantOf(match.value, match.bindings); isConstant {
				// An anchored regex matches the whole string, so it is not a loose
				// match; the other checks already read it as what it is.
				if match.operator != CheckRegex || !anchoredRegex(value) {
					keep(match.exprSite, request, value, match.operator)
				}
			}
		}
		warnings = append(warnings, budget.warnings...)
	}

	slices.SortFunc(checks, compareChecks)
	return slices.CompactFunc(checks, func(a, b Check) bool { return compareChecks(a, b) == 0 }), pathShapes, warnings
}

// blockID identifies a physical rule by its head's file and line, so two allow
// blocks that share a rule path can be told apart.
func blockID(rule *ast.Rule) string {
	if rule == nil {
		return ""
	}
	if head := rule.Loc(); head != nil {
		return fmt.Sprintf("%s:%d", head.File, head.Row)
	}
	return ""
}

// pathShape renders a request path held against an array as the segments the
// endpoint fixes: a literal is kept as written, a variable becomes a {name}
// placeholder, in the write model's notation. It gives up, returning false, on
// an element that is neither, since a shape it cannot read in full would mislead.
func (r *refReader) pathShape(array *ast.Array, bindings map[ast.Var]binding) (string, bool) {
	parts := make([]string, 0, array.Len())
	for i := 0; i < array.Len(); i++ {
		element := array.Elem(i)
		if constant, ok := constantOf(element, bindings); ok {
			parts = append(parts, constant.String())
			continue
		}
		variable, isVar := varOf(element)
		if !isVar {
			return "", false
		}
		name, named := r.varName(variable)
		if !named {
			return "", false
		}
		parts = append(parts, `"{`+name+`}"`)
	}
	if len(parts) == 0 {
		return "", false
	}
	return "[" + strings.Join(parts, ", ") + "]", true
}

// varName is the name the author gave a variable, through the table the compiler
// keeps of the names it rewrote, and false for one the author never wrote.
func (r *refReader) varName(variable ast.Var) (string, bool) {
	if original, found := r.compiler.RewrittenVars[variable]; found {
		return original.String(), true
	}
	if variable.IsGenerated() {
		return "", false
	}
	return variable.String(), true
}

// compareChecks orders checks the way they are reported, by where they are and
// then by what they compare, and says when two are the same one: a comparison
// a function makes is found at every call as well as in the function.
func compareChecks(a, b Check) int {
	return cmp.Or(
		strings.Compare(a.File, b.File),
		cmp.Compare(a.Line, b.Line),
		strings.Compare(a.Rule, b.Rule),
		strings.Compare(a.Request, b.Request),
		strings.Compare(a.Value, b.Value),
	)
}

// constantOf returns the value a term stands for when the policy writes it out:
// a string, a number, a boolean, or a collection of them. A reference is not
// one, even with no variable in it, since it names a document or a rule.
func constantOf(term *ast.Term, bindings map[ast.Var]binding) (*ast.Term, bool) {
	if v, isVar := varOf(term); isVar {
		if resolved := resolveVar(v, bindings); resolved.status == resolvedTerm {
			return constantOf(resolved.term, bindings)
		}
		return nil, false
	}
	if !term.IsGround() {
		return nil, false
	}
	constant := true
	ast.WalkRefs(term, func(ast.Ref) bool {
		constant = false
		return true
	})
	return term, constant
}

// checkedDecisions says which decisions reach a check where the walk met it,
// and what the check holding does to each.
func (r *refReader) checkedDecisions(at exprSite) []CheckedDecision {
	fields := r.within[at.rule]
	var decisions []CheckedDecision
	for name, ways := range r.ways[at.rule] {
		if kept, sliced := fields[name]; sliced && !kept[at.top] {
			// The expression only builds another field of what the rule
			// returns, and this decision is not asked about it.
			continue
		}
		decision := CheckedDecision{Name: name}
		for way := range ways {
			if way.grants == at.negated {
				// Holding lands on the side that refuses on this way.
				continue
			}
			decision.Grants = true
			// A negated expression that grants sits in a rule on the side that
			// refuses, and every flip of the side is a negation, so the way
			// there has crossed one already.
			decision.Exception = decision.Exception || way.crossed
		}
		decisions = append(decisions, decision)
	}
	slices.SortFunc(decisions, func(a, b CheckedDecision) int {
		return strings.Compare(a.Name, b.Name)
	})
	return decisions
}
