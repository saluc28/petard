package opaengine

import (
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
)

// This file reads the builtins that match a part of the request more loosely
// than equality: a substring, a prefix or suffix, a glob, an unanchored regex.
// A linter sees startswith(input.path, "/admin") as a function call; the engine
// reads it as a check on the request, because a value that merely embeds the one
// the policy writes can satisfy it. It is what PTD-OPA-012 looks for, and what
// PTD-OPA-009 and PTD-OPA-010 missed while only == and in counted as checks.

// looseMatchBuiltin says, for one boolean string-matching builtin, which operand
// carries the part of the request, which carries the value the policy writes,
// and the loose form the match takes. glob.match takes the matched string last
// and the pattern first; the others take the subject first.
type looseMatchBuiltin struct {
	requestArg int
	valueArg   int
	operator   CheckOperator
}

// looseMatchBuiltins are the string-matching builtins a rule can assert as a
// condition, by their canonical names.
var looseMatchBuiltins = map[string]looseMatchBuiltin{
	"contains":    {requestArg: 0, valueArg: 1, operator: CheckSubstring},
	"startswith":  {requestArg: 0, valueArg: 1, operator: CheckPrefix},
	"endswith":    {requestArg: 0, valueArg: 1, operator: CheckSuffix},
	"glob.match":  {requestArg: 2, valueArg: 0, operator: CheckGlob},
	"regex.match": {requestArg: 1, valueArg: 0, operator: CheckRegex},
}

// foundMatch is a loose string match met while walking, kept with what its body
// knew, because resolving the request side means asking the call sites once the
// walk is over, the same as a comparison.
type foundMatch struct {
	exprSite
	request  *ast.Term
	value    *ast.Term
	operator CheckOperator
}

// markMatches records a loose string match an expression asserts.
//
// Only an asserted call counts. startswith(a, b) as a condition holds when a
// starts with b; x := startswith(a, b) binds x and asserts nothing, the line
// equal and equality already draw. An asserted call carries exactly the
// builtin's arity in operands, with no extra operand for a captured result.
func (r *refReader) markMatches(expr *ast.Expr, sc scope) {
	operator := expr.Operator()
	if operator == nil || len(expr.With) > 0 {
		return
	}
	spec, known := looseMatchBuiltins[operator.String()]
	if !known {
		return
	}
	builtin, declared := ast.BuiltinMap[operator.String()]
	if !declared || builtin.Decl == nil {
		return
	}
	operands := expr.Operands()
	if len(operands) != builtin.Decl.Arity() {
		return
	}
	r.foundMatches = append(r.foundMatches, foundMatch{
		exprSite: r.site(sc, expr.Loc()),
		request:  operands[spec.requestArg],
		value:    operands[spec.valueArg],
		operator: spec.operator,
	})
}

// anchoredRegex reports whether a regex pattern pins both ends, which makes
// regex.match a whole-string test rather than the loose mid-string one. A value
// the policy writes anchored is matched as a whole, so it is left to the other
// checks rather than read as a loose match.
func anchoredRegex(value *ast.Term) bool {
	str, isString := value.Value.(ast.String)
	if !isString {
		return false
	}
	pattern := string(str)
	return strings.HasPrefix(pattern, "^") && strings.HasSuffix(pattern, "$")
}
