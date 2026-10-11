package opaengine

import (
	"regexp/syntax"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
)

// This file reads the builtins that match a part of the request more loosely
// than equality: a substring, a prefix or suffix, a glob, an unanchored regex.
// A linter sees startswith(input.path, "/admin") as a function call; the engine
// reads it as a check on the request, because a value that merely embeds the one
// the policy writes can satisfy it. It is what PTD-OPA-012 looks for, and
// PTD-OPA-009, PTD-OPA-010 and PTD-OPA-011 read it as a check like == and in.

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

// matchForm is how much of a value a pattern has to cover to match it.
type matchForm int

const (
	// formEmbedded matches a value that holds the pattern anywhere inside it.
	formEmbedded matchForm = iota

	// formAffix matches a value pinned to the pattern at one end, or by a
	// pattern with a wildcard somewhere other than at both ends.
	formAffix

	// formWhole matches the whole value and nothing wider.
	formWhole
)

// formOf reads the pattern of a regex or a glob and says which check the match
// is: the loose form it takes, an equality, or none.
//
// regex.match and glob.match are one builtin each for matches as far apart as
// an equality and a substring, and the difference is in the pattern. The other
// builtins say their form by their name, and are returned as they are.
func formOf(operator CheckOperator, value *ast.Term) (CheckOperator, bool) {
	pattern, isString := value.Value.(ast.String)
	if !isString {
		return operator, true
	}
	switch operator {
	case CheckRegex:
		switch regexForm(string(pattern)) {
		case formWhole:
			// Both ends pinned in every alternative: a test of the whole value,
			// which may still be a pattern and so is no equality either.
			return "", false
		case formAffix:
			return CheckRegexAnchored, true
		}
	case CheckGlob:
		switch globForm(string(pattern)) {
		case formWhole:
			return CheckEqual, true
		case formEmbedded:
			return CheckGlobEmbedded, true
		}
	}
	return operator, true
}

// globForm reads a glob. With no wildcard in it the pattern matches itself and
// nothing else; with one at each end it matches whatever holds what is between
// them; anything else is a wildcard a route is usually written with.
func globForm(pattern string) matchForm {
	switch {
	case !strings.ContainsAny(pattern, `*?[{\`):
		return formWhole
	case strings.Trim(pattern, "*") == "":
		// All wildcard: it matches anything, and embeds nothing to speak of.
		return formAffix
	case strings.HasPrefix(pattern, "*") && strings.HasSuffix(pattern, "*"):
		return formEmbedded
	default:
		return formAffix
	}
}

// regexForm reads a regex the way OPA compiles one, with Go's regexp syntax
// (regex.match compiles its pattern with regexp.Compile, in getRegexp,
// v1/topdown/regex.go:142 at v1.21.1).
//
// An alternation is as loose as its loosest branch: ^/public|/health$ pins one
// end in each branch and both in neither, so a value only has to start one way
// or end the other. A branch with no end pinned matches anywhere inside the
// value. A pattern that does not parse is left as the loosest form, since OPA
// would refuse it before it matched anything.
func regexForm(pattern string) matchForm {
	parsed, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return formEmbedded
	}
	form := formWhole
	for _, branch := range anchorsOf(parsed) {
		switch {
		case !branch.start && !branch.end:
			return formEmbedded
		case !branch.start || !branch.end:
			form = formAffix
		}
	}
	return form
}

// anchors says which ends of the value one branch of a regex is pinned to.
type anchors struct{ start, end bool }

// anchorsOf returns the ends each branch of a regex pins, one entry for every
// way through its alternations.
//
// Only \A, \z and the ^ and $ that mean them pin an end: under (?m) the two
// match at any line of the value, and a value can carry a newline. An end
// pinned and then opened again with .* is not pinned: ^.*admin.*$ matches
// whatever embeds admin.
func anchorsOf(re *syntax.Regexp) []anchors {
	switch re.Op {
	case syntax.OpBeginText:
		return []anchors{{start: true}}
	case syntax.OpEndText:
		return []anchors{{end: true}}
	case syntax.OpCapture:
		return anchorsOf(re.Sub[0])
	case syntax.OpAlternate:
		var branches []anchors
		for _, sub := range re.Sub {
			branches = append(branches, anchorsOf(sub)...)
		}
		return branches
	case syntax.OpConcat:
		if len(re.Sub) == 1 {
			return anchorsOf(re.Sub[0])
		}
		first, last := re.Sub[0], re.Sub[len(re.Sub)-1]
		opensStart := first.Op == syntax.OpBeginText && matchesAnything(re.Sub[1])
		opensEnd := last.Op == syntax.OpEndText && matchesAnything(re.Sub[len(re.Sub)-2])

		var branches []anchors
		for _, head := range anchorsOf(first) {
			for _, tail := range anchorsOf(last) {
				branches = append(branches, anchors{start: head.start && !opensStart, end: tail.end && !opensEnd})
			}
		}
		return branches
	default:
		return []anchors{{}}
	}
}

// matchesAnything reports whether a piece of a regex matches any run of
// characters, as .* and .+ do.
func matchesAnything(re *syntax.Regexp) bool {
	for re.Op == syntax.OpCapture {
		re = re.Sub[0]
	}
	unbounded := re.Op == syntax.OpStar || re.Op == syntax.OpPlus || (re.Op == syntax.OpRepeat && re.Max == -1)
	if !unbounded {
		return false
	}
	any := re.Sub[0]
	return any.Op == syntax.OpAnyChar || any.Op == syntax.OpAnyCharNotNL
}
