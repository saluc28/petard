package opaengine

import (
	"fmt"

	"github.com/open-policy-agent/opa/v1/ast"
)

// Bindings are what a residual condition turned out to say about the parts of
// the request somebody asked about.
type Bindings struct {
	// Values maps each path asked about to the concrete values the condition
	// pins it to. A path the condition says nothing about is absent rather than
	// present and empty.
	Values map[string][]string

	// Unexplained is how many expressions of the condition constrained
	// something else.
	//
	// It is the number that decides whether a capability may be stated flatly.
	// A condition that only names a document says the principal can act on that
	// document; the same condition plus "input.mfa" says they can act on it if
	// they also supply a second factor, and the two must not become the same
	// edge in a graph somebody path finds across.
	Unexplained int
}

// BindingsOf reads a residual condition and reports what it pins the given
// parts of the request to, and how much of it is about something else.
//
// Partial evaluation answers "what is left of this decision" with conditions
// like `input.action = "read"; "d-t11-1" = input.doc`, and that text is where
// the names of the things a principal can act on live. Nothing else in the
// analysis holds them: a policy never lists its documents or its verbs, it
// constrains them, and the constraint is what comes back.
//
// It reads the condition with OPA's own parser rather than by matching strings,
// because the two sides of an equality come back in whichever order the
// evaluator left them, quoting follows Rego's rules and not ours, and a
// condition that is not an equality at all has to be recognized as such instead
// of being pattern matched into one.
//
// Only ground scalars are collected. A condition that ties a path to another
// part of the request says the two must agree and names nothing, and a negated
// equality says which value is refused rather than which is allowed: both count
// as constraining something else, because turning either into a value would
// state the opposite of what the policy does.
func BindingsOf(condition string, paths ...string) (Bindings, error) {
	body, err := ast.ParseBody(condition)
	if err != nil {
		return Bindings{}, fmt.Errorf("opaengine: reading the condition %q: %w", condition, err)
	}

	wanted := make([]ast.Ref, 0, len(paths))
	for _, path := range paths {
		ref, err := ast.ParseRef(path)
		if err != nil {
			return Bindings{}, fmt.Errorf("opaengine: reading the path %s: %w", path, err)
		}
		wanted = append(wanted, ref)
	}

	bindings := Bindings{Values: make(map[string][]string, len(paths))}
	for _, expr := range body {
		path, value, explained := explains(expr, paths, wanted)
		if !explained {
			bindings.Unexplained++
			continue
		}
		bindings.Values[path] = append(bindings.Values[path], value)
	}
	return bindings, nil
}

// explains reports which of the paths asked about an expression pins, and to
// what.
func explains(expr *ast.Expr, paths []string, wanted []ast.Ref) (string, string, bool) {
	if expr.Negated || !expr.IsEquality() {
		return "", "", false
	}
	operands := expr.Operands()
	if len(operands) != 2 {
		return "", "", false
	}

	for i, ref := range wanted {
		if value, found := boundValue(operands[0], operands[1], ref); found {
			return paths[i], value, true
		}
	}
	return "", "", false
}

// boundValue reports the ground value of an equality where the other side is
// the reference asked about, whichever way round the two were written.
func boundValue(left, right *ast.Term, wanted ast.Ref) (string, bool) {
	for _, pair := range [][2]*ast.Term{{left, right}, {right, left}} {
		ref, isRef := pair[0].Value.(ast.Ref)
		if !isRef || !ref.Equal(wanted) {
			continue
		}
		if scalar, isScalar := scalarOf(pair[1]); isScalar {
			return scalar, true
		}
	}
	return "", false
}

// scalarOf returns a term as the value it names, unquoted, when it names one
// value and not a set of them.
//
// A string comes back without its quotes because it is an identity and not a
// piece of Rego: a document called d-1 should be a node called d-1, not one
// called "d-1".
func scalarOf(term *ast.Term) (string, bool) {
	switch value := term.Value.(type) {
	case ast.String:
		return string(value), true
	case ast.Number, ast.Boolean:
		return value.String(), true
	default:
		return "", false
	}
}
