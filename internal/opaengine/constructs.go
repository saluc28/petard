package opaengine

import (
	"github.com/open-policy-agent/opa/v1/ast"
)

// Constructs counts the Rego forms of a bundle that the resolver has to
// understand.
//
// It exists to answer a question the fixture cannot: which of the edge cases
// the design worried about show up in policies written by other people, and how
// often. The counts are over the whole compiled bundle rather than over the
// rules the decisions reach, because a bundle whose decisions cannot be found
// still has forms worth counting, and a number that silently changed meaning
// when the walk failed would be the wrong number to compare across a corpus.
//
// What the walk of the decisions met, as opposed to what the source holds, is
// already in the ReadSet: reads carry their negation and the call chain that
// resolved them, and the rules a with modifier hides are listed there.
type Constructs struct {
	// Packages and Rules are the size of the bundle, so that every other count
	// can be read as a share of something.
	Packages int
	Rules    int

	// Functions are the rules that take formal parameters, which is the case
	// that made the interprocedural walk necessary: inside the body nothing
	// binds a parameter to a term, the binding sits at the call.
	Functions int

	// With counts the expressions carrying a with modifier, whose reads and
	// callees are left out of the decisions.
	With int

	// Every and Comprehensions count the bodies with a scope of their own, which
	// a flat pass over the enclosing body does not see.
	Every          int
	Comprehensions int

	// Negations counts the negated expressions anywhere in the bundle, which is
	// exact rather than inferred because Expr.Negated is a bool.
	Negations int

	// Defaults counts the rules that declare a fallback value, the difference
	// between a check that answers no and one that goes silent.
	Defaults int
}

// Constructs counts the forms of the bundle. See the type for what is counted.
//
// Two things are absent and neither can be had here. some x in xs is desugared
// into ordinary indexed iteration before anything can see it, which is exactly
// why it needed no work. And import statements are gone: the compiler resolves
// them into the references that used them and then clears the list
// (Compiler.removeImports, v1/ast/compile.go:2273 at v1.19.0), so a count taken
// on the compiled AST would report zero for a module full of them. Nothing
// about behavior is lost, since the references carry what the imports meant,
// but the statements themselves are not there to count.
func (b *Bundle) Constructs() Constructs {
	var counts Constructs

	for _, module := range b.Compiler.Modules {
		counts.Packages++

		ast.WalkRules(module, func(rule *ast.Rule) bool {
			counts.Rules++
			if len(rule.Head.Args) > 0 {
				counts.Functions++
			}
			if rule.Default {
				counts.Defaults++
			}
			return false
		})

		ast.WalkExprs(module, func(expr *ast.Expr) bool {
			if len(expr.With) > 0 {
				counts.With++
			}
			if expr.Negated {
				counts.Negations++
			}
			if expr.IsEvery() {
				counts.Every++
			}
			return false
		})

		ast.WalkTerms(module, func(term *ast.Term) bool {
			switch term.Value.(type) {
			case *ast.ArrayComprehension, *ast.SetComprehension, *ast.ObjectComprehension:
				counts.Comprehensions++
			}
			return false
		})
	}
	return counts
}
