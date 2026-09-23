package opaengine

import (
	"fmt"
	"maps"
	"slices"

	"github.com/open-policy-agent/opa/v1/ast"
)

// This file rewrites the and and or of a rule's body into rules partial
// evaluation can go through. Like the rewrite of else, it produces a policy that
// is compiled apart and only ever partially evaluated.

// maxSplitRules is how many rules one rule may become once every or in its body
// is taken apart. Each or doubles the count, so a body with seven of them would
// already be 128 rules; past the bound the rule is left as written, which
// partial evaluation still answers correctly, only less precisely.
const maxSplitRules = 64

// splitLogical returns a copy of compiled modules where every and and every or
// written at the top of a rule's body is taken apart, or nil when no rule has
// one.
//
// Partial evaluation does not go into either once an operand depends on
// something unknown. It saves the whole expression, with the operands plugged
// but not evaluated (v1/topdown/eval.go:4480 and 4539 at v1.20.2, "a valid, but
// non-optimized PE result"), so the residual still names the documents the
// operands read instead of the requests that make them hold. A decision written
// with or, asked what anybody can get out of it, answers with a reference to
// data.users rather than with the users who hold the role, and a principal the
// data already rules out keeps an operand that can never hold.
//
// What each operator means is plain in the evaluator: an operand is a closed
// scope that holds or does not, and the variables it binds stay inside it
// (v1/topdown/eval.go:4568; v1/ast/compile.go:5419). Written as the rules
// partial evaluation already knows how to take apart, the or of a body is one
// rule per operand, and the and is its two operands one after the other:
//
//	p if { B0; A or C; B1 }    becomes    p if { B0; A; B1 }
//	                                       p if { B0; C; B1 }
//
//	p if { B0; A and C; B1 }   becomes    p if { B0; A; C; B1 }
//
// Keeping an operand closed is what the renaming is for. A variable an operand
// binds and the rest of the rule does not use gets a name of its own, so that
// two operands binding the same name, or an operand and a comprehension
// elsewhere in the rule, do not start meaning the same value once they share a
// body. A variable the rest of the rule binds is shared already, and keeps its
// name.
//
// It works on compiled modules because only there is every variable of a body
// a variable: before compiling, a bare name may just as well be a rule of the
// package or an import, and renaming one of those would change what the policy
// reads. An and or an or nested inside a comprehension, an every or a not is
// left as it is, and so is every rule of a function that carries an else, whose
// branches partial evaluation hands back whole anyway.
func splitLogical(compiled map[string]*ast.Module) map[string]*ast.Module {
	if !hasLogical(compiled) {
		return nil
	}

	modules := make(map[string]*ast.Module, len(compiled))
	for name, module := range compiled {
		modules[name] = module.Copy()
	}
	fresh := freshVars(modules)
	for _, name := range slices.Sorted(maps.Keys(modules)) {
		module := modules[name]
		rules := make([]*ast.Rule, 0, len(module.Rules))
		for _, rule := range module.Rules {
			rules = append(rules, splitRule(rule, fresh)...)
		}
		module.Rules = rules
		// As for the else, the rewritten policy is evaluated and never reported.
		module.Annotations = nil
	}
	closeOperands(modules)
	return modules
}

// hasLogical reports whether any rule has an and or an or at the top of its
// body, which is the only place splitLogical takes one apart.
func hasLogical(modules map[string]*ast.Module) bool {
	for _, module := range modules {
		for _, rule := range module.Rules {
			if rule.Else == nil && logicalAt(rule.Body) >= 0 {
				return true
			}
		}
	}
	return false
}

// logicalAt returns the index of the first and or or of a body, or -1.
func logicalAt(body ast.Body) int {
	for i, expr := range body {
		switch expr.Terms.(type) {
		case *ast.LogicalAnd, *ast.LogicalOr:
			return i
		}
	}
	return -1
}

// splitRule takes apart every and and or at the top of a rule's body, including
// the ones an operand brings up once it is written out in the body.
func splitRule(rule *ast.Rule, fresh func() ast.Var) []*ast.Rule {
	if rule.Else != nil || logicalAt(rule.Body) < 0 {
		return []*ast.Rule{rule}
	}

	pending := []*ast.Rule{rule}
	var done []*ast.Rule
	for len(pending) > 0 {
		if len(pending)+len(done) > maxSplitRules {
			return []*ast.Rule{rule}
		}
		current := pending[0]
		pending = pending[1:]

		at := logicalAt(current.Body)
		if at < 0 {
			done = append(done, current)
			continue
		}
		var ways [][]ast.Body
		switch operator := current.Body[at].Terms.(type) {
		case *ast.LogicalAnd:
			ways = [][]ast.Body{{operator.Lhs, operator.Rhs}}
		case *ast.LogicalOr:
			ways = [][]ast.Body{{operator.Lhs}, {operator.Rhs}}
		}
		for _, operands := range ways {
			split, ok := withOperands(current, at, fresh, operands...)
			if !ok {
				return []*ast.Rule{rule}
			}
			pending = append(pending, split)
		}
	}
	return done
}

// withOperands returns a copy of a rule where the expression at one index is
// replaced by the operands given, one after the other, and reports whether the
// operands could be kept closed.
func withOperands(rule *ast.Rule, at int, fresh func() ast.Var, operands ...ast.Body) (*ast.Rule, bool) {
	outer := topVars(rule.Head)
	for i, expr := range rule.Body {
		if i != at {
			outer.Update(topVars(expr))
		}
	}
	replaced := rule.Body[at]

	body := make([]*ast.Expr, 0, len(rule.Body)+len(operands))
	for _, expr := range rule.Body[:at] {
		body = append(body, expr.Copy())
	}
	for _, operand := range operands {
		closed, ok := closedOperand(operand, outer, fresh)
		if !ok {
			return nil, false
		}
		for _, expr := range closed {
			// A with modifier on the and or the or applies to each operand.
			for _, with := range replaced.With {
				expr.With = append(expr.With, with.Copy())
			}
			body = append(body, expr)
		}
	}
	for _, expr := range rule.Body[at+1:] {
		body = append(body, expr.Copy())
	}

	split := rule.Copy()
	split.Body = ast.NewBody(body...)
	return split, true
}

// closedOperand returns the expressions of an operand, with every variable it
// binds on its own renamed, and reports whether the renaming went through.
//
// It cannot fail with the function it hands to OPA, which never returns an
// error, on a body, which stays a body. Should either stop holding, the caller
// leaves the rule as it is written rather than write out an operand whose
// variables are no longer its own.
func closedOperand(operand ast.Body, outer ast.VarSet, fresh func() ast.Var) (ast.Body, bool) {
	renamed := map[ast.Var]ast.Var{}
	for v := range allVars(operand) {
		if outer.Contains(v) || ast.RootDocumentNames.Contains(ast.NewTerm(v)) {
			continue
		}
		renamed[v] = fresh()
	}

	copied := operand.Copy()
	if len(renamed) == 0 {
		return copied, true
	}
	transformed, err := ast.TransformVars(copied, func(v ast.Var) (ast.Value, error) {
		if name, found := renamed[v]; found {
			return name, nil
		}
		return v, nil
	})
	body, isBody := transformed.(ast.Body)
	return body, err == nil && isBody
}

// topVars returns the variables a node uses outside the comprehensions and
// bodies of its own it holds. Those are the ones that are the rule's.
func topVars(node any) ast.VarSet {
	visitor := ast.NewVarVisitor().WithParams(ast.VarVisitorParams{SkipClosures: true, SkipRefCallHead: true})
	visitor.Walk(node)
	return visitor.Vars()
}

// allVars returns every variable a node uses, the ones of its nested bodies
// included, and not the names of the functions it calls.
func allVars(node any) ast.VarSet {
	visitor := ast.NewVarVisitor().WithParams(ast.VarVisitorParams{SkipRefCallHead: true})
	visitor.Walk(node)
	return visitor.Vars()
}

// freshVars returns a source of variable names no module uses.
func freshVars(modules map[string]*ast.Module) func() ast.Var {
	taken := ast.NewVarSet()
	for _, module := range modules {
		taken.Update(allVars(module))
	}
	next := 0
	return func() ast.Var {
		for {
			name := ast.Var(fmt.Sprintf("__petard_local%d__", next))
			next++
			if !taken.Contains(name) {
				taken.Add(name)
				return name
			}
		}
	}
}

// closeOperands marks every body a not, an and or an or holds as written with
// braces.
//
// The compiler moves what an operand needs into the operand itself, so a not
// written as not data.users[input.user].blocked comes out holding two
// expressions, one binding a variable of its own. A body written without braces
// is checked for safety by a rule of its own, which decides from the shape of
// the body which of its variables must come from outside (v1/ast/compile.go:5132
// at v1.20.2), and the compiled operand no longer has the shape it was written
// with: compiled a second time, it fails the check. With braces it is what the
// first compilation made of it, a closed scope.
func closeOperands(modules map[string]*ast.Module) {
	for _, module := range modules {
		ast.WalkExprs(module, func(expr *ast.Expr) bool {
			switch operator := expr.Terms.(type) {
			case *ast.Not:
				operator.ExplicitBody = true
			case *ast.LogicalAnd:
				operator.ExplicitLhs, operator.ExplicitRhs = true, true
			case *ast.LogicalOr:
				operator.ExplicitLhs, operator.ExplicitRhs = true, true
			}
			return false
		})
	}
}
