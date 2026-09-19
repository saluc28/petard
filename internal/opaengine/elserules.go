package opaengine

import (
	"fmt"
	"maps"
	"slices"

	"github.com/open-policy-agent/opa/v1/ast"
)

// This file rewrites the rules that carry an else into rules partial evaluation
// can go through. The rewritten policy is compiled apart and only ever
// partially evaluated: the walk reads the policy as it is written.

// exclusiveElse rewrites every complete rule with an else into rules that
// exclude each other, in place, and reports whether it rewrote any.
//
// OPA does not partially evaluate a rule with an else once it depends on
// something unknown. It keeps the reference to the rule and moves on
// (v1/topdown/eval.go:2967 at v1.20.2), so the residual names the rule for
// whoever asks, and a decision behind it reads as granting everybody the same
// way: a principal without the role as much as one who holds it. What an else
// means is plain in the evaluator: the branches of one definition are tried in
// order, and the first whose body has a result gives the value
// (v1/topdown/eval.go:3831 to 3862). Written as rules that say so, each branch
// after the first waits for the ones before it to fail:
//
//	p := v0 if B0 else := v1 if B1
//
// becomes
//
//	p := v0 if B0
//	p := v1 if { not h0; B1 }
//	h0 if B0
//
// Functions keep their else. A function is evaluated against the value it is
// asked for (v1/topdown/eval.go:2291 and 2308), so a branch whose value does
// not match counts as failed and the next one is tried, and branches that
// exclude each other would change what it answers. Partial evaluation still
// hands back a call to one of them whole.
func exclusiveElse(modules map[string]*ast.Module) bool {
	helpers := helperNames(modules, "_petard_else_")

	rewrote := false
	for _, name := range slices.Sorted(maps.Keys(modules)) {
		module := modules[name]
		rules := make([]*ast.Rule, 0, len(module.Rules))
		changed := false
		for _, rule := range module.Rules {
			if rule.Else == nil || len(rule.Head.Args) > 0 {
				rules = append(rules, rule)
				continue
			}
			rules = append(rules, exclusiveBranches(rule, helpers)...)
			changed = true
		}
		if changed {
			module.Rules = rules
			// Annotations point at the rules they were written above, and the
			// rewritten policy is evaluated, never reported: nothing needs them.
			module.Annotations = nil
			rewrote = true
		}
	}
	return rewrote
}

// exclusiveBranches turns one definition with an else into one rule per branch,
// and one helper per branch that others wait on.
func exclusiveBranches(root *ast.Rule, helpers func() ast.Var) []*ast.Rule {
	var (
		rules  []*ast.Rule
		before []*ast.Expr
	)
	for branch := root; branch != nil; branch = branch.Else {
		body := make([]*ast.Expr, 0, len(before)+len(branch.Body))
		for _, failed := range before {
			body = append(body, failed.Copy())
		}
		body = append(body, branch.Body.Copy()...)
		rules = append(rules, &ast.Rule{
			Head:     branch.Head.Copy(),
			Body:     ast.NewBody(body...),
			Module:   root.Module,
			Location: branch.Location,
		})
		if branch.Else == nil {
			break
		}

		helper := helpers()
		head := ast.NewHead(helper, nil, ast.BooleanTerm(true))
		head.Location = branch.Location
		rules = append(rules, &ast.Rule{
			Head:     head,
			Body:     branch.Body.Copy(),
			Module:   root.Module,
			Location: branch.Location,
		})

		failed := ast.NewExpr(ast.VarTerm(string(helper)).SetLocation(branch.Location))
		failed.Negated = true
		failed.Location = branch.Location
		before = append(before, failed)
	}
	return rules
}

// helperNames returns a source of rule names no rule of the bundle has, each the
// prefix followed by a number.
func helperNames(modules map[string]*ast.Module, prefix string) func() ast.Var {
	taken := map[string]bool{}
	for _, module := range modules {
		for _, rule := range module.Rules {
			taken[rule.Head.Ref()[0].Value.String()] = true
		}
	}
	next := 0
	return func() ast.Var {
		for {
			name := fmt.Sprintf("%s%d", prefix, next)
			next++
			if !taken[name] {
				taken[name] = true
				return ast.Var(name)
			}
		}
	}
}
