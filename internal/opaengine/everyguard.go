package opaengine

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage"
)

// This file asks what an every being vacuously true is worth to a decision. An
// every over an empty collection holds, whatever its body says. Whether that
// lets a request through depends on everything around it: a guard written next
// to it or three rules away, another rule that grants anyway. No list of
// shapes covers them, so the question is put to the policy: the same decision,
// asked of the policy as it is and of a copy where the every expressions in
// question cannot hold over an empty domain. Where the two answer alike, the
// vacuous truth changes nothing.

// ErrNoSuchEvery is returned when no every expression sits at a place named, or
// the one that does ranges over something no guard can be written for.
var ErrNoSuchEvery = errors.New("opaengine: no every expression to guard at that place")

// EveryPlace is where an every expression sits in a policy: a file and a line.
type EveryPlace struct {
	File string
	Line int
}

// WithGuardedEvery returns the bundle with every `every` expression at the
// places named made unable to hold over an empty domain. Nothing else differs:
// the decisions, their names and the rest of the policy are the ones of the
// bundle it is called on, which is left as it was.
//
// The guard is an iteration of the domain written just before the every, the
// way a policy guards one itself: xs[_] ahead of every x in xs. It holds for
// any collection with an element in it, whatever the element is, and partial
// evaluation goes through it as it goes through any other reference.
//
// The copy is for partial evaluation and for asking a decision about a request.
// What the engine reads off the policy, the reads and the checks, is still read
// off the original.
func (b *Bundle) WithGuardedEvery(places ...EveryPlace) (*Bundle, error) {
	compiler, err := b.forPartial()
	if err != nil {
		return nil, err
	}

	modules := make(map[string]*ast.Module, len(compiler.Modules))
	for name, compiled := range compiler.Modules {
		module := compiled.Copy()
		// The copy is evaluated and never reported, as the other rewrites are.
		module.Annotations = nil
		modules[name] = module
	}

	guard := everyGuard{written: make(map[EveryPlace]int, len(places)), fresh: freshVars(modules)}
	for _, place := range places {
		guard.written[place] = 0
	}
	changed := map[string]bool{}
	for _, module := range modules {
		for _, rule := range module.Rules {
			before := guard.total()
			for leg := rule; leg != nil; leg = leg.Else {
				leg.Body = guard.body(leg.Body)
			}
			if guard.total() > before {
				changed[rulePath(rule).String()] = true
			}
		}
	}
	for _, place := range places {
		if guard.written[place] == 0 {
			return nil, fmt.Errorf("%w: %s:%d", ErrNoSuchEvery, place.File, place.Line)
		}
	}

	// The modules were compiled once already: see closeOperands for what that
	// asks of a second compilation.
	closeOperands(modules)
	recompiled := ast.NewCompiler()
	recompiled.Compile(modules)
	if recompiled.Failed() {
		return nil, fmt.Errorf("%w, with an every guarded: %w", ErrCompile, recompiled.Errors)
	}

	copied := &Bundle{
		Compiler:        b.Compiler,
		RegoVersion:     b.RegoVersion,
		Files:           b.Files,
		Entrypoints:     b.Entrypoints,
		DenyEntrypoints: b.DenyEntrypoints,
		partialCompiler: recompiled,
		fieldQueries:    b.fieldQueries,
		changed:         changed,
	}
	// The policy partial evaluation runs against is the one just compiled, and
	// nothing is left to build the first time it is asked for.
	copied.partialOnce.Do(func() {})
	return copied, nil
}

// everyGuard writes the guard of the every expressions at the places it was
// given, wherever in a rule they sit.
type everyGuard struct {
	// written counts the guards written at each place. A place is one of the
	// guard's when it is a key here.
	written map[EveryPlace]int

	// fresh gives the variables of each guard a name nothing else uses.
	fresh func() ast.Var
}

// total is the number of guards written so far, over every place.
func (g *everyGuard) total() int {
	total := 0
	for _, written := range g.written {
		total += written
	}
	return total
}

// body returns a body with a guard ahead of each every it holds at one of the
// places, and the bodies nested inside its expressions treated the same way.
func (g *everyGuard) body(body ast.Body) ast.Body {
	guarded := make([]*ast.Expr, 0, len(body))
	for _, expr := range body {
		g.nested(expr)
		if every, isEvery := expr.Terms.(*ast.Every); isEvery {
			if place, mine := g.at(expr); mine {
				if iteration, ok := g.iteration(every.Domain); ok {
					// A with modifier on the every applies to its guard as well.
					for _, with := range expr.With {
						iteration.With = append(iteration.With, with.Copy())
					}
					guarded = append(guarded, iteration)
					g.written[place]++
				}
			}
		}
		guarded = append(guarded, expr)
	}
	return ast.NewBody(guarded...)
}

// nested goes into every body an expression holds: the body of an every, the
// operands of a not, an and or an or, and the comprehensions among its terms.
func (g *everyGuard) nested(expr *ast.Expr) {
	switch holder := expr.Terms.(type) {
	case *ast.Every:
		holder.Body = g.body(holder.Body)
	case *ast.Not:
		holder.Body = g.body(holder.Body)
	case *ast.LogicalAnd:
		holder.Lhs, holder.Rhs = g.body(holder.Lhs), g.body(holder.Rhs)
	case *ast.LogicalOr:
		holder.Lhs, holder.Rhs = g.body(holder.Lhs), g.body(holder.Rhs)
	}
	ast.WalkTerms(expr, func(term *ast.Term) bool {
		switch comprehension := term.Value.(type) {
		case *ast.ArrayComprehension:
			comprehension.Body = g.body(comprehension.Body)
		case *ast.SetComprehension:
			comprehension.Body = g.body(comprehension.Body)
		case *ast.ObjectComprehension:
			comprehension.Body = g.body(comprehension.Body)
		default:
			return false
		}
		// The body was gone through by the call above, and its own expressions
		// with it.
		return true
	})
}

// at returns the place an expression sits at, and whether it is one the guard
// is for.
func (g *everyGuard) at(expr *ast.Expr) (EveryPlace, bool) {
	if expr.Location == nil {
		return EveryPlace{}, false
	}
	place := EveryPlace{File: expr.Location.File, Line: expr.Location.Row}
	_, mine := g.written[place]
	return place, mine
}

// iteration writes domain[k] = v over two variables of its own, which holds
// once for each element the domain has and so not at all for an empty one. A
// domain that is neither a reference nor a variable, a collection written out
// in the policy, is one the request cannot empty and gets no guard.
func (g *everyGuard) iteration(domain *ast.Term) (*ast.Expr, bool) {
	var element ast.Ref
	switch value := domain.Value.(type) {
	case ast.Ref:
		element = value.Copy()
	case ast.Var:
		element = ast.Ref{ast.NewTerm(value)}
	default:
		return nil, false
	}
	element = append(element, ast.VarTerm(string(g.fresh())))
	iteration := ast.Equality.Expr(ast.NewTerm(element), ast.VarTerm(string(g.fresh())))
	iteration.Location = domain.Location
	return iteration, true
}

// Computes reports whether a path under data is built by rules of the policy,
// and not held in the documents: data.app.required_checks where the policy
// defines required_checks. What such a path holds is in the rules, and emptying
// a document changes nothing of it.
func (b *Bundle) Computes(path string) bool {
	ref, err := ast.ParseRef(path)
	if err != nil || !ref.HasPrefix(ast.DefaultRootRef) {
		return false
	}
	ground := ref
	for i, term := range ref {
		if i > 0 && !term.IsGround() {
			ground = ref[:i]
			break
		}
	}
	return len(b.Compiler.GetRulesForVirtualDocument(ground)) > 0
}

// SameAnswer reports whether a decision answers one request the same in two
// bundles: with the same value, or with none in both. The request is whole,
// with nothing of it left unknown.
//
// The value is what is compared, and not whether the decision holds. A decision
// that answers with a score or a report is defined either way, and a change to
// the policy shows in what it says.
func SameAnswer(ctx context.Context, a, b *Bundle, data *Data, decision string, input map[string]any) (bool, error) {
	if data == nil {
		return false, ErrNoData
	}
	var answers [2]string
	for i, bundle := range []*Bundle{a, b} {
		compiler, err := bundle.forPartial()
		if err != nil {
			return false, err
		}
		results, err := evaluated(ctx, data, decision, func(txn storage.Transaction) (rego.ResultSet, error) {
			return rego.New(
				rego.Query(bundle.query(decision)),
				rego.Compiler(compiler),
				rego.Store(data.store),
				rego.Transaction(txn),
				rego.Input(input),
			).Eval(ctx)
		})
		if err != nil {
			return false, fmt.Errorf("%w: %s: %w", ErrPartial, decision, err)
		}
		values := make([]string, 0, len(results))
		for _, result := range results {
			for _, expr := range result.Expressions {
				values = append(values, fmt.Sprintf("%#v", expr.Value))
			}
		}
		// A decision that collects answers with one result for each element,
		// in no order worth comparing.
		slices.Sort(values)
		answers[i] = strings.Join(values, "\n")
	}
	return answers[0] == answers[1], nil
}

// SameResiduals reports whether partial evaluation leaves the same of a
// decision in two bundles: the same conditions, and the same rules generated to
// hold what the conditions refer to.
//
// It is what tells whether a change to the policy changed anything a decision
// says, for the requests one question leaves open. Everything OPA returned is
// compared, as it is written, once the variables a compilation or the
// evaluation generated are renamed in the order they appear, since two
// compilations of one rule number them differently. Two answers that mean the
// same and are written differently are taken to differ, so false says the two
// could not be shown equal and nothing more.
//
// A condition no request can meet is left out of both sides first. Partial
// evaluation goes through two references to one unknown part of the request
// apart from each other, data.reviews[input.change] read twice, and leaves the
// combinations where the two disagree: "c1" = input.change next to "c2" =
// input.change. Such a condition holds for nobody, and counting it would tell
// apart two policies that say the same. A condition written twice is one
// condition.
//
// Partial evaluation does not write out everything it leaves. A comprehension
// over something unknown, and a call to a function with an else, come back as
// they are written, naming the rules they use (v1/topdown/eval.go:1241 and
// 2215 at v1.21.1). Two answers that read the same can then mean different
// things, when one of those rules is not the same in the two bundles. So an
// answer that still refers to a rule the second bundle changed, or to a rule
// that uses one, is not shown equal.
func SameResiduals(ctx context.Context, a, b *Bundle, data *Data, ask Request) (bool, error) {
	left, err := partial(ctx, a, data, ask)
	if err != nil {
		return false, err
	}
	right, err := partial(ctx, b, data, ask)
	if err != nil {
		return false, err
	}
	if len(left) != len(right) {
		return false, nil
	}
	for i := range left {
		if !slices.Equal(canonicalResidual(left[i]), canonicalResidual(right[i])) {
			return false, nil
		}
		refers, err := b.refersToChanged(right[i])
		if err != nil || refers {
			return false, err
		}
	}
	return true, nil
}

// refersToChanged reports whether what partial evaluation returned still
// refers to a rule this bundle changed, directly or through the rules it
// names.
func (b *Bundle) refersToChanged(queries *rego.PartialQueries) (bool, error) {
	if len(b.changed) == 0 {
		return false, nil
	}
	compiler, err := b.forPartial()
	if err != nil {
		return false, err
	}

	refers := false
	followed := map[*ast.Rule]bool{}
	var visit func(ref ast.Ref) bool
	visit = func(ref ast.Ref) bool {
		if refers || !ref.HasPrefix(ast.DefaultRootRef) {
			return refers
		}
		for _, rule := range compiler.GetRulesForVirtualDocument(ref) {
			if followed[rule] {
				continue
			}
			followed[rule] = true
			if b.changed[rulePath(rule).String()] {
				refers = true
				return true
			}
			ast.WalkRefs(rule, visit)
		}
		return refers
	}
	for _, query := range queries.Queries {
		ast.WalkRefs(query, visit)
	}
	for _, module := range queries.Support {
		ast.WalkRefs(module, visit)
	}
	return refers, nil
}

// canonicalResidual writes what one partial evaluation returned as lines that
// compare: the conditions some request can meet, then the rules generated to
// hold what those conditions refer to, each with its generated variables
// renamed, sorted and each kept once.
//
// A generated rule no condition reaches, directly or through another generated
// rule, says nothing of the decision: partial evaluation writes the rules of a
// set the answer would have listed even where no request gets an answer.
func canonicalResidual(queries *rego.PartialQueries) []string {
	var lines []string
	reached := map[*ast.Rule]bool{}
	var follow func(ref ast.Ref) bool
	follow = func(ref ast.Ref) bool {
		for _, module := range queries.Support {
			for _, rule := range module.Rules {
				// The reference names the rule, something inside what it
				// returns, or a document the rule sits under.
				path := rulePath(rule)
				named := ref.HasPrefix(path) || path.HasPrefix(ref.GroundPrefix())
				if reached[rule] || !named {
					continue
				}
				reached[rule] = true
				if !pinsTwice(rule.Body) {
					// A rule whose body no request meets never speaks.
					lines = append(lines, "rule "+module.Package.Path.String()+" "+canonical(rule.Copy()))
				}
				ast.WalkRefs(rule, follow)
			}
		}
		return false
	}

	for _, query := range queries.Queries {
		if pinsTwice(query) {
			continue
		}
		lines = append(lines, "query "+canonical(query.Copy()))
		ast.WalkRefs(query, follow)
	}
	slices.Sort(lines)
	return slices.Compact(lines)
}

// canonical writes a query or a rule with the variables a compilation or the
// evaluation generated renamed by the order they first appear in. What cannot
// be renamed is written as it is.
func canonical(node any) string {
	renamed := map[ast.Var]ast.Var{}
	transformed, err := ast.TransformVars(node, func(v ast.Var) (ast.Value, error) {
		if !isGeneratedName(v) {
			return v, nil
		}
		name, seen := renamed[v]
		if !seen {
			name = ast.Var(fmt.Sprintf("__v%d__", len(renamed)))
			renamed[v] = name
		}
		return name, nil
	})
	if err != nil {
		return fmt.Sprint(node)
	}
	return fmt.Sprint(transformed)
}

// isGeneratedName reports whether a variable was named by a compilation, by the
// evaluation, or by one of the rewrites of this package, and not by the author
// of the policy.
func isGeneratedName(v ast.Var) bool {
	return v.IsGenerated() || v.IsWildcard() || strings.HasPrefix(string(v), "__")
}

// pinsTwice reports whether a condition holds one part of the request, written
// out with no variable in it, equal to two different values.
func pinsTwice(body ast.Body) bool {
	pinned := map[string]*ast.Term{}
	for _, expr := range body {
		if !expr.IsEquality() || expr.Negated {
			continue
		}
		operands := expr.Operands()
		for _, pair := range [][2]*ast.Term{{operands[0], operands[1]}, {operands[1], operands[0]}} {
			ref, isRef := pair[0].Value.(ast.Ref)
			if !isRef || !isInputRooted(ref) || !ref.IsGround() {
				continue
			}
			if _, isScalar := scalarOf(pair[1]); !isScalar {
				continue
			}
			if before, seen := pinned[ref.String()]; seen && !before.Equal(pair[1]) {
				return true
			}
			pinned[ref.String()] = pair[1]
		}
	}
	return false
}
