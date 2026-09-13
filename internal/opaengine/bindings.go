package opaengine

import (
	"fmt"

	"github.com/open-policy-agent/opa/v1/ast"
)

// maxRefExpansion bounds how deep substituteRef keeps replacing a variable
// with the term it stands for. Alias chains are cycle safe on their own, but a
// term can hold a variable that resolves to a term holding another one, and
// that nesting is what this stops.
const maxRefExpansion = 16

// The two document roots. They are plain variables in the AST, but nothing
// binds them and nothing should try to resolve them.
var (
	dataRoot  = rootVar(ast.DefaultRootDocument)
	inputRoot = rootVar(ast.InputRootDocument)
)

// rootVar reads the variable out of one of OPA's root document terms.
//
// Those terms are package level values of OPA's own and have been variables
// since there was an AST, so the assertion cannot fail on any bundle. Naming it
// is about the day it does: a bare assertion would panic at init with nothing
// to go on, and this one says which term changed shape.
func rootVar(term *ast.Term) ast.Var {
	name, ok := term.Value.(ast.Var)
	if !ok {
		panic(fmt.Sprintf("opaengine: root document %v is a %T, not a variable", term, term.Value))
	}
	return name
}

// bindingKind says how a variable came to stand for something.
type bindingKind int

const (
	// bindingAlias means the variable stands for a term, from an equality in
	// the same body.
	bindingAlias bindingKind = iota

	// bindingOutput means the variable holds what a builtin returned. It is
	// not an alias for a term: there is no term, only an origin and the
	// arguments the value was computed from.
	bindingOutput

	// bindingRuleOutput means the variable holds what a rule of the policy
	// returned. The walker records these, because knowing the arity of a rule
	// takes the rule graph, which a single body does not have.
	bindingRuleOutput

	// bindingIteration means the variable ranges over the keys of a
	// collection, as a variable used as an index and bound nowhere else does.
	bindingIteration
)

// binding is what one body says about one local variable.
type binding struct {
	kind bindingKind

	// term is what the variable stands for, when kind is bindingAlias.
	term *ast.Term

	// origin is the builtin or the rule that produced the value, for the two
	// output kinds, and the collection ranged over, for bindingIteration.
	origin ast.Ref

	// args are the operands the value was computed from, for the output kinds.
	// A pure builtin returns nothing the arguments did not already contain, so
	// they are where its provenance comes from.
	args []*ast.Term

	// external is true when the value comes from outside the policy, which
	// only a nondeterministic builtin can do. It is the difference between
	// http.send, whose answer somebody else controls, and graph.reachable,
	// which only rearranges what it was given. Treating the two alike would
	// invent taint where there is none.
	external bool
}

// collectBindings walks a rule body and records what each local variable
// stands for.
//
// The compiler does not throw away the reference a policy author wrote: it
// splits it into a binding and a use, in the same body. Reading
// data.users[input.user].profile as data.users[__local1__].profile is not a
// loss of information, it is dataflow made explicit, and this table is how it
// gets read back.
//
// The function is pure on purpose: one body in, one table out, no compiler and
// no shared state. That is also its limit. A body only knows its own
// variables, so a formal parameter stays unbound here; tying it to the
// argument at the call site needs the rule graph and lives elsewhere.
//
// Two cases are skipped deliberately. A negated expression binds nothing,
// because "not x = 1" gives x no value. And an every expression carries a body
// with a scope of its own, whose variables do not escape into this one.
func collectBindings(body ast.Body) map[ast.Var]binding {
	bindings := make(map[ast.Var]binding)
	for _, expr := range body {
		if expr.Negated || !expr.IsCall() {
			continue
		}
		if expr.IsEquality() || expr.IsAssignment() {
			collectEquality(expr, bindings)
			continue
		}
		collectBuiltinOutput(expr, bindings)
	}
	return bindings
}

// collectEquality records the alias an equality establishes.
//
// Unification is symmetric, so the variable can sit on either side. When both
// sides are variables only left to right is recorded: that is the direction
// the compiler generates, and recording both would close a loop between two
// names for the same value.
func collectEquality(expr *ast.Expr, bindings map[ast.Var]binding) {
	left, right := expr.Operand(0), expr.Operand(1)
	if left == nil || right == nil {
		return
	}
	if v, ok := varOf(left); ok {
		bind(bindings, v, binding{kind: bindingAlias, term: right})
		return
	}
	if v, ok := varOf(right); ok {
		bind(bindings, v, binding{kind: bindingAlias, term: left})
	}
}

// collectBuiltinOutput records the variable a builtin writes its result into.
//
// A builtin called with one operand more than its declared arity is being
// called for its value, and that extra operand is where the value lands. It is
// how the compiler writes "x := http.send(...)", and it is the moment a
// decision stops depending on the policy and starts depending on whatever
// answered the call.
//
// Calls to rules and functions declared by the policy are left alone: their
// arity is not in the builtin table, and following them is interprocedural
// work that needs the rule graph.
func collectBuiltinOutput(expr *ast.Expr, bindings map[ast.Var]binding) {
	operator := expr.Operator()
	if operator == nil {
		return
	}
	builtin, ok := ast.BuiltinMap[operator.String()]
	if !ok || builtin.Decl == nil {
		return
	}

	operands := expr.Operands()
	arity := builtin.Decl.Arity()
	if len(operands) != arity+1 {
		return
	}
	if v, ok := varOf(operands[len(operands)-1]); ok {
		bind(bindings, v, binding{
			kind:     bindingOutput,
			origin:   operator,
			args:     operands[:arity],
			external: builtin.Nondeterministic,
		})
	}
}

// bind keeps the first binding of a variable. A body can unify the same
// variable more than once, and the earliest one is the one the compiler
// generated to carry the value.
func bind(bindings map[ast.Var]binding, v ast.Var, b binding) {
	if _, taken := bindings[v]; !taken {
		bindings[v] = b
	}
}

// isRoot reports whether v is one of the two document roots.
func isRoot(v ast.Var) bool {
	return v == dataRoot || v == inputRoot
}

// varOf returns the variable a term holds, if it holds one.
//
// Wildcards are refused: a wildcard is a fresh anonymous variable at every
// occurrence, so standing for one would mean standing for nothing.
func varOf(term *ast.Term) (ast.Var, bool) {
	v, ok := term.Value.(ast.Var)
	if !ok || v.IsWildcard() {
		return "", false
	}
	return v, true
}

// resolutionStatus says how far resolveVar got.
type resolutionStatus int

const (
	// resolvedTerm means the chain ended on a concrete term.
	resolvedTerm resolutionStatus = iota

	// resolvedOutput means the chain ended on what a call returned, from a
	// builtin or from a rule of the policy. There is no term to put in its
	// place: what the value is depends on that call.
	resolvedOutput

	// resolvedIteration means the variable ranges over a collection.
	resolvedIteration

	// unresolvedUnbound means nothing in this body binds the variable. A
	// formal parameter looks exactly like this: the body is simply not where
	// the answer is.
	unresolvedUnbound

	// unresolvedCycle means the aliases lead back to a variable already
	// visited.
	unresolvedCycle
)

// resolution is what a variable turned out to stand for.
type resolution struct {
	status resolutionStatus

	// term is set when status is resolvedTerm.
	term *ast.Term

	// source is the binding the chain ended on, for the statuses that do not
	// end on a term: it names the call or the collection the value comes from.
	source binding
}

// resolveVar follows the alias chain of v until it reaches a concrete term or
// the builtin the value came from.
//
// Cycles are caught by remembering the variables already visited rather than
// by a depth cap. A cap would also cut a long but legitimate chain, and it
// would cut it silently, which is the failure this layer exists to prevent.
func resolveVar(v ast.Var, bindings map[ast.Var]binding) resolution {
	seen := make(map[ast.Var]bool)
	for {
		if seen[v] {
			return resolution{status: unresolvedCycle}
		}
		seen[v] = true

		b, ok := bindings[v]
		if !ok {
			return resolution{status: unresolvedUnbound}
		}
		switch b.kind {
		case bindingOutput, bindingRuleOutput:
			return resolution{status: resolvedOutput, source: b}
		case bindingIteration:
			return resolution{status: resolvedIteration, source: b}
		}

		next, isVar := varOf(b.term)
		if !isVar {
			return resolution{status: resolvedTerm, term: b.term}
		}
		v = next
	}
}

// substitutedRef is a reference with its local variables put back to what they
// stand for.
type substitutedRef struct {
	// ref is the rewritten reference. Variables that could not be resolved are
	// still in it, so it is always a reference and never a half result.
	ref ast.Ref

	// root is what the head of the reference stands for, when it is not a
	// document root: the output of a call, or a collection being iterated. It
	// is nil for the ordinary case of a reference rooted in data or input, and
	// for one whose head could not be resolved at all.
	root *binding

	// indexes are the same, for the segments after the head. An index that
	// comes out of a call is how a document gets chosen by something other
	// than the policy, and dropping it would report the read as constant.
	indexes []binding

	// unresolved lists the variables left in ref because this body does not
	// bind them. It is not a failure, it is a measurement: a reference found
	// with an unresolved index is still a reference found, but its provenance
	// is not known yet, and the two counts must never be added together.
	unresolved []ast.Var
}

// substituteRef rewrites a reference, replacing local variables with the terms
// they stand for.
//
// This is where data.users[__local1__].profile.department becomes
// data.users[input.user].profile.department, which is the form a taxonomy
// pattern can reason about: not "this policy reads data.users" but "this
// decision reads the profile of whoever is asking".
func substituteRef(ref ast.Ref, bindings map[ast.Var]binding) substitutedRef {
	var result substitutedRef
	result.ref = substitute(ref, bindings, &result, 0, true)
	return result
}

// substitute rewrites one reference, recursing into the terms it puts in,
// because a resolved term can itself be a reference holding variables.
//
// atHead says whether this reference is the one being substituted or one
// nested in an index of it. The head of a nested reference is not the head of
// the read: in data.users[fetched.body.id] the read is rooted in data, and
// what came from outside is the index.
func substitute(ref ast.Ref, bindings map[ast.Var]binding, result *substitutedRef, depth int, atHead bool) ast.Ref {
	if depth >= maxRefExpansion {
		return ref
	}

	out := make(ast.Ref, 0, len(ref))
	for i, term := range ref {
		v, isVar := varOf(term)
		if !isVar {
			out = append(out, term)
			continue
		}
		if i == 0 && isRoot(v) {
			out = append(out, term)
			continue
		}

		switch resolved := resolveVar(v, bindings); resolved.status {
		case resolvedTerm:
			// A variable standing for a reference in head position becomes the
			// new head, and the rest of this reference hangs off it: that is
			// how "doc := data.documents[input.doc]" and a later "doc.project"
			// come back together as one path.
			if stands, ok := resolved.term.Value.(ast.Ref); ok && i == 0 {
				out = append(out, substitute(stands, bindings, result, depth+1, atHead)...)
				continue
			}
			out = append(out, substituteTerm(resolved.term, bindings, result, depth+1))

		case resolvedOutput, resolvedIteration:
			// There is no term to put in its place, but where the value comes
			// from is known, and that is what a reference needs to be judged.
			source := resolved.source
			if i == 0 && atHead {
				result.root = &source
			} else {
				result.indexes = append(result.indexes, source)
			}
			out = append(out, term)

		default:
			result.unresolved = append(result.unresolved, v)
			out = append(out, term)
		}
	}
	return out
}

// substituteTerm rewrites a term standing in an index position. Only a
// reference can hold variables worth replacing; anything else is already as
// concrete as it will get.
func substituteTerm(term *ast.Term, bindings map[ast.Var]binding, result *substitutedRef, depth int) *ast.Term {
	inner, ok := term.Value.(ast.Ref)
	if !ok {
		return term
	}
	return ast.NewTerm(substitute(inner, bindings, result, depth, false))
}
