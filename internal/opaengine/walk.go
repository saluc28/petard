package opaengine

import (
	"slices"

	"github.com/open-policy-agent/opa/v1/ast"
)

// This file holds the walk: from the declared decisions, through the rules
// they depend on, collecting the data references of each and the calls between
// them.

// refReader walks the rules that make up the decisions, collecting the data
// references of each and the calls between them.
type refReader struct {
	compiler *ast.Compiler
	pending  []*ast.Rule
	visited  map[*ast.Rule]bool

	// current is the rule being walked, so that a call found in its body knows
	// who is calling.
	current *ast.Rule

	found     []ruleRefs
	callSites map[*ast.Rule][]callSite

	// edges are the rules each rule reaches, recorded while walking so that a
	// value found deep in a helper can be traced back to the decisions that
	// depend on it. Which decision is asking is not a detail of presentation:
	// the whole claim of the taint pattern is that this decision depends on
	// that source.
	edges map[*ast.Rule][]callEdge

	// inputPaths are the paths of input the decisions touch, normalized like
	// the data ones.
	inputPaths []string

	// underWith holds the rules some expression reaches through a with
	// modifier. Being in here is not enough to be skipped: a rule reached both
	// ways is a normal dependency.
	underWith map[string]bool

	// foundClosures are the calls that follow a relation as far as it goes,
	// kept as they were met so that the relation can be named once the reads of
	// every rule are known.
	foundClosures []foundClosure
}

// closureBuiltins are the constructs a policy has to use to follow a relation
// transitively.
//
// Rego forbids recursion between rules, so transitivity cannot be written as a
// rule that calls itself: Compiler.checkRecursion (v1/ast/compile.go:1299 at
// v1.19.0) is a mandatory stage of the compilation and fails on any cycle. That
// leaves three ways of writing it, and two of them are these calls. The third
// is a closure somebody precomputed and stored in the data, which is an
// ordinary read carrying no construct at all: nothing here can see it, and the
// pattern that cares declares the gap rather than guessing at field names.
var closureBuiltins = []string{"graph.reachable", "graph.reachable_paths", "walk"}

// foundClosure is one transitive construct met while walking.
type foundClosure struct {
	rule    *ast.Rule
	builtin string

	// args are the declared operands, without the one the value lands in.
	args []*ast.Term

	// bindings are those in force where the call was found, needed to say what
	// its arguments stand for.
	bindings map[ast.Var]binding

	location *ast.Location
}

// ruleRefs are the data references met in one rule.
type ruleRefs struct {
	rule *ast.Rule
	refs []foundRef
}

// callEdge is one rule reached from another, and whether the expression that
// reaches it negates it.
//
// The flag belongs to the edge and not to the rule at either end: the same
// rule can be a plain dependency of one decision and a negated one of another,
// and a value that only reaches a decision through a negation denies access
// rather than granting it.
type callEdge struct {
	callee  *ast.Rule
	negated bool
}

// scope is what a body knows while it is being walked: what its variables
// stand for, and whether it sits under a negation.
//
// Both travel down into comprehensions and every bodies, which is why they
// travel together rather than as two parameters that could get out of step.
type scope struct {
	bindings map[ast.Var]binding
	negated  bool
}

// foundRef is a data reference met while walking, before the reads of a rule
// are pruned of the paths that only lead to other paths.
type foundRef struct {
	resolved substitutedRef

	// bindings are those in force where the reference was found, kept because
	// judging its provenance may mean following what a call returned, and that
	// is written in terms of this body's variables.
	bindings map[ast.Var]binding

	negated  bool
	location *ast.Location
}

func (r *refReader) walk() {
	for len(r.pending) > 0 {
		rule := r.pending[0]
		r.pending = r.pending[1:]
		if r.visited[rule] {
			continue
		}
		r.visited[rule] = true

		// The head is not walked: the compiler moves whatever needs evaluating
		// in a head key, value or argument into the body, so the body has it.
		r.current = rule
		var found []foundRef
		r.walkBody(rule.Body, scope{}, &found)
		r.found = append(r.found, ruleRefs{rule: rule, refs: found})
	}
}

// skipped returns the rules only a with modifier reaches.
func (r *refReader) skipped() []string {
	visited := make(map[string]bool, len(r.visited))
	for rule := range r.visited {
		visited[rule.Path().String()] = true
	}

	var skipped []string
	for path := range r.underWith {
		if !visited[path] {
			skipped = append(skipped, path)
		}
	}
	slices.Sort(skipped)
	return skipped
}

// walkBody walks one body with the bindings of the bodies enclosing it. A
// comprehension and an every body can read variables from outside while
// binding their own, so the tables stack instead of replacing each other.
func (r *refReader) walkBody(body ast.Body, outer scope, found *[]foundRef) {
	inner := scope{
		bindings: r.bindingsOf(r.current, body, outer.bindings),
		negated:  outer.negated,
	}
	for _, expr := range body {
		r.walkExpr(expr, inner, found)
	}
}

// bindingsOf reads what a body says about its variables, and adds the two
// things a body alone cannot know.
//
// collectBindings stays pure and works on an ast.Body, as the design says it
// should. Knowing that a call returns a value takes the arity of the callee,
// which lives in the rule graph, and telling an iterating variable from a
// formal parameter takes the head of the rule. Both are here, where that
// context exists, instead of being pushed down into a function whose whole
// value is that it has none.
func (r *refReader) bindingsOf(rule *ast.Rule, body ast.Body, inherited map[ast.Var]binding) map[ast.Var]binding {
	bindings := merge(inherited, collectBindings(body))
	r.addRuleOutputs(body, bindings)
	addIterations(rule, body, bindings)
	return bindings
}

// addRuleOutputs records the variables that receive what a rule of the policy
// returns, which collectBindings cannot do: the arity of a function is in its
// head, not in the body that calls it.
func (r *refReader) addRuleOutputs(body ast.Body, bindings map[ast.Var]binding) {
	for _, expr := range body {
		if len(expr.With) > 0 || !expr.IsCall() {
			continue
		}
		operator := expr.Operator()
		if operator == nil {
			continue
		}
		callees := r.compiler.GetRulesForVirtualDocument(operator)
		if len(callees) == 0 {
			continue
		}

		operands := expr.Operands()
		arity := len(callees[0].Head.Args)
		if arity == 0 || len(operands) != arity+1 {
			continue
		}
		if v, ok := varOf(operands[arity]); ok {
			bind(bindings, v, binding{kind: bindingRuleOutput, origin: operator, args: operands[:arity]})
		}
	}
}

// addIterations marks the variables that range over a collection.
//
// A variable used as an index and bound nowhere else is iterating: in Rego,
// data.projects[p] with p free means "for every project", and p takes the keys
// of the collection. The distinction that matters is with a formal parameter,
// which looks identical and is the opposite: its value comes from the caller,
// not from the collection next to it. Rego makes the distinction exact,
// because a rule head key has to be bound in the body while an argument must
// not be.
func addIterations(rule *ast.Rule, body ast.Body, bindings map[ast.Var]binding) {
	parameters := parameterVars(rule)

	ast.WalkRefs(body, func(ref ast.Ref) bool {
		switch rootOfRef(ref) {
		case ProvenanceData, ProvenanceInput:
		default:
			return false
		}

		for i := 1; i < len(ref); i++ {
			v, ok := varOf(ref[i])
			if !ok || parameters[v] {
				continue
			}
			bind(bindings, v, binding{kind: bindingIteration, origin: ref[:i:i]})
		}
		return false
	})
}

// parameterVars returns the formal parameters of a rule.
func parameterVars(rule *ast.Rule) map[ast.Var]bool {
	if rule == nil || len(rule.Head.Args) == 0 {
		return nil
	}
	parameters := make(map[ast.Var]bool, len(rule.Head.Args))
	for _, arg := range rule.Head.Args {
		if v, ok := varOf(arg); ok {
			parameters[v] = true
		}
	}
	return parameters
}

func (r *refReader) walkExpr(expr *ast.Expr, sc scope, found *[]foundRef) {
	sc.negated = sc.negated || expr.Negated

	// An expression with a with modifier is simulating a decision, not taking
	// one. Neither its reads nor the rules it reaches belong to the analysis.
	if len(expr.With) > 0 {
		r.markUnderWith(expr)
		return
	}

	if expr.IsEvery() {
		every, ok := expr.Terms.(*ast.Every)
		if !ok {
			return
		}
		r.walkTerm(every.Domain, sc, found)
		r.walkBody(every.Body, sc, found)
		return
	}

	if expr.IsCall() {
		// The operator of a call is a rule reference, not a read: following it
		// is how the walk moves from one rule to the next.
		if operator := expr.Operator(); operator != nil {
			r.followCall(operator, expr.Operands(), sc)
			r.markClosure(operator, expr, sc)
		}
		for _, operand := range expr.Operands() {
			r.walkTerm(operand, sc, found)
		}
		return
	}

	if term, ok := expr.Terms.(*ast.Term); ok {
		r.walkTerm(term, sc, found)
	}
}

func (r *refReader) walkTerm(term *ast.Term, sc scope, found *[]foundRef) {
	if term == nil {
		return
	}

	switch value := term.Value.(type) {
	case ast.Ref:
		// A reference to a rule is a dependency; only base documents are read.
		if r.follow(value, sc.negated) {
			return
		}
		// Whether this reads data is decided after substitution, not before.
		// The head is often a variable standing for a reference, as in
		// "doc := data.documents[input.doc]" in one expression and
		// "doc.project" in another, and before substitution that reference
		// does not look like it touches data at all.
		resolved := substituteRef(value, sc.bindings)
		if isInputRooted(resolved.ref) {
			// What the decisions touch of input is not a read of data, but it
			// is what tells subject from resource later on, and it is free to
			// collect while the body is already being walked.
			r.inputPaths = append(r.inputPaths, normalize(resolved.ref))
		}
		// A reference rooted in what a call returned is kept too, and it is the
		// only way a value from outside the policy is ever seen: it reads no
		// document, so nothing under data or input names it, and without this
		// enrichment.body.clearance would exist nowhere in the analysis.
		//
		// Substitution is also where a reference can turn into a rule without
		// looking like one. "c := containers[_]" followed by "c.privileged"
		// substitutes to data.pkg.containers[_].privileged, which is rooted in
		// data and is not a document: containers is computed by the policy, and
		// the rule behind it was already followed by the expression that bound
		// c. Counting it would put a path nobody can write into the write model
		// and into every number measured on a corpus.
		if (isDataRooted(resolved.ref) || resolved.root != nil) && !r.namesRule(resolved.ref) {
			*found = append(*found, foundRef{
				resolved: resolved,
				bindings: sc.bindings,
				negated:  sc.negated,
				location: term.Loc(),
			})
		}
		for _, inner := range value[1:] {
			r.walkTerm(inner, sc, found)
		}

	case *ast.ArrayComprehension:
		r.walkBody(value.Body, sc, found)
		r.walkTerm(value.Term, sc, found)

	case *ast.SetComprehension:
		r.walkBody(value.Body, sc, found)
		r.walkTerm(value.Term, sc, found)

	case *ast.ObjectComprehension:
		r.walkBody(value.Body, sc, found)
		r.walkTerm(value.Key, sc, found)
		r.walkTerm(value.Value, sc, found)

	case *ast.Array:
		for i := range value.Len() {
			r.walkTerm(value.Elem(i), sc, found)
		}

	case ast.Set:
		for _, elem := range value.Slice() {
			r.walkTerm(elem, sc, found)
		}

	case ast.Object:
		value.Foreach(func(key, val *ast.Term) {
			r.walkTerm(key, sc, found)
			r.walkTerm(val, sc, found)
		})
	}
}

// follow queues the rules a reference points at, and reports whether it points
// at any. A reference that resolves to rules names a virtual document: it is
// computed by the policy, not read from data.
func (r *refReader) follow(ref ast.Ref, negated bool) bool {
	rules := r.compiler.GetRulesForVirtualDocument(ref)
	if len(rules) == 0 {
		return false
	}
	for _, rule := range rules {
		r.reach(rule, negated)
	}
	return true
}

// namesRule reports whether a reference names something the policy computes.
//
// It asks the same question follow does and queues nothing, because the caller
// that needs it is looking at a reference the substitution produced, and the
// rule at the end of it was already reached through the expression that bound
// the variable.
func (r *refReader) namesRule(ref ast.Ref) bool {
	return len(r.compiler.GetRulesForVirtualDocument(ref)) > 0
}

// followCall does what follow does, and records the arguments, so that a
// parameter can later be traced back to what was passed for it.
func (r *refReader) followCall(operator ast.Ref, operands []*ast.Term, sc scope) {
	rules := r.compiler.GetRulesForVirtualDocument(operator)
	if len(rules) == 0 {
		return
	}

	for _, rule := range rules {
		r.reach(rule, sc.negated)

		// A call made for its value carries one operand more than the function
		// declares, to receive the result. Only the declared ones are
		// arguments.
		arity := len(rule.Head.Args)
		if arity == 0 || arity > len(operands) {
			continue
		}
		r.callSites[rule] = append(r.callSites[rule], callSite{
			caller:   r.current,
			args:     operands[:arity],
			bindings: sc.bindings,
		})
	}
}

// reach queues a rule the current one depends on, and records the edge.
func (r *refReader) reach(callee *ast.Rule, negated bool) {
	if !r.visited[callee] {
		r.pending = append(r.pending, callee)
	}
	r.edges[r.current] = append(r.edges[r.current], callEdge{callee: callee, negated: negated})
}

// markClosure records a call that follows a relation transitively.
//
// Only the declared operands are kept: a builtin called for its value carries
// one more, and that one is where the answer lands rather than what the answer
// was computed from.
func (r *refReader) markClosure(operator ast.Ref, expr *ast.Expr, sc scope) {
	name := operator.String()
	if !slices.Contains(closureBuiltins, name) {
		return
	}
	builtin, known := ast.BuiltinMap[name]
	if !known || builtin.Decl == nil {
		return
	}

	operands := expr.Operands()
	arity := min(builtin.Decl.Arity(), len(operands))
	r.foundClosures = append(r.foundClosures, foundClosure{
		rule:     r.current,
		builtin:  name,
		args:     operands[:arity],
		bindings: sc.bindings,
		location: expr.Loc(),
	})
}

// markUnderWith records the rules an expression reaches, without following
// them.
func (r *refReader) markUnderWith(expr *ast.Expr) {
	ast.WalkRefs(expr, func(ref ast.Ref) bool {
		for _, rule := range r.compiler.GetRulesForVirtualDocument(ref) {
			r.underWith[rule.Path().String()] = true
		}
		return false
	})
}

// merge stacks a body's own bindings on top of the ones it inherits.
func merge(outer, inner map[ast.Var]binding) map[ast.Var]binding {
	if len(outer) == 0 {
		return inner
	}
	merged := make(map[ast.Var]binding, len(outer)+len(inner))
	for v, b := range outer {
		merged[v] = b
	}
	for v, b := range inner {
		merged[v] = b
	}
	return merged
}
