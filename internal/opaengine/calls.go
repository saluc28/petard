package opaengine

import (
	"fmt"
	"slices"

	"github.com/open-policy-agent/opa/v1/ast"
)

// Default bounds for the interprocedural walk. See Limits.
const (
	defaultMaxCallDepth = 8
	defaultMaxCallPaths = 64
)

// Limits bounds what the analysis is allowed to spend.
//
// The zero value means the defaults, so callers who have no opinion can pass
// Limits{} and get a bounded analysis rather than an unbounded one.
type Limits struct {
	// MaxCallDepth is how many calls deep the walk follows an argument back to
	// where it comes from.
	//
	// It does not guard against recursion: OPA refuses to compile a policy
	// whose rules call each other in a cycle, so the rule graph of anything
	// that compiles is acyclic. It guards against cost.
	MaxCallDepth int

	// MaxCallPaths is how many call paths the walk explores for one reference.
	//
	// This is the bound that matters. Depth alone does not contain the fan
	// out: a function called from three places at each level has thousands of
	// paths at depth eight, all of them legal.
	MaxCallPaths int

	// MaxResiduals is how many residual conditions of one decision are
	// reported by partial evaluation.
	//
	// This one is bounded by the data and not by the policy: partial
	// evaluation expands concrete documents into a disjunction, so the count
	// follows the cardinality of what the decision reads.
	MaxResiduals int
}

func (l Limits) maxCallDepth() int {
	if l.MaxCallDepth <= 0 {
		return defaultMaxCallDepth
	}
	return l.MaxCallDepth
}

func (l Limits) maxCallPaths() int {
	if l.MaxCallPaths <= 0 {
		return defaultMaxCallPaths
	}
	return l.MaxCallPaths
}

func (l Limits) maxResiduals() int {
	if l.MaxResiduals <= 0 {
		return defaultMaxResiduals
	}
	return l.MaxResiduals
}

// callSite is one place where a rule calls another, recorded as the walk goes
// through it so that the bindings are the ones in force right there.
type callSite struct {
	caller *ast.Rule

	// args are the actual arguments, already trimmed of the output operand a
	// call adds when it is made for its value.
	args []*ast.Term

	// bindings are those of the body holding the call.
	bindings map[ast.Var]binding
}

// callBudget is what a single reference is allowed to spend looking for where
// its parameters come from.
type callBudget struct {
	limits   Limits
	paths    int
	warnings []string
}

// spend reports whether one more call path may be explored.
func (b *callBudget) spend(callee *ast.Rule) bool {
	b.paths++
	if b.paths <= b.limits.maxCallPaths() {
		return true
	}
	b.warn("gave up after %d call paths while resolving %s: raise MaxCallPaths to follow the rest",
		b.limits.maxCallPaths(), rulePath(callee))
	return false
}

func (b *callBudget) warn(format string, args ...any) {
	b.warnings = append(b.warnings, fmt.Sprintf(format, args...))
}

// parameterProvenance answers where the value of a formal parameter comes
// from, by looking at what the callers of the rule pass in that position.
//
// This is the part the binding resolver cannot do. That one works on one body
// at a time, and inside a function body nothing binds a parameter:
// the binding lives at the call site, in another rule. Without this walk the
// fixture's own chain stays invisible, because is_member(user, proj) reads the
// profile of "user" and only its caller knows that user is input.user.
//
// The answer is aggregated over every call site, and a path that reaches input
// wins over one that does not. The claim being made is "there is a way to call
// this rule where the caller chooses the document", which is the claim an
// attack path is built on. Reporting the other paths instead would hide it.
func (r *refReader) parameterProvenance(rule *ast.Rule, param ast.Var, budget *callBudget, depth int) (Provenance, *Trace) {
	place, ok := parameterPlaceOf(rule, param)
	if !ok {
		// Not a parameter: a variable bound by the rule head, or by iteration.
		// Nothing at a call site can say where it comes from.
		return ProvenanceUnresolved, nil
	}
	if depth >= budget.limits.maxCallDepth() {
		budget.warn("stopped at %d calls deep while resolving %s: raise MaxCallDepth to follow further",
			budget.limits.maxCallDepth(), rulePath(rule))
		return ProvenanceUnresolved, nil
	}

	best, bestTrace := ProvenanceUnresolved, (*Trace)(nil)
	for _, site := range r.callSites[rule] {
		arg, passed := place.pick(site.args, site.bindings)
		if !passed {
			continue
		}
		if !budget.spend(rule) {
			break
		}

		provenance, trace := r.argumentProvenance(site, arg, budget, depth)
		if !better(provenance, best) {
			continue
		}
		best, bestTrace = provenance, &Trace{
			Term:    trace.Term,
			Callers: append([]string{rulePath(site.caller).String()}, trace.Callers...),
		}
	}
	return best, bestTrace
}

// argumentProvenance says where one actual argument comes from, in the body
// that passes it, and what it turns out to be.
func (r *refReader) argumentProvenance(site callSite, arg *ast.Term, budget *callBudget, depth int) (Provenance, Trace) {
	if v, isVar := varOf(arg); isVar {
		switch resolved := resolveVar(v, site.bindings); resolved.status {
		case resolvedTerm:
			return r.termProvenance(resolved.term, site.bindings, budget, depth),
				r.describe(resolved.term, site.bindings)
		case resolvedOutput, resolvedIteration:
			return r.bindingProvenance(resolved.source, site.bindings, budget, depth),
				Trace{Term: resolved.source.origin.String()}
		case unresolvedUnbound:
			// The argument is itself a parameter of the caller: keep walking
			// up, which is what makes the analysis interprocedural rather than
			// one hop deep.
			provenance, trace := r.parameterProvenance(site.caller, v, budget, depth+1)
			if trace == nil {
				return provenance, Trace{}
			}
			return provenance, *trace
		default:
			return ProvenanceUnresolved, Trace{}
		}
	}
	return r.termProvenance(arg, site.bindings, budget, depth), r.describe(arg, site.bindings)
}

// describe says what an argument turns out to be, in words a reader can check
// against the policy.
func (r *refReader) describe(term *ast.Term, bindings map[ast.Var]binding) Trace {
	ref, ok := term.Value.(ast.Ref)
	if !ok {
		return Trace{Term: term.String()}
	}

	resolved := substituteRef(ref, bindings)
	if text, presentable := r.readable(resolved.ref); presentable {
		return Trace{Term: text}
	}
	// The reference still holds names the compiler invented. What produced the
	// value is the useful thing to say in their place.
	if resolved.root != nil {
		return Trace{Term: resolved.root.origin.String()}
	}
	return Trace{}
}

// termProvenance says where the value of a term comes from, resolving what the
// body binds.
//
// The term is as often a variable as a reference: the compiler names every
// intermediate value, so what a function hands back is almost never written
// out, it is a __localN__ standing for it.
func (r *refReader) termProvenance(term *ast.Term, bindings map[ast.Var]binding, budget *callBudget, depth int) Provenance {
	if v, isVar := varOf(term); isVar {
		switch resolved := resolveVar(v, bindings); resolved.status {
		case resolvedTerm:
			// resolveVar follows aliases to something that is not a variable,
			// so this recursion goes one step and stops.
			return r.termProvenance(resolved.term, bindings, budget, depth)
		case resolvedOutput, resolvedIteration:
			return r.bindingProvenance(resolved.source, bindings, budget, depth)
		default:
			return ProvenanceUnresolved
		}
	}

	ref, ok := term.Value.(ast.Ref)
	if !ok {
		// A literal: the same document every time.
		return ProvenanceStatic
	}
	return r.rootProvenance(substituteRef(ref, bindings), bindings, budget, depth)
}

// bindingProvenance says where the value a binding stands for comes from.
//
// A nondeterministic builtin is where the trail ends and the taint begins:
// nothing in the policy decides that value. A pure builtin returns nothing its
// arguments did not already contain, so its provenance is theirs, and the same
// holds for a rule of the policy, whose provenance is that of what it returns.
func (r *refReader) bindingProvenance(b binding, bindings map[ast.Var]binding, budget *callBudget, depth int) Provenance {
	if depth >= budget.limits.maxCallDepth() {
		budget.warn("stopped at %d calls deep while resolving %s: raise MaxCallDepth to follow further",
			budget.limits.maxCallDepth(), b.origin)
		return ProvenanceUnresolved
	}

	switch b.kind {
	case bindingOutput:
		if b.external {
			return ProvenanceBuiltin
		}
		return r.bestOfTerms(b.args, bindings, budget, depth+1)

	case bindingRuleOutput:
		// What the callee returns, plus what the caller passed in: a function
		// that hands back one of its arguments has the provenance of that
		// argument.
		best := r.bestOfTerms(b.args, bindings, budget, depth+1)
		for _, rule := range r.compiler.GetRulesForVirtualDocument(b.origin) {
			if !budget.spend(rule) {
				break
			}
			if returned := r.returnProvenance(rule, budget, depth+1); better(returned, best) {
				best = returned
			}
		}
		return best

	case bindingIteration:
		// Ranging over a collection: the value is one of its keys, so it comes
		// from wherever the collection does.
		return rootOfRef(b.origin)
	}
	return ProvenanceUnresolved
}

// returnProvenance says where the value a rule hands back comes from.
func (r *refReader) returnProvenance(rule *ast.Rule, budget *callBudget, depth int) Provenance {
	if rule.Head.Value == nil {
		// A rule with no value is a predicate: it says yes or no, it does not
		// hand back a document.
		return ProvenanceStatic
	}
	return r.termProvenance(rule.Head.Value, r.bindingsOf(rule, rule.Body, nil), budget, depth)
}

// bestOfTerms returns the strongest provenance among a list of terms.
func (r *refReader) bestOfTerms(terms []*ast.Term, bindings map[ast.Var]binding, budget *callBudget, depth int) Provenance {
	best := ProvenanceStatic
	for _, term := range terms {
		if p := r.termProvenance(term, bindings, budget, depth); better(p, best) {
			best = p
		}
	}
	return best
}

// rootOfRef reads where a reference is rooted, without resolving anything.
func rootOfRef(ref ast.Ref) Provenance {
	switch {
	case len(ref) == 0:
		return ProvenanceUnresolved
	case ref[0].Equal(ast.InputRootDocument):
		return ProvenanceInput
	case ref[0].Equal(ast.DefaultRootDocument):
		return ProvenanceData
	default:
		return ProvenanceStatic
	}
}

// parameterPlace is where a variable sits among the arguments of a rule: the
// argument, and the keys that lead to it inside the arrays and objects the head
// takes apart. collab([user, project]) holds user at argument 0, element 0,
// and InfraBox writes its lookups of the requester that way.
type parameterPlace struct {
	position int
	within   []*ast.Term
}

// parameterPlaceOf returns where a variable sits in the arguments of a rule, if
// it is one of its parameters.
func parameterPlaceOf(rule *ast.Rule, param ast.Var) (parameterPlace, bool) {
	for i, arg := range rule.Head.Args {
		if within, found := placeIn(arg, param); found {
			return parameterPlace{position: i, within: within}, true
		}
	}
	return parameterPlace{}, false
}

// placeIn finds a variable in an argument as the head writes it, and returns
// the keys on the way to it: an index for an array, a key for an object. The
// compiler keeps the array or the object in the head and renames the variables
// inside it, so this is the shape the walk meets.
func placeIn(term *ast.Term, param ast.Var) ([]*ast.Term, bool) {
	switch value := term.Value.(type) {
	case ast.Var:
		return nil, value == param
	case *ast.Array:
		for i := range value.Len() {
			if within, found := placeIn(value.Elem(i), param); found {
				return append([]*ast.Term{ast.IntNumberTerm(i)}, within...), true
			}
		}
	case ast.Object:
		for _, key := range value.Keys() {
			if within, found := placeIn(value.Get(key), param); found {
				return append([]*ast.Term{key}, within...), true
			}
		}
	}
	return nil, false
}

// pick returns what a call passes for the parameter at this place: the
// argument, and inside it the element the head takes apart, where the call
// writes the array or the object out, or binds a variable to one first. A call
// that hands over a value the policy computes is not followed into it.
func (p parameterPlace) pick(args []*ast.Term, bindings map[ast.Var]binding) (*ast.Term, bool) {
	if p.position >= len(args) {
		return nil, false
	}
	term := args[p.position]
	for _, key := range p.within {
		if v, isVar := varOf(term); isVar {
			resolved := resolveVar(v, bindings)
			if resolved.status != resolvedTerm {
				return nil, false
			}
			term = resolved.term
		}
		var element *ast.Term
		switch value := term.Value.(type) {
		case *ast.Array:
			element = value.Get(key)
		case ast.Object:
			element = value.Get(key)
		}
		if element == nil {
			return nil, false
		}
		term = element
	}
	return term, true
}

func (p parameterPlace) equal(other parameterPlace) bool {
	return p.position == other.position && slices.EqualFunc(p.within, other.within, (*ast.Term).Equal)
}

// better reports whether a says more than b about who chooses the document.
//
// Input first: it is the one an attacker controls. Then a builtin, whose value
// comes from outside the policy. Then data, then a constant. Unresolved says
// nothing and loses to everything.
func better(a, b Provenance) bool {
	return provenanceRank(a) > provenanceRank(b)
}

func provenanceRank(p Provenance) int {
	switch p {
	case ProvenanceInput:
		return 4
	case ProvenanceBuiltin:
		return 3
	case ProvenanceData:
		return 2
	case ProvenanceStatic:
		return 1
	default:
		return 0
	}
}
