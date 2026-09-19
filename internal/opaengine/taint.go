package opaengine

import (
	"slices"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
)

// This file follows a value that the policy did not compute: from the call
// that brought it in, through the rules that pass it along, to the decisions
// that end up depending on it. Where a value comes from is answered in
// bindings.go and provenance.go; where it goes is answered here.

// Taint is one place where a decision reads a value that came from outside the
// policy.
//
// The fact worth reporting is not that a policy calls http.send. Every policy
// that enriches a decision does, and saying so is the kind of noise a linter
// already produces. It is that a named decision depends on a named endpoint,
// so whoever controls that endpoint decides in the policy's place. The two
// claims are told apart by one thing only: whether the value reaches a
// decision at all.
type Taint struct {
	// Rule is where the value is read, File and Line where in the source.
	Rule string
	File string
	Line int

	// Ref is the read as it stands in the rule, with the names the author
	// wrote: enrichment.body.clearance.
	Ref string

	// Origin is the builtin that brought the value in: http.send.
	Origin string

	// Endpoint is where the call went, when the policy writes it as a
	// constant, and empty when the destination is computed.
	//
	// Empty is not "unknown to us": a destination the request can steer is a
	// worse case than a fixed one, because then whoever asks also chooses who
	// the policy asks. The two have to stay distinguishable, which is why this
	// is not filled in with a guess.
	Endpoint string

	// UnderNegation is true when the read itself sits inside a negation. It
	// says nothing about the path from the decision down to here: that part is
	// per decision, and lives in Decisions.
	UnderNegation bool

	// Errors is what the call asked to happen when it fails, which decides
	// whether anybody outside the policy can still notice that it did.
	Errors ErrorHandling

	// Decisions are the entrypoints that depend on this value, sorted by name.
	//
	// A value that reaches none is not a taint, and is not reported: that is
	// the whole difference between a policy that calls out and a decision that
	// depends on the answer.
	Decisions []TaintedDecision
}

// ErrorHandling says what a call asked to happen when it fails.
//
// It is read from the request object where the policy writes one out, and it
// changes nothing about whether a decision fails open: verified on the fixture,
// which holds the same vulnerable shape twice, with the option and without it,
// and fails open both times. What it changes is whether the failure can still
// be made visible from outside the policy, and that is the difference between a
// deployment that has a switch left and one that has none.
type ErrorHandling int

const (
	// ErrorHandlingDefault means the call did not ask for anything, so a
	// failure produces a builtin error. OPA swallows those and the expression
	// becomes undefined, but the caller can pass strict-builtin-errors and make
	// the same failure fatal.
	ErrorHandlingDefault ErrorHandling = iota

	// ErrorHandlingSuppressed means the call asked for raise_error: false, so a
	// failure produces an object carrying an error and no body. There is no
	// error left for anybody to make fatal.
	ErrorHandlingSuppressed

	// ErrorHandlingUnknown means the request is computed rather than written
	// out, so what it asks for cannot be read from the policy. It is reported
	// as its own answer rather than assumed to be the default.
	ErrorHandlingUnknown
)

// String returns the handling as a report should name it.
func (e ErrorHandling) String() string {
	switch e {
	case ErrorHandlingSuppressed:
		return "suppressed"
	case ErrorHandlingUnknown:
		return "unknown"
	default:
		return "default"
	}
}

// TaintedDecision is one decision a value from outside the policy reaches.
type TaintedDecision struct {
	// Name is the path of the decision rule.
	Name string

	// UnderNegation is true when the value only ever reaches this decision to
	// deny: the negation of the read itself and the negations on the way down
	// from the decision add up to an odd number. A value read under not, in a
	// rule the decision reaches under not, is read to grant.
	//
	// It is one flag rather than two because the caller would have to combine
	// them anyway, and getting that combination wrong is exactly the silent
	// false positive this flag exists to avoid. Both halves are exact: Expr.
	// Negated is a bool in the AST, and the path is walked here. A read keeps
	// them apart instead, in ReachedDecision, since the question asked of a
	// missing document needs the two halves separately.
	UnderNegation bool
}

// Grants reports whether the value reaches any decision in a position to grant
// rather than to deny.
func (t Taint) Grants() bool {
	for _, decision := range t.Decisions {
		if !decision.UnderNegation {
			return true
		}
	}
	return false
}

// taints collects the values that came from outside the policy, and the
// decisions each of them reaches.
//
// The candidates are the references the walk found that are rooted in what a
// call returned rather than in a document. Most of them are ordinary policy:
// what one rule computed and another reads. The ones kept are those that
// descend from a builtin nobody in the policy controls.
func (r *refReader) taints(reach map[*ast.Rule]decisionPaths, limits Limits) ([]Taint, []string) {
	var (
		taints   []Taint
		warnings []string
	)
	for _, entry := range r.found {
		for _, candidate := range dropPrefixes(entry.refs) {
			if candidate.resolved.root == nil {
				continue
			}

			budget := &callBudget{limits: limits}
			source, external := r.externalOrigin(*candidate.resolved.root, candidate.bindings, budget, 0)
			warnings = append(warnings, budget.warnings...)
			if !external {
				continue
			}
			decisions := r.decisionsAt(entry.rule, candidate.top, reach)
			if len(decisions) == 0 {
				continue
			}
			taints = append(taints, r.taintOf(entry.rule, candidate, source, decisions))
		}
	}
	return taints, warnings
}

// decisionPaths says, for one rule, which decisions reach it and whether any of
// them reaches it on the side that grants.
type decisionPaths map[string]bool

// taintOf describes one tainted read.
func (r *refReader) taintOf(rule *ast.Rule, candidate foundRef, source binding, decisions []ReachedDecision) Taint {
	ref, _ := r.readable(candidate.resolved.ref)
	taint := Taint{
		Rule:          rulePath(rule).String(),
		Ref:           ref,
		Origin:        source.origin.String(),
		Endpoint:      endpointOf(source, candidate.bindings),
		Errors:        errorHandlingOf(source, candidate.bindings),
		UnderNegation: candidate.negated,
	}

	loc := candidate.location
	if loc == nil {
		loc = rule.Loc()
	}
	if loc != nil {
		taint.File, taint.Line = loc.File, loc.Row
	}

	for _, decision := range decisions {
		taint.Decisions = append(taint.Decisions, TaintedDecision{
			Name:          decision.Name,
			UnderNegation: candidate.negated != decision.UnderNegation,
		})
	}
	return taint
}

// reachedDecisions turns what the walk recorded about one rule into the
// decisions that depend on it, in a stable order.
//
// The flag stays about the way down, and combining it with the negation of the
// expression is left to whoever asks: the taint of a value takes the two
// together, and the pattern about a check that goes missing takes them apart.
func reachedDecisions(reached decisionPaths) []ReachedDecision {
	decisions := make([]ReachedDecision, 0, len(reached))
	for name, grants := range reached {
		decisions = append(decisions, ReachedDecision{Name: name, UnderNegation: !grants})
	}
	slices.SortFunc(decisions, func(a, b ReachedDecision) int {
		return strings.Compare(a.Name, b.Name)
	})
	return decisions
}

// decisionReach says, for every rule the walk visited, which decisions reach it
// and whether any of them reaches it on the side that grants.
//
// The walk starts at the decisions, so every rule it visited contributes to
// one; what the walk does not keep is which. That is the missing half of the
// taint claim, and it is also where the negation of a whole rule shows up: not
// denied_vulnerable makes every read inside that rule a read that denies, and
// no property of the rule itself can say so.
//
// The side is the parity of the negations on the way down. A second negation
// takes the first one back: an exemption a violation asks not to hold, in a
// decision that asks for no violation, grants when it holds.
//
// The state is the pair of a rule and the side the path so far lands on, so a
// rule reached both ways is recorded both ways and the side that grants wins.
// Cycles cannot happen, since OPA refuses to compile a policy whose rules
// depend on each other in a loop, but the visited set makes the walk terminate
// regardless of that guarantee.
func (r *refReader) decisionReach(decisions []decisionRoot) map[*ast.Rule]decisionPaths {
	type state struct {
		rule   *ast.Rule
		grants bool
	}

	reached := make(map[*ast.Rule]decisionPaths)
	for _, decision := range decisions {
		name := decision.name

		seen := make(map[state]bool)
		queue := []state{{rule: decision.rule, grants: true}}
		for len(queue) > 0 {
			at := queue[0]
			queue = queue[1:]
			if seen[at] {
				continue
			}
			seen[at] = true

			paths := reached[at.rule]
			if paths == nil {
				paths = make(decisionPaths)
				reached[at.rule] = paths
			}
			paths[name] = paths[name] || at.grants

			for _, edge := range r.edges[at.rule] {
				if at.rule == decision.rule && decision.within != nil && !decision.within[edge.top] {
					// The expression only builds another field of what the
					// rule returns, and this decision is not asked about it.
					continue
				}
				queue = append(queue, state{rule: edge.callee, grants: at.grants != edge.negated})
			}
		}
	}
	return reached
}

// externalOrigin finds the builtin a value descends from, when that builtin is
// one nothing in the policy controls.
//
// bindingProvenance answers the same question with a yes or a no and stops
// there, on purpose: for a read of data, naming the builtin behind two hops of
// policy would claim a directness that is not there. Taint is the one question
// where the far end of the chain is the answer, which is why it is asked here
// and separately rather than by widening what a read reports.
//
// A pure builtin is not a wall to stop at: it returns nothing its arguments did
// not already hold, so a decision reading count(response.body.groups) depends
// on the response just as much as one reading the response itself.
func (r *refReader) externalOrigin(b binding, bindings map[ast.Var]binding, budget *callBudget, depth int) (binding, bool) {
	if depth >= budget.limits.maxCallDepth() {
		budget.warn("stopped at %d calls deep while following what %s returned: raise MaxCallDepth to follow further",
			budget.limits.maxCallDepth(), b.origin)
		return binding{}, false
	}

	switch b.kind {
	case bindingOutput:
		if b.external {
			return b, true
		}
		return r.externalOfTerms(b.args, bindings, budget, depth+1)

	case bindingRuleOutput:
		if source, found := r.externalOfTerms(b.args, bindings, budget, depth+1); found {
			return source, true
		}
		for _, rule := range r.compiler.GetRulesForVirtualDocument(b.origin) {
			if !budget.spend(rule) {
				break
			}
			if rule.Head.Value == nil {
				continue
			}
			source, found := r.externalOfTerm(rule.Head.Value, r.bindingsOf(rule, rule.Body, nil), budget, depth+1)
			if found {
				return source, true
			}
		}
	}
	return binding{}, false
}

// externalOfTerms returns the first external source among a list of terms.
func (r *refReader) externalOfTerms(terms []*ast.Term, bindings map[ast.Var]binding, budget *callBudget, depth int) (binding, bool) {
	for _, term := range terms {
		if source, found := r.externalOfTerm(term, bindings, budget, depth); found {
			return source, true
		}
	}
	return binding{}, false
}

// externalOfTerm returns the external source a term's value descends from.
func (r *refReader) externalOfTerm(term *ast.Term, bindings map[ast.Var]binding, budget *callBudget, depth int) (binding, bool) {
	if v, isVar := varOf(term); isVar {
		switch resolved := resolveVar(v, bindings); resolved.status {
		case resolvedTerm:
			return r.externalOfTerm(resolved.term, bindings, budget, depth)
		case resolvedOutput:
			return r.externalOrigin(resolved.source, bindings, budget, depth)
		default:
			return binding{}, false
		}
	}

	ref, isRef := term.Value.(ast.Ref)
	if !isRef {
		return binding{}, false
	}
	if resolved := substituteRef(ref, bindings); resolved.root != nil {
		return r.externalOrigin(*resolved.root, bindings, budget, depth)
	}
	return binding{}, false
}

// endpointOf reads where a call went, when the call names it as a constant.
//
// It knows the two builtins whose destination is written in a place worth
// reading, instead of taking the first constant string it finds among the
// arguments. That shortcut would report rand.intn("seed", 10) as a call to an
// endpoint named seed: every builtin here is nondeterministic, and not every
// nondeterministic builtin talks to somebody.
//
// A custom builtin registered by the host has a destination too, and no way to
// declare it yet. The reference stays empty rather than guessed.
func endpointOf(source binding, bindings map[ast.Var]binding) string {
	switch source.origin.String() {
	case "http.send":
		return objectField(source.args, bindings, "url")
	case "net.lookup_ip_addr":
		return firstString(source.args)
	default:
		return ""
	}
}

// errorHandlingOf reads what a call asked to happen when it fails.
//
// Only http.send takes the option. A request the policy computes is reported as
// unknown rather than as the default: assuming the default would claim that a
// mitigation is available without having read anything that says so.
func errorHandlingOf(source binding, bindings map[ast.Var]binding) ErrorHandling {
	if source.origin.String() != "http.send" {
		return ErrorHandlingDefault
	}

	request, written := requestObject(source.args, bindings)
	if !written {
		return ErrorHandlingUnknown
	}

	asked := request.Get(ast.StringTerm("raise_error"))
	if asked == nil {
		// The request is there and says nothing about errors, which is the
		// default and the case where a switch is still available.
		return ErrorHandlingDefault
	}
	raise, isBool := asked.Value.(ast.Boolean)
	switch {
	case !isBool:
		return ErrorHandlingUnknown
	case bool(raise):
		return ErrorHandlingDefault
	default:
		return ErrorHandlingSuppressed
	}
}

// requestObject returns the request a call was given, following a variable to
// what it stands for.
//
// A policy that builds its request above the call and passes the variable is
// writing the same request, only not in one line, and it is a common way to
// write one. Refusing to follow that step would report a destination as
// computed and a mitigation as unreadable on a policy that spells out both.
func requestObject(args []*ast.Term, bindings map[ast.Var]binding) (ast.Object, bool) {
	for _, arg := range args {
		if object, isObject := arg.Value.(ast.Object); isObject {
			return object, true
		}
		v, isVar := varOf(arg)
		if !isVar {
			continue
		}
		if resolved := resolveVar(v, bindings); resolved.status == resolvedTerm {
			if object, isObject := resolved.term.Value.(ast.Object); isObject {
				return object, true
			}
		}
	}
	return nil, false
}

// objectField returns a constant string field of the request object.
func objectField(args []*ast.Term, bindings map[ast.Var]binding, field string) string {
	request, written := requestObject(args, bindings)
	if !written {
		return ""
	}
	value := request.Get(ast.StringTerm(field))
	if value == nil {
		return ""
	}
	if text, isString := value.Value.(ast.String); isString {
		return string(text)
	}
	return ""
}

// firstString returns the first argument that is a constant string.
func firstString(args []*ast.Term) string {
	for _, arg := range args {
		if text, isString := arg.Value.(ast.String); isString {
			return string(text)
		}
	}
	return ""
}
