package opaengine

import (
	"slices"

	"github.com/open-policy-agent/opa/v1/ast"
)

// This file finds where a decision looks a part of the request up by value.
//
// An index is one way a request picks a document: data.users[input.user] names
// the document by its key. The other way is to take every document of a
// collection and keep the ones that hold the value, and it is at least as
// common. Kubernetes applies a role binding when one of its subjects equals the
// name or one of the groups of whoever is asking (appliesTo and appliesToUser,
// pkg/registry/rbac/validation/rule.go:263 at v1.37.0), Chef Automate grants
// through the policies whose members hold one of the subjects of the request,
// and the data filtering example of open-policy-agent/contrib keeps the posts
// whose author is the requester, which OPA then compiles into a SQL filter.
// Reading only the indexes would leave all of them looking like documents the
// data picks.

// Match is a part of the request that a read is searched for by value.
type Match struct {
	// Term is the part of the request, as a path with every dynamic segment
	// written [_]: input.user, input.subjects[_].
	Term string

	// Position is the segment of the read that holds the value, counted from
	// the data root the way Index counts. For an equality it is the last
	// dynamic segment, the element of the collection that is being kept or
	// dropped. For a search with in it is one past the end of the path: the
	// read is the collection, and the element has no segment of its own there.
	Position int

	// Member is true when the read is the collection and the term is looked for
	// among its elements, rather than compared with the value the read lands on.
	Member bool
}

// comparison is an expression that tests two terms against each other, with
// the terms as the body holding it writes them.
type comparison struct {
	// left and right are the two sides. For a search, left is the element and
	// right the collection.
	left, right *ast.Term
	member      bool
}

// foundComparison is a comparison met while walking, kept with what its body
// knows, because judging its sides means asking the call sites, and those are
// only all known once the walk is over.
type foundComparison struct {
	comparison
	rule     *ast.Rule
	bindings map[ast.Var]binding
}

// paramSide is one side of a comparison a function makes, as its callers see
// it: one of its parameters, or a part of the request the function reads on its
// own.
type paramSide struct {
	// param is the position of the parameter, or -1 when the side is request.
	param   int
	request ast.Ref
}

// paramComparison is a comparison a function makes that its callers can map
// onto their own arguments.
type paramComparison struct {
	left, right paramSide
	member      bool
}

// markComparisons records the comparisons an expression makes.
func (r *refReader) markComparisons(expr *ast.Expr, sc scope) {
	for _, found := range r.comparisonsIn(r.current, expr, sc.bindings) {
		r.foundComparisons = append(r.foundComparisons, foundComparison{
			comparison: found,
			rule:       r.current,
			bindings:   sc.bindings,
		})
	}
}

// comparisonsIn returns what an expression compares: the two sides of an
// equality or of a search with in, or the arguments a function of the policy
// compares once the call is made.
//
// Only a call that asserts counts. equal(a, b, x) is how the compiler writes
// x := a == b, and it holds whether or not a equals b. A function is followed
// only when it is called as a condition: called for its value, it may well be
// defined with a result that says no.
func (r *refReader) comparisonsIn(rule *ast.Rule, expr *ast.Expr, bindings map[ast.Var]binding) []comparison {
	operator := expr.Operator()
	if operator == nil || len(expr.With) > 0 {
		return nil
	}
	operands := expr.Operands()

	switch operator.String() {
	case ast.Equality.Name:
		if len(operands) != 2 || bindsHere(rule, operands[0], operands[1], bindings) {
			return nil
		}
		return []comparison{{left: operands[0], right: operands[1]}}
	case ast.Equal.Name:
		if len(operands) != 2 {
			return nil
		}
		return []comparison{{left: operands[0], right: operands[1]}}
	case ast.Member.Name:
		if len(operands) != 2 {
			return nil
		}
		return []comparison{{left: operands[0], right: operands[1], member: true}}
	case ast.MemberWithKey.Name:
		if len(operands) != 3 {
			return nil
		}
		return []comparison{{left: operands[1], right: operands[2], member: true}}
	}

	callees := r.compiler.GetRulesForVirtualDocument(operator)
	if len(callees) == 0 || len(callees[0].Head.Args) != len(operands) {
		return nil
	}
	var found []comparison
	for _, compared := range r.summary(callees) {
		left, right := compared.left.at(operands), compared.right.at(operands)
		if left != nil && right != nil {
			found = append(found, comparison{left: left, right: right, member: compared.member})
		}
	}
	return found
}

// at puts the side of a function's comparison into the terms of a call.
func (s paramSide) at(operands []*ast.Term) *ast.Term {
	if s.param < 0 {
		return ast.NewTerm(s.request)
	}
	if s.param >= len(operands) {
		return nil
	}
	return operands[s.param]
}

// bindsHere reports whether an equality gives a variable its value rather than
// testing it.
//
// The compiler writes x := data.users[_] and x == data.users[_] with the same
// operator once it is done, and only the first is a binding. The binding table
// already says which expression bound each variable, so the question is
// whether it was this one. A parameter is never bound by its own body: its
// value comes from the caller, and an equality on it is a test.
func bindsHere(rule *ast.Rule, left, right *ast.Term, bindings map[ast.Var]binding) bool {
	parameters := parameterVars(rule)
	for _, pair := range [][2]*ast.Term{{left, right}, {right, left}} {
		v, isVar := varOf(pair[0])
		if !isVar || parameters[v] {
			continue
		}
		if bound, ok := bindings[v]; ok && bound.kind == bindingAlias && bound.term == pair[1] {
			return true
		}
	}
	return false
}

// summary returns the comparisons a function makes between its parameters, or
// between a parameter and the request, over every definition it has.
//
// A function with several definitions holds when any of them does, so a
// comparison made by one of them is one way the call can hold, and that is the
// claim a lookup rests on. What a function compares inside its own body
// between a parameter and the data is not here: that read is in the function,
// and it is judged where it is, through the callers.
func (r *refReader) summary(rules []*ast.Rule) []paramComparison {
	key := rulePath(rules[0]).String()
	if known, done := r.summaries[key]; done {
		return known
	}
	// Rego refuses recursion between rules, so this is never met on the way
	// back to the same function. It is set anyway, because the cost of being
	// wrong about that would be a stack overflow on somebody else's bundle.
	r.summaries[key] = nil

	var summary []paramComparison
	for _, rule := range rules {
		bindings := r.bindingsOf(rule, rule.Body, nil)
		for _, expr := range rule.Body {
			for _, compared := range r.comparisonsIn(rule, expr, bindings) {
				left, leftOK := sideOf(rule, compared.left, bindings)
				right, rightOK := sideOf(rule, compared.right, bindings)
				if !leftOK || !rightOK || (left.param < 0 && right.param < 0) {
					continue
				}
				entry := paramComparison{left: left, right: right, member: compared.member}
				if !slices.ContainsFunc(summary, entry.equal) {
					summary = append(summary, entry)
				}
			}
		}
	}
	r.summaries[key] = summary
	return summary
}

// sideOf says what a term of a function body is to the callers: a parameter,
// or a part of the request.
func sideOf(rule *ast.Rule, term *ast.Term, bindings map[ast.Var]binding) (paramSide, bool) {
	if v, isVar := varOf(term); isVar {
		if position, isParam := parameterPosition(rule, v); isParam {
			return paramSide{param: position}, true
		}
		if resolved := resolveVar(v, bindings); resolved.status == resolvedTerm {
			return sideOf(rule, resolved.term, bindings)
		}
		return paramSide{}, false
	}
	ref, isRef := term.Value.(ast.Ref)
	if !isRef {
		return paramSide{}, false
	}
	resolved := substituteRef(ref, bindings)
	if resolved.root != nil || !isInputRooted(resolved.ref) {
		return paramSide{}, false
	}
	return paramSide{param: -1, request: resolved.ref}, true
}

func (c paramComparison) equal(other paramComparison) bool {
	return c.member == other.member && c.left.equal(other.left) && c.right.equal(other.right)
}

func (s paramSide) equal(other paramSide) bool {
	return s.param == other.param && s.request.Equal(other.request)
}

// refMatch is a match found for one data reference of a rule, waiting for the
// read that reference becomes.
type refMatch struct {
	ref   ast.Ref
	match Match
}

// matches judges every comparison met while walking, and keeps the ones where
// one side is a document of the data and the other a part of the request.
//
// Each comparison gets the budget one reference gets for its indexes, since
// judging it is the same walk: where a parameter comes from.
func (r *refReader) matches(limits Limits) (map[*ast.Rule][]refMatch, []string) {
	found := make(map[*ast.Rule][]refMatch)
	var warnings []string
	for _, compared := range r.foundComparisons {
		budget := &callBudget{limits: limits}
		keep := func(document, request *ast.Term) {
			if match, ref, ok := r.matchOf(compared, document, request, budget); ok {
				found[compared.rule] = append(found[compared.rule], refMatch{ref: ref, match: match})
			}
		}

		// An equality is symmetric and either side can be the document. A
		// search is not: the collection is the document, and the element is
		// what it is searched for.
		keep(compared.right, compared.left)
		if !compared.member {
			keep(compared.left, compared.right)
		}
		warnings = append(warnings, budget.warnings...)
	}
	return found, warnings
}

// matchOf judges one orientation of a comparison.
func (r *refReader) matchOf(compared foundComparison, document, request *ast.Term, budget *callBudget) (Match, ast.Ref, bool) {
	ref, isDocument := r.documentOf(document, compared.bindings)
	if !isDocument {
		return Match{}, nil, false
	}
	term, isRequest := r.requestOf(compared.rule, request, compared.bindings, budget)
	if !isRequest {
		return Match{}, nil, false
	}

	if compared.member {
		return Match{Term: term, Position: len(ref), Member: true}, ref, true
	}
	position, ranges := rangingElement(ref, compared.bindings)
	if !ranges {
		// The value sits in a document something else names: the owner of the
		// document the request asks for, say. That is a check on a document,
		// not a lookup of the requester among many.
		return Match{}, nil, false
	}
	return Match{Term: term, Position: position}, ref, true
}

// documentOf returns the data reference a term stands for, when it names a
// document rather than something the policy computes.
func (r *refReader) documentOf(term *ast.Term, bindings map[ast.Var]binding) (ast.Ref, bool) {
	if v, isVar := varOf(term); isVar {
		if resolved := resolveVar(v, bindings); resolved.status == resolvedTerm {
			return r.documentOf(resolved.term, bindings)
		}
		return nil, false
	}
	ref, isRef := term.Value.(ast.Ref)
	if !isRef {
		return nil, false
	}
	resolved := substituteRef(ref, bindings)
	if resolved.root != nil || !isDataRooted(resolved.ref) || r.namesRule(resolved.ref) {
		return nil, false
	}
	return resolved.ref, true
}

// requestOf returns the part of the request a term stands for, asking the call
// sites when the term is a parameter.
func (r *refReader) requestOf(rule *ast.Rule, term *ast.Term, bindings map[ast.Var]binding, budget *callBudget) (string, bool) {
	if v, isVar := varOf(term); isVar {
		if _, isParam := parameterPosition(rule, v); isParam {
			provenance, trace := r.parameterProvenance(rule, v, budget, 0)
			if provenance != ProvenanceInput || trace == nil || trace.Term == "" {
				return "", false
			}
			return normalizeTerm(trace.Term), true
		}
		if resolved := resolveVar(v, bindings); resolved.status == resolvedTerm {
			return r.requestOf(rule, resolved.term, bindings, budget)
		}
		return "", false
	}
	ref, isRef := term.Value.(ast.Ref)
	if !isRef {
		return "", false
	}
	resolved := substituteRef(ref, bindings)
	if resolved.root != nil || !isInputRooted(resolved.ref) {
		return "", false
	}
	return normalize(resolved.ref), true
}

// rangingElement returns the last dynamic segment of a reference, when that
// segment ranges over its collection rather than being fixed by something.
func rangingElement(ref ast.Ref, bindings map[ast.Var]binding) (int, bool) {
	for i := len(ref) - 1; i > 0; i-- {
		switch value := ref[i].Value.(type) {
		case ast.String, ast.Number:
			continue
		case ast.Var:
			if value.IsWildcard() {
				return i, true
			}
			return i, resolveVar(value, bindings).status == resolvedIteration
		default:
			return 0, false
		}
	}
	return 0, false
}

// matchesFor returns the matches found for one reference of a rule, without
// repeats.
func matchesFor(found []refMatch, ref ast.Ref) []Match {
	var matches []Match
	for _, candidate := range found {
		if candidate.ref.Equal(ref) && !slices.Contains(matches, candidate.match) {
			matches = append(matches, candidate.match)
		}
	}
	return matches
}

// normalizeTerm writes a term the way normalize writes a reference, and leaves
// it as it is when it is not one.
func normalizeTerm(term string) string {
	ref, err := ast.ParseRef(term)
	if err != nil {
		return term
	}
	return normalize(ref)
}
