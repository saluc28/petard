package opaengine

import (
	"slices"

	"github.com/open-policy-agent/opa/v1/ast"
)

// This file holds the judgment: given a reference and what its body knows,
// who chooses the document it lands on. The part of the answer that lives at
// the call sites is in calls.go.

// resolve turns the references found into reads, asking the call sites about
// the indexes no body could answer for.
func (r *refReader) resolve(limits Limits, reach map[*ast.Rule]decisionPaths) *ReadSet {
	result := &ReadSet{}

	matches, warnings := r.matches(limits)
	result.Warnings = append(result.Warnings, warnings...)

	for _, entry := range r.found {
		for _, candidate := range dropPrefixes(entry.refs) {
			if candidate.resolved.root != nil {
				// Not a read of a document: the reference hangs off what a call
				// returned. Where that value came from is taint.go's question,
				// and counting it here would move the number of data paths.
				continue
			}
			budget := &callBudget{limits: limits}
			read := r.readOf(entry.rule, candidate, budget)
			read.Decisions = reachedDecisions(reach[entry.rule])
			read.Matches = matchesFor(matches[entry.rule], candidate.resolved.ref)
			result.Reads = append(result.Reads, read)
			result.Warnings = append(result.Warnings, budget.warnings...)
		}
	}

	result.InputPaths = sortedUnique(slices.Clone(r.inputPaths))
	return result
}

// readOf turns one reference into a read, asking the callers about the index
// when the body it was found in cannot say.
func (r *refReader) readOf(rule *ast.Rule, candidate foundRef, budget *callBudget) Read {
	provenance, origin := r.indexProvenance(candidate.resolved, candidate.bindings, budget, 0)

	var trace *Trace
	if provenance == ProvenanceUnresolved {
		provenance, trace = r.throughCallers(rule, candidate.resolved, budget)
	}

	ref, _ := r.readable(candidate.resolved.ref)
	read := Read{
		Path:          normalize(candidate.resolved.ref),
		Ref:           ref,
		Rule:          rulePath(rule).String(),
		Provenance:    provenance,
		Origin:        origin,
		Trace:         trace,
		Indexes:       r.indexesOf(candidate.resolved.ref, trace),
		UnderNegation: candidate.negated,
		RuleDefault:   r.defaultOf(rule),
	}

	loc := candidate.location
	if loc == nil {
		// Terms the compiler generates carry no location of their own, and the
		// rule they belong to is the closest true answer.
		loc = rule.Loc()
	}
	if loc != nil {
		read.File, read.Line = loc.File, loc.Row
	}
	return read
}

// defaultOf returns the value a rule falls back to when no body of it holds.
//
// A default is a rule of its own in the compiled policy, sitting next to the
// ones that have a body, which is why it is looked up among the siblings rather
// than read off the rule at hand. Its absence is an answer too: a rule with no
// default is undefined when nothing holds, and undefined is not false.
func (r *refReader) defaultOf(rule *ast.Rule) string {
	for _, sibling := range r.compiler.GetRulesExact(rulePath(rule)) {
		if sibling.Default {
			return valueOf(sibling)
		}
	}
	return ""
}

// throughCallers asks the call sites about the variables the body left open.
//
// A reference with more than one open variable takes the strongest answer: if
// any one of them turns out to be chosen by the caller, the caller has a say
// in which document is read, and that is the fact worth reporting.
func (r *refReader) throughCallers(rule *ast.Rule, resolved substitutedRef, budget *callBudget) (Provenance, *Trace) {
	best, bestTrace := ProvenanceUnresolved, (*Trace)(nil)
	for _, v := range resolved.unresolved {
		provenance, trace := r.parameterProvenance(rule, v, budget, 0)
		if better(provenance, best) {
			best, bestTrace = provenance, trace
		}
	}
	return best, bestTrace
}

// indexProvenance decides who chooses the document a read picks.
//
// It asks about the indexes, not about the root: a read is always rooted in
// data, and what varies is which document it lands on. The question about a
// root is a different one, and rootProvenance is where it is asked.
//
// The strongest answer among the indexes wins, for the same reason it wins
// among call sites: one index the requester controls is enough to make the
// read one they can steer.
func (r *refReader) indexProvenance(resolved substitutedRef, bindings map[ast.Var]binding, budget *callBudget, depth int) (Provenance, string) {
	best, origin := ProvenanceStatic, ""

	consider := func(source binding) {
		if p := r.bindingProvenance(source, bindings, budget, depth); better(p, best) {
			best, origin = p, originOf(source)
		}
	}
	if resolved.root != nil {
		consider(*resolved.root)
	}
	for _, index := range resolved.indexes {
		consider(index)
	}

	for _, term := range resolved.ref[1:] {
		inner, ok := term.Value.(ast.Ref)
		if !ok {
			continue
		}
		if p := rootOfRef(inner); better(p, best) {
			best, origin = p, ""
		}
	}

	// Nothing positive to say, and an open variable: that is unresolved rather
	// than constant, and the difference is the whole second measure.
	if best == ProvenanceStatic && len(resolved.unresolved) > 0 {
		return ProvenanceUnresolved, ""
	}
	return best, origin
}

// rootProvenance decides where the value of a term comes from, by its root.
//
// This is the question to ask about an argument passed at a call site:
// input.user is rooted in input whatever its trailing segments are, and
// answering it with the rule for indexes would say "static", because the only
// dynamic segment it has is none.
func (r *refReader) rootProvenance(resolved substitutedRef, bindings map[ast.Var]binding, budget *callBudget, depth int) Provenance {
	if resolved.root != nil {
		return r.bindingProvenance(*resolved.root, bindings, budget, depth)
	}
	if len(resolved.unresolved) > 0 {
		return ProvenanceUnresolved
	}
	return rootOfRef(resolved.ref)
}

// originOf names the source of a value, but only where the name is the truth.
//
// A value that came through a rule of the policy has that rule as its origin,
// not whatever the rule called: reporting the deeper name would claim a
// directness that is not there.
func originOf(b binding) string {
	if b.kind == bindingOutput && b.external {
		return b.origin.String()
	}
	return ""
}

// indexesOf lists the dynamic segments of a reference, with what stands in
// each.
//
// When the rule itself does not say, the answer may still have come from a
// call site. A trace speaks for one index, so it is only used when there is
// exactly one to speak for: with two open indexes there would be no telling
// which of them it answers.
func (r *refReader) indexesOf(ref ast.Ref, trace *Trace) []Index {
	var indexes []Index
	for i, term := range ref[1:] {
		switch term.Value.(type) {
		case ast.String, ast.Number:
			continue
		}

		text := ""
		if inner, ok := term.Value.(ast.Ref); ok {
			if readable, presentable := r.readable(inner); presentable {
				text = readable
			}
		}
		indexes = append(indexes, Index{Position: i + 1, Term: text})
	}

	if len(indexes) == 1 && indexes[0].Term == "" && trace != nil {
		indexes[0].Term = trace.Term
	}
	return indexes
}
