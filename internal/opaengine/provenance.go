package opaengine

import (
	"slices"
	"strings"

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

	through := r.paramReads(limits, reach)
	result.Warnings = append(result.Warnings, through.warnings...)

	for _, entry := range r.found {
		for _, candidate := range dropPrefixes(entry.refs, through.extends[entry.rule]) {
			if candidate.resolved.root != nil {
				// Not a read of a document: the reference hangs off what a call
				// returned. Where that value came from is taint.go's question,
				// and counting it here would move the number of data paths.
				continue
			}
			budget := &callBudget{limits: limits}
			read := r.readOf(entry.rule, candidate, budget)
			read.Decisions = r.decisionsAt(entry.rule, candidate.top, reach)
			if len(read.Decisions) == 0 {
				// The expression only builds a field of the answer that no
				// decision asks about, which is not a read of any of them.
				continue
			}
			read.Matches = matchesFor(matches[entry.rule], candidate.resolved.ref)
			result.Reads = append(result.Reads, read)
			result.Warnings = append(result.Warnings, budget.warnings...)
		}
		result.Reads = append(result.Reads, through.reads[entry.rule]...)
	}

	for _, paths := range r.inputPaths {
		result.InputPaths = append(result.InputPaths, dropPrefixPaths(paths)...)
	}
	result.InputPaths = sortedUnique(result.InputPaths)
	result.RequestReads = r.requestReadsOf(reach)
	return result
}

// requestReadsOf names the decisions that reach each place a rule touches a
// part of the request, and leaves out the places no decision reaches. The same
// part touched twice on one line is one place.
//
// A field of a parameter is a part of the request where a call hands the
// function one, the whole request included, and is listed for the decisions
// that reach the function through that call.
func (r *refReader) requestReadsOf(reach map[*ast.Rule]decisionPaths) []RequestRead {
	var reads []RequestRead
	keep := func(rule *ast.Rule, path string, location *ast.Location, decisions []ReachedDecision) {
		if len(decisions) == 0 {
			return
		}
		read := RequestRead{Path: path, Rule: rulePath(rule).String(), Decisions: decisions}
		if location == nil {
			location = rule.Loc()
		}
		if location != nil {
			read.File, read.Line = location.File, location.Row
		}
		if !slices.ContainsFunc(reads, func(other RequestRead) bool {
			return other.Path == read.Path && other.Rule == read.Rule && other.File == read.File && other.Line == read.Line
		}) {
			reads = append(reads, read)
		}
	}

	for _, touched := range r.requestReads {
		keep(touched.rule, touched.path, touched.location, r.decisionsAt(touched.rule, touched.top, reach))
	}
	for _, found := range r.foundParams {
		decisions := r.decisionsAt(found.rule, found.top, reach)
		for _, passed := range r.arguments(found.rule, found.param) {
			base, isRef := passed.term.Value.(ast.Ref)
			if !isRef || !isInputRooted(base) {
				continue
			}
			keep(found.rule, normalize(base.Concat(found.resolved.ref[1:])), found.location,
				reachedBy(decisions, r.decisionsAt(passed.site.caller, passed.site.top, reach)))
		}
	}
	return reads
}

// paramReads are the reads made through a parameter: a function that is handed
// a document and reads a field of it.
type paramReads struct {
	// reads are the reads, by the function each sits in.
	reads map[*ast.Rule][]Read

	// extends are the references those reads go on from, written out to the
	// field, by the rule whose body names the document. There the document is
	// only the way to the field, as it is when the field is read in the same
	// body.
	extends map[*ast.Rule][]ast.Ref

	warnings []string
}

// paramReads turns the references that start at a parameter into reads, one for
// every document a caller hands over.
//
// privileged(user) reads user.role, and nothing in its body says whose role.
// The call does: privileged(data.users[input.user]) makes it
// data.users[input.user].role, the read a pattern needs to see, since a
// function is where a policy puts a test it makes of more than one record. The
// read sits in the function, where the field is named, and belongs to the
// decisions that reach the function through that call.
//
// A parameter handed something other than a document reads no data here: a part
// of the request is a check's concern (see requestOf), and what a call returned
// is where a value from outside the policy is followed (see taint.go).
func (r *refReader) paramReads(limits Limits, reach map[*ast.Rule]decisionPaths) paramReads {
	through := paramReads{reads: map[*ast.Rule][]Read{}, extends: map[*ast.Rule][]ast.Ref{}}

	// The reads of each reference first, since a function further down can
	// turn one of them into the way to its own: outer(user) passing
	// user.profile to a function that reads profile.team reads the team, and
	// the profile only on the way there.
	made := make([][]Read, len(r.foundParams))
	passedOn := map[*ast.Rule][]ast.Ref{}
	for i, found := range r.foundParams {
		budget := &callBudget{limits: limits}
		decisions := r.decisionsAt(found.rule, found.top, reach)
		for _, passed := range r.arguments(found.rule, found.param) {
			base, isRef := passed.term.Value.(ast.Ref)
			if !isRef {
				continue
			}
			document := substituteRef(base, passed.site.bindings)
			if document.root != nil || !isDataRooted(document.ref) || r.namesRule(document.ref) {
				continue
			}
			ref := document.ref.Concat(found.resolved.ref[1:])
			if r.namesRule(ref) {
				continue
			}

			read := r.paramRead(found, passed.site, document, ref, budget)
			read.Decisions = reachedBy(decisions, r.decisionsAt(passed.site.caller, passed.site.top, reach))
			if len(read.Decisions) == 0 {
				continue
			}
			through.extends[passed.site.caller] = append(through.extends[passed.site.caller], ref)
			for _, field := range passed.via {
				passedOn[field.rule] = append(passedOn[field.rule], field.ref)
			}
			made[i] = withRead(made[i], read)
		}
		through.warnings = append(through.warnings, budget.warnings...)
	}

	for i, found := range r.foundParams {
		if slices.ContainsFunc(passedOn[found.rule], func(field ast.Ref) bool { return field.Equal(found.resolved.ref) }) {
			continue
		}
		for _, read := range made[i] {
			through.reads[found.rule] = withRead(through.reads[found.rule], read)
		}
	}
	return through
}

// paramRead is the read a field of a parameter makes of one document a call
// hands over.
//
// Who picks the document is asked of the body that names it, and who picks what
// the function goes on to inside it is asked of the function. The stronger of
// the two answers is the read's, as among the indexes of any reference.
func (r *refReader) paramRead(found paramRef, site callSite, document substitutedRef, ref ast.Ref, budget *callBudget) Read {
	caller := rulePath(site.caller).String()
	trace := &Trace{Callers: []string{caller}}

	outside, origin := r.indexProvenance(document, site.bindings, budget, 0)
	if outside == ProvenanceUnresolved {
		var asked *Trace
		if outside, asked = r.throughCallers(site.caller, document, budget); asked != nil {
			trace = &Trace{Term: asked.Term, Callers: append([]string{caller}, asked.Callers...)}
		}
	}

	// The parameter itself is answered for by the call. An index nothing binds
	// ranges over what the document holds, which is the data's to pick.
	field, ranges := found.resolved, false
	field.unresolved = slices.DeleteFunc(slices.Clone(field.unresolved), func(v ast.Var) bool {
		if v == found.param {
			return true
		}
		if _, isParam := parameterPlaceOf(found.rule, v); isParam {
			return false
		}
		ranges = true
		return true
	})
	inside, insideOrigin := r.indexProvenance(field, found.bindings, budget, 0)
	if inside == ProvenanceUnresolved {
		var asked *Trace
		if inside, asked = r.throughCallers(found.rule, field, budget); asked != nil && trace.Term == "" {
			trace = asked
		}
	}
	if ranges && !better(inside, ProvenanceData) {
		inside, insideOrigin = ProvenanceData, ""
	}

	provenance := outside
	switch {
	case better(inside, outside) && inside != ProvenanceStatic:
		provenance, origin = inside, insideOrigin
	case outside == ProvenanceStatic && inside == ProvenanceUnresolved:
		// Nothing says who picks the field the function goes on to.
		provenance = ProvenanceUnresolved
	}

	readable, _ := r.readable(ref)
	read := Read{
		Path:          normalize(ref),
		Ref:           readable,
		Rule:          rulePath(found.rule).String(),
		Provenance:    provenance,
		Origin:        origin,
		Trace:         trace,
		Indexes:       r.indexesOf(ref, trace),
		Matches:       r.matchesThrough(found, site, document, ref),
		UnderNegation: found.negated,
		RuleDefault:   r.defaultOf(found.rule),
	}
	loc := found.location
	if loc == nil {
		loc = found.rule.Loc()
	}
	if loc != nil {
		read.File, read.Line = loc.File, loc.Row
	}
	return read
}

// reachedBy keeps the decisions that also reach the call a read comes through.
// A function called by two decisions with two documents reads each of them for
// the decision that hands it over, and not for the other.
func reachedBy(decisions, throughCall []ReachedDecision) []ReachedDecision {
	return slices.DeleteFunc(slices.Clone(decisions), func(decision ReachedDecision) bool {
		return !slices.ContainsFunc(throughCall, func(other ReachedDecision) bool { return other.Name == decision.Name })
	})
}

// withRead adds a read to the reads of a function, or its decisions to the same
// read made through another call.
func withRead(reads []Read, read Read) []Read {
	for i := range reads {
		same := reads[i].Ref == read.Ref && reads[i].Line == read.Line && reads[i].File == read.File
		if !same {
			continue
		}
		for _, decision := range read.Decisions {
			if !slices.Contains(reads[i].Decisions, decision) {
				reads[i].Decisions = append(reads[i].Decisions, decision)
			}
		}
		slices.SortFunc(reads[i].Decisions, func(a, b ReachedDecision) int { return strings.Compare(a.Name, b.Name) })
		return reads
	}
	return append(reads, read)
}

// dropPrefixPaths removes the paths of input that are a strict prefix of
// another path the same rule touches.
//
// It is dropPrefixes for the request, and for the same reason: the compiler
// hands object.get(input, ["created_by", "username"], "") a variable it first
// binds to input, and touching input to reach one field of it is touching that
// field. Kept, the whole request would stay unknown to every question that
// fixes the subject, and the subject would not be fixed.
func dropPrefixPaths(paths []string) []string {
	kept := make([]string, 0, len(paths))
	for _, path := range paths {
		if !slices.ContainsFunc(paths, func(other string) bool {
			return strings.HasPrefix(other, path+".") || strings.HasPrefix(other, path+"[")
		}) {
			kept = append(kept, path)
		}
	}
	return kept
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
