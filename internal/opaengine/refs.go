package opaengine

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/storage"
)

// This file holds what the analysis produces: the reads of a bundle, and the
// shape they are reported in. The walk that finds them is in walk.go, and the
// judgment about where their indexes come from is in provenance.go.

// ErrNoDecisions is returned when the bundle annotates no entrypoint and the
// caller declared none either.
//
// It is an error rather than an empty result on purpose. Without a decision
// there is nothing to walk back from, and a run that reports zero reads would
// be indistinguishable from a policy that reads nothing at all. Guessing which
// rules are decisions is a separate job, with a confidence level of its own to
// declare.
var ErrNoDecisions = errors.New("opaengine: no rule is annotated as an entrypoint, and none was declared")

// ErrNoSuchEntrypoint is returned when a declared entrypoint names neither a
// rule of the bundle, nor a document that rules with a reference in their head
// build, nor a part of the value a rule returns.
//
// A declaration that matches nothing is a mistake worth stopping for: taking it
// as zero decisions would report a policy nobody looked at as a policy that
// reads nothing.
var ErrNoSuchEntrypoint = errors.New("opaengine: no rule has the declared entrypoint path")

// ErrBadEntrypoint is returned when a declared entrypoint is not a rule path at
// all.
var ErrBadEntrypoint = errors.New("opaengine: the entrypoint is not a rule path")

// Provenance says where the dynamic part of a data path comes from.
//
// It is reported per read and never folded into the count of paths found.
// Finding data.users[_].roles is one capability; being able to say that the
// index is whoever is asking is another, and a single number that mixes them
// would hide whichever of the two is missing.
type Provenance int

const (
	// ProvenanceStatic means the path has no dynamic segment: it names one
	// document and always the same one.
	ProvenanceStatic Provenance = iota

	// ProvenanceInput means a dynamic segment resolves to input, so the caller
	// of the decision chooses which document is read.
	ProvenanceInput

	// ProvenanceData means the dynamic segments resolve to data: the document
	// is chosen by other data, not by the caller.
	ProvenanceData

	// ProvenanceBuiltin means the path is rooted in what a builtin returned,
	// named by Origin. The decision does not depend on the policy here, it
	// depends on whatever answered the call.
	ProvenanceBuiltin

	// ProvenanceUnresolved means a variable in the path is not bound in this
	// body, and the callers do not say what it is either.
	ProvenanceUnresolved
)

// String returns the provenance as it appears in a report.
func (p Provenance) String() string {
	switch p {
	case ProvenanceStatic:
		return "static"
	case ProvenanceInput:
		return "input"
	case ProvenanceData:
		return "data"
	case ProvenanceBuiltin:
		return "builtin"
	case ProvenanceUnresolved:
		return "unresolved"
	default:
		return "unknown"
	}
}

// Read is one place where a decision reads data.
type Read struct {
	// Path is the normalized path, with every dynamic segment written as [_]:
	// data.users[_].profile.department. Two reads of the same field through
	// different variables share a Path, which is what makes paths countable.
	Path string

	// Ref is the path as resolved inside the rule that reads it, keeping what
	// the index turned out to be: data.users[input.user].profile.department.
	// Inside a function the index stays the parameter, because that is what
	// the rule really reads: which document depends on who calls it.
	Ref string

	// Rule is the rule that reads it, File and Line where.
	Rule string
	File string
	Line int

	Provenance Provenance

	// Origin names the builtin the value came from, when Provenance is
	// ProvenanceBuiltin.
	Origin string

	// Trace is set when the provenance was established outside this rule, and
	// says how. Without it the claim would have to be taken on trust.
	Trace *Trace

	// Indexes are the dynamic segments of the path, with the position they sit
	// at, so that a captured segment of a write model entry can be matched
	// against the term that actually stands there.
	Indexes []Index

	// Matches are the parts of the request the read is searched for by value,
	// the other way a request picks a document. They leave Provenance alone:
	// that answers who names the key, and in data.policies[p].members[_] the
	// keys still come from the data, whatever the members are compared with.
	Matches []Match

	// UnderNegation is true when the reference is read inside a negated
	// expression.
	//
	// It is a plain bool in the AST, so this is exact rather than inferred,
	// and the taxonomy needs it: when the value is missing, a read to deny and
	// a read to grant fail in opposite directions. It says nothing about the
	// way down from the decision to this rule, which is a property of the walk
	// and is reported in Decisions.
	UnderNegation bool

	// Decisions are the entrypoints that depend on this read, sorted by name.
	Decisions []ReachedDecision

	// RuleDefault is the value the rule holding this read falls back to when no
	// body of it holds, and is empty when the rule declares none.
	//
	// It is what tells a check that goes silent from one that answers no. An
	// undefined body produces nothing at all, and a not on nothing succeeds; a
	// default of false ends the same way, and only a default that denies closes
	// it. Nothing else in a read carries the distinction, and asking for it
	// afterwards would mean keeping the rule around.
	RuleDefault string
}

// ReachedDecision is one decision that depends on a read, and how it depends on
// it.
//
// The flag is about the way down: whether every path from the decision to the
// rule holding the read meets an odd number of negations. It is kept apart from
// the negation of the expression, which Read reports on its own, because the two
// combine differently depending on the question. A check whose absence lets the
// request through is one combination, and there the two negations cancel out. A
// value somebody controls is not asked the question at all: they pick the value,
// so the side it lands on does not limit what they can do.
type ReachedDecision struct {
	// Name is the path the decision is asked at: the rule, or the field of what
	// the rule returns when that is what was declared.
	Name string

	// UnderNegation is true when every path from the decision down to the rule
	// meets an odd number of negations, so the rule holding can only deny. Two
	// take each other back: in a decision that grants on no violation, the
	// exemption a violation asks not to hold grants.
	UnderNegation bool
}

// Index is one dynamic segment of a read: which document it picks, and where
// in the path it does the picking.
type Index struct {
	// Position counts from the root: in data.users[input.user].profile the
	// index sits at 2, where data is 0 and users is 1.
	Position int

	// Term is what stands there, for instance input.user. It is empty when the
	// rule does not say and the callers could not either.
	Term string
}

// Trace is how the provenance of a read was established outside its own rule.
type Trace struct {
	// Term is what the index turns out to be at the call site, for instance
	// input.user. The rule itself cannot say it: inside a function the index
	// is a parameter, and which document it names depends on who calls.
	Term string

	// Callers is the chain of rules that carries the value, nearest first.
	Callers []string
}

// Closure is one place where a decision follows a relation as far as it goes.
//
// What it does not carry is the direction of the relation: whether the walk
// climbs to the ancestors of something or descends to what it contains. The
// direction would be needed by an analysis that rebuilt the relation to count
// what it reaches, and nothing here rebuilds anything. A pattern measures the
// closure by evaluating the decision twice, once against the data as it stands
// and once against data with the relation cut, so what the direction was never
// enters the number.
type Closure struct {
	// Builtin is the construct the policy used.
	Builtin string

	// Rule is where the call sits, File and Line where in the source.
	Rule string
	File string
	Line int

	// Relation are the data paths the relation is built from, sorted. It is
	// what somebody would have to change to stop the propagation, which makes
	// it both the explanation and the handle to measure with.
	//
	// It is empty when the relation is computed rather than read, and empty is
	// an answer: the propagation is there and nothing in the data holds it up.
	Relation []string

	// Seed is the term the walk starts from, in the words of the author.
	Seed string

	// Decisions are the entrypoints that depend on this closure, sorted by name.
	Decisions []ReachedDecision
}

// Quantifier is one every expression the decisions reach, with what it iterates
// and whether the body guards that domain against being empty.
//
// It is kept apart from Reads and Closures for the same reason those are kept
// apart from each other: it names a construct, not a document. An every over an
// empty domain is vacuously true, so on the side that grants it is a check that
// stops applying when there is nothing to apply it to, which is what
// PTD-OPA-007 looks for.
type Quantifier struct {
	// Rule is the rule the every sits in, File and Line where.
	Rule string
	File string
	Line int

	// Domain is the normalized path of the collection the every iterates, when
	// it is a reference into input or data. It is empty when the domain is a
	// literal or a computed value, which cannot be emptied by the request and so
	// is not the pattern's concern.
	Domain string

	// Provenance says whether the domain is chosen by the request or by the
	// data, the same scale a read carries.
	Provenance Provenance

	// Guarded is true when the body forces the domain non-empty before the
	// every, which is the counter case: a guarded every cannot go vacuous.
	Guarded bool

	// Decisions are the entrypoints that depend on this every, sorted by name.
	// The parity of the negation on the way down says whether a vacuous truth
	// grants or denies, which is the whole difference between fail-open and
	// fail-closed.
	Decisions []ReachedDecision
}

// ReadSet is everything the decisions of a bundle read.
type ReadSet struct {
	Reads []Read

	// Closures are the places the decisions follow a relation transitively.
	Closures []Closure

	// Quantifiers are the every expressions the decisions reach.
	Quantifiers []Quantifier

	// Taints are the values the decisions read that the policy did not
	// compute, with the decisions each of them reaches.
	//
	// They are kept apart from Reads, and it is not a matter of tidiness. A
	// read names a document under data, and the count of those is the measure
	// the fixture is checked against; a tainted value names no document at
	// all, since it is whatever answered a call. Folding the two together
	// would move a number that means something else.
	Taints []Taint

	// Decisions are the entrypoints the walk started from.
	Decisions []string

	// SkippedUnderWith lists rules that only expressions carrying a with
	// modifier reach. They are left out of the decisions, and listed rather
	// than dropped in silence: counting them would treat test scaffolding as
	// policy and inflate every number measured.
	SkippedUnderWith []string

	// Warnings are the limits the walk ran into. A bound that stops the
	// analysis has to say so: an answer cut short and an answer that does not
	// exist look the same in a number.
	Warnings []string

	// InputPaths are the parts of the request the decisions touch, sorted and
	// distinct. They are what the shape recognizers read.
	InputPaths []string
}

// Paths returns the distinct normalized paths, sorted.
func (rs *ReadSet) Paths() []string {
	paths := make([]string, 0, len(rs.Reads))
	for _, read := range rs.Reads {
		paths = append(paths, read.Path)
	}
	slices.Sort(paths)
	return slices.Compact(paths)
}

// CountWithProvenance returns how many reads have the given provenance.
func (rs *ReadSet) CountWithProvenance(p Provenance) int {
	count := 0
	for _, read := range rs.Reads {
		if read.Provenance == p {
			count++
		}
	}
	return count
}

// Reads finds every place the decisions of a bundle read data.
//
// It starts from the decisions, the rules the policy annotates as entrypoints
// plus the ones Bundle.Entrypoints declares, and walks the rules they
// depend on, following calls but not expressions that carry a with modifier.
// Inside each rule it resolves references against the bindings of the body
// they live in, including the bodies of comprehensions and every expressions,
// which carry scopes of their own. What a body cannot answer, because the
// index is a formal parameter, is then asked of the call sites.
//
// Pass Limits{} for the default bounds.
func Reads(bundle *Bundle, limits Limits) (*ReadSet, error) {
	decisions, err := entrypointRules(bundle)
	if err != nil {
		return nil, err
	}
	if len(decisions) == 0 {
		return nil, ErrNoDecisions
	}

	pending := make([]*ast.Rule, 0, len(decisions))
	within := make(map[*ast.Rule]map[string]map[int]bool)
	for _, decision := range decisions {
		pending = append(pending, decision.rule)
		if decision.within != nil {
			if within[decision.rule] == nil {
				within[decision.rule] = make(map[string]map[int]bool)
			}
			within[decision.rule][decision.name] = decision.within
		}
	}
	reader := &refReader{
		compiler:   bundle.Compiler,
		visited:    make(map[*ast.Rule]bool),
		pending:    pending,
		inputPaths: make(map[*ast.Rule][]string),
		within:     within,
		underWith:  make(map[string]bool),
		callSites:  make(map[*ast.Rule][]callSite),
		edges:      make(map[*ast.Rule][]callEdge),
		summaries:  make(map[string][]paramComparison),
	}
	// Two passes, and the order matters: the call sites of a rule are only
	// trustworthy once the walk knows which rules are part of the decisions at
	// all. A call from a rule nothing reaches must not lend its provenance.
	reader.walk()
	reach := reader.decisionReach(decisions)
	result := reader.resolve(limits, reach)

	taints, warnings := reader.taints(reach, limits)
	result.Taints = taints
	result.Closures = reader.closures(result.Reads, reach)
	result.Quantifiers = reader.quantifiers(reach)
	result.Warnings = sortedUnique(append(result.Warnings, warnings...))

	for _, decision := range decisions {
		result.Decisions = append(result.Decisions, decision.name)
	}
	result.Decisions = sortedUnique(result.Decisions)
	result.SkippedUnderWith = reader.skipped()
	return result, nil
}

// closures names the relation each transitive construct follows, now that the
// reads of every rule are known.
//
// The relation is rarely written into the call. A policy builds an adjacency
// list in a rule of its own and passes that rule, which is the idiomatic way,
// so the paths to report are the ones that rule reads. When the call is handed
// a document under data directly, that document is the relation.
func (r *refReader) closures(reads []Read, reach map[*ast.Rule]decisionPaths) []Closure {
	closures := make([]Closure, 0, len(r.foundClosures))
	for _, found := range r.foundClosures {
		closure := Closure{
			Builtin:   found.builtin,
			Rule:      rulePath(found.rule).String(),
			Decisions: r.decisionsAt(found.rule, found.top, reach),
		}
		if len(closure.Decisions) == 0 {
			continue
		}
		if len(found.args) > 0 {
			closure.Relation = r.relationOf(found.args[0], found.bindings, reads)
		}
		// The seed is reported only where the policy writes it out. In the
		// idiomatic form it is a formal parameter of the function holding the
		// call, and the compiler has renamed it: printing a generated name
		// would say less than saying nothing.
		if len(found.args) > 1 && found.args[1].IsGround() {
			closure.Seed = found.args[1].String()
		}

		loc := found.location
		if loc == nil {
			loc = found.rule.Loc()
		}
		if loc != nil {
			closure.File, closure.Line = loc.File, loc.Row
		}
		closures = append(closures, closure)
	}
	return closures
}

// quantifiers names the every expressions the decisions reach, now that the
// walk knows which decisions reach each rule and how.
func (r *refReader) quantifiers(reach map[*ast.Rule]decisionPaths) []Quantifier {
	quantifiers := make([]Quantifier, 0, len(r.foundEverys))
	for _, found := range r.foundEverys {
		quantifier := Quantifier{
			Rule:      rulePath(found.rule).String(),
			Guarded:   found.guarded,
			Decisions: r.decisionsAt(found.rule, found.top, reach),
		}
		if len(quantifier.Decisions) == 0 {
			continue
		}

		if resolved, ok := resolveDomain(found.domain, found.bindings); ok {
			if isInputRooted(resolved) || isDataRooted(resolved) {
				quantifier.Domain = normalize(resolved)
				quantifier.Provenance = rootOfRef(resolved)
			}
		}

		loc := found.location
		if loc == nil {
			loc = found.rule.Loc()
		}
		if loc != nil {
			quantifier.File, quantifier.Line = loc.File, loc.Row
		}
		quantifiers = append(quantifiers, quantifier)
	}
	return quantifiers
}

// relationOf names the data a relation is built from.
func (r *refReader) relationOf(arg *ast.Term, bindings map[ast.Var]binding, reads []Read) []string {
	ref, isRef := arg.Value.(ast.Ref)
	if !isRef {
		v, isVar := varOf(arg)
		if !isVar {
			return nil
		}
		if resolved := resolveVar(v, bindings); resolved.status == resolvedTerm {
			return r.relationOf(resolved.term, bindings, reads)
		}
		return nil
	}

	// A rule of the policy: the relation is whatever that rule reads.
	if rules := r.compiler.GetRulesForVirtualDocument(ref); len(rules) > 0 {
		return pathsReadBy(reads, rulePath(rules[0]).String())
	}
	if resolved := substituteRef(ref, bindings); isDataRooted(resolved.ref) {
		return []string{normalize(resolved.ref)}
	}
	return nil
}

// pathsReadBy returns the distinct paths one rule reads, sorted.
func pathsReadBy(reads []Read, rule string) []string {
	var paths []string
	for _, read := range reads {
		if read.Rule == rule {
			paths = append(paths, read.Path)
		}
	}
	return sortedUnique(paths)
}

// sortedUnique sorts a list of strings and drops the repeats.
func sortedUnique(values []string) []string {
	slices.Sort(values)
	return slices.Compact(values)
}

// decisionRoot is one decision the walk starts from: the name it is asked at,
// and one of the rules that build it.
type decisionRoot struct {
	name string
	rule *ast.Rule

	// within are the expressions of the rule the decision depends on when it
	// is a field of what the rule returns, and nil when it is the whole of it.
	within map[int]bool
}

// entrypointRules returns the decisions of a bundle: the rules the policy
// annotates as entrypoints, and the ones the caller declared.
//
// The two sources are merged rather than one overriding the other, which is
// what OPA itself does with an entrypoint given on the command line next to an
// annotated one (v1/compile/compile.go:383 at v1.19.0 dedups the two lists
// instead of preferring either).
//
// A declared entrypoint may also reach into the value a rule returns. A rule
// that answers {"allowed": ..., "violations": [...]} is always defined, so
// asked as a whole it holds whatever it says, and the enforcement point does
// not ask it that way: AWX reads allowed out of the object
// (awx/main/tasks/policy.py:263 and :443 at bbda905), and the Envoy plugin
// does the same when a decision is an object (envoyauth/response.go:124 at
// v1.20.2-envoy). OPA takes such a path as an entrypoint, since opa build
// checks it with GetRules (v1/compile/compile.go:705 at v1.20.2), and
// evaluates it by carrying the rest of the reference into the value
// (v1/topdown/eval.go:4038). Here the decision keeps the declared name, so
// that residuals and dependence are asked of the field, and the walk starts
// from the rule less the expressions that only build another field, where
// leaving them out cannot change whether the rule holds (see fieldExprs).
func entrypointRules(bundle *Bundle) ([]decisionRoot, error) {
	compiler := bundle.Compiler

	type key struct {
		name string
		rule *ast.Rule
	}
	var roots []decisionRoot
	seen := make(map[key]bool)
	// declared is the reference of a decision that reaches into the value its
	// rules return, and nil for one that is the rules themselves.
	keep := func(found []*ast.Rule, declared ast.Ref) {
		for _, rule := range found {
			root := decisionRoot{name: rulePath(rule).String(), rule: rule}
			if declared != nil {
				root.name = declared.String()
				root.within = fieldExprs(rule, declared[len(rulePath(rule)):])
			}
			if !seen[key{root.name, rule}] {
				seen[key{root.name, rule}] = true
				roots = append(roots, root)
			}
		}
	}

	for _, ref := range compiler.GetAnnotationSet().Flatten() {
		if ref.Annotations == nil || !ref.Annotations.Entrypoint {
			continue
		}
		keep(compiler.GetRulesExact(ref.Path), nil)
	}

	for _, declared := range bundle.Entrypoints {
		ref, err := entrypointRef(declared)
		if err != nil {
			return nil, err
		}
		found := compiler.GetRulesExact(ref)
		if len(found) == 0 {
			found = documentRules(compiler, ref)
		}
		if len(found) > 0 {
			keep(found, nil)
			continue
		}

		// Past every rule, into the value one of them returns: the decision is
		// that field, and it keeps the name it was declared with.
		found = compiler.GetRulesForVirtualDocument(ref)
		if len(found) == 0 {
			return nil, fmt.Errorf("%w: %s", ErrNoSuchEntrypoint, declared)
		}
		keep(found, ref)
	}
	return roots, nil
}

// documentRules returns the rules that build the document ref names when no
// rule has that exact path.
//
// A rule whose head is a reference reaches past the name it starts with:
// allow["decision"] builds data.authzen.allow, and opa build takes that
// document as an entrypoint. A package is a document as well, but the rules
// under it are the whole policy rather than one decision, so only the rules of
// a package shorter than ref are kept and a package stays refused.
func documentRules(compiler *ast.Compiler, ref ast.Ref) []*ast.Rule {
	var rules []*ast.Rule
	for _, rule := range compiler.GetRulesWithPrefix(ref) {
		if len(rule.Module.Package.Path) < len(ref) {
			rules = append(rules, rule)
		}
	}
	return rules
}

// entrypointRef turns a declared decision into the reference that names it.
//
// Two spellings are accepted and neither of them is ours: data.authz.allow is
// how this tool prints a decision, and authz/allow is how opa build takes one
// (cmd/build.go:280 at v1.19.0). Somebody who has just read a report and
// somebody who knows the opa CLI should each be able to type what they already
// have in front of them, which is the whole of the choice.
func entrypointRef(declared string) (ast.Ref, error) {
	if strings.Contains(declared, "/") {
		path, ok := storage.ParsePath("/" + strings.Trim(declared, "/"))
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrBadEntrypoint, declared)
		}
		return path.Ref(ast.DefaultRootDocument), nil
	}

	// A bare name is not a reference to OPA's parser, and the two spellings
	// agree on what it means anyway: opa build reads violation as
	// data.violation, so that is what it is read as here.
	text := declared
	if !strings.Contains(text, ".") {
		text = "data." + text
	}
	ref, err := ast.ParseRef(text)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrBadEntrypoint, declared, err)
	}
	rooted, isRulePath := rootAtData(ref)
	if !isRulePath {
		return nil, fmt.Errorf("%w: %s", ErrBadEntrypoint, declared)
	}
	return rooted, nil
}

// rootAtData rewrites a parsed reference the way a rule path is written, and
// reports whether it could be one at all.
//
// A path parsed from text has the package as a variable, data.authz.allow being
// the root document followed by two strings while authz.allow is a variable
// followed by one, and a rule path is strings all the way down. A segment that
// is not a plain name, a wildcard or an index, names a set of documents rather
// than a rule, and is refused instead of being matched against nothing.
func rootAtData(ref ast.Ref) (ast.Ref, bool) {
	if len(ref) == 0 {
		return nil, false
	}

	rooted := make(ast.Ref, 0, len(ref)+1)
	rooted = append(rooted, ast.DefaultRootDocument)

	if !isDataRooted(ref) {
		name, isVar := varOf(ref[0])
		if !isVar {
			return nil, false
		}
		rooted = append(rooted, ast.StringTerm(string(name)))
	}

	for _, term := range ref[1:] {
		segment, isString := term.Value.(ast.String)
		if !isString {
			return nil, false
		}
		rooted = append(rooted, ast.NewTerm(segment))
	}
	return rooted, true
}

// RulesNamed returns the paths of the rules of a bundle whose last segment is
// name, sorted and without repeats.
//
// It answers a question and decides nothing: which rules of this bundle are
// called violation is a fact, that a rule called violation is a decision is a
// convention of whoever deploys OPA. Keeping the two apart is what lets a
// caller turn a documented convention into a declaration, Gatekeeper querying
// violation on every constraint template being the case this exists for,
// without the engine ever guessing at a name.
func (b *Bundle) RulesNamed(name string) []string {
	var paths []string
	for _, module := range b.Compiler.Modules {
		ast.WalkRules(module, func(rule *ast.Rule) bool {
			path := rulePath(rule)
			if last, isString := path[len(path)-1].Value.(ast.String); isString && string(last) == name {
				paths = append(paths, path.String())
			}
			return false
		})
	}
	return sortedUnique(paths)
}

// readable rewrites the generated variable names back to the ones the policy
// author wrote, using the table the compiler kept for exactly this, and says
// whether what comes out is fit to show.
//
// data.users[__local6__].profile.department is the truth, and it is unreadable;
// data.users[user].profile.department is the same truth in the words of whoever
// has to check it. Some variables have no author name because the author never
// wrote them: those references are not presentable, and printing them anyway
// would look like a defect in the tool.
func (r *refReader) readable(ref ast.Ref) (string, bool) {
	rewritten := r.compiler.RewrittenVars

	presentable := true
	out := make(ast.Ref, 0, len(ref))
	for _, term := range ref {
		v, isVar := varOf(term)
		if !isVar {
			out = append(out, term)
			continue
		}
		if original, found := rewritten[v]; found {
			out = append(out, ast.NewTerm(original))
			continue
		}
		if v.IsGenerated() {
			presentable = false
		}
		out = append(out, term)
	}
	return out.String(), presentable
}

// dropPrefixes removes references that are a strict prefix of another one.
//
// Reading data.documents[input.doc] to then read its project field is one
// read, not two: the shorter reference is the way to the longer one. Keeping
// both would count a path the policy never uses on its own, and the write
// model would be asked to cover it.
func dropPrefixes(found []foundRef) []foundRef {
	kept := make([]foundRef, 0, len(found))
	for i, candidate := range found {
		isPrefix := false
		for j, other := range found {
			if i != j && strictPrefix(candidate.resolved.ref, other.resolved.ref) {
				isPrefix = true
				break
			}
		}
		if !isPrefix {
			kept = append(kept, candidate)
		}
	}
	return kept
}

// isDataRooted reports whether a reference reads a document under data.
func isDataRooted(ref ast.Ref) bool {
	return len(ref) > 0 && ref[0].Equal(ast.DefaultRootDocument)
}

// isInputRooted reports whether a reference reads part of the request.
func isInputRooted(ref ast.Ref) bool {
	return len(ref) > 0 && ref[0].Equal(ast.InputRootDocument)
}

func strictPrefix(short, long ast.Ref) bool {
	if len(short) >= len(long) {
		return false
	}
	for i := range short {
		if !short[i].Equal(long[i]) {
			return false
		}
	}
	return true
}

// DocumentPath writes the path to one document of a collection: a normalized
// path with the dynamic segment at one position replaced by a key.
//
// data.users[_].profile.department at position 2 with the key mallory comes
// back as data.users.mallory.profile.department. It is what turns a path a
// pattern reasons about into a document somebody can be asked about, and a key
// that is not a bare name comes back quoted, because the result has to be a
// reference OPA will parse.
func DocumentPath(path string, at int, key string) (string, error) {
	ref, err := ast.ParseRef(path)
	if err != nil {
		return "", fmt.Errorf("opaengine: reading the path %s: %w", path, err)
	}
	if at <= 0 || at >= len(ref) {
		// Position zero is the data root, and past the end there is nothing:
		// either way the caller is holding a position that belongs to another
		// path.
		return "", fmt.Errorf("opaengine: %s has no segment at position %d", path, at)
	}

	document := slices.Clone(ref)
	document[at] = ast.StringTerm(key)
	return document.String(), nil
}

// normalize writes a reference as a path, with every dynamic segment replaced
// by [_].
//
// The placeholder is Rego, not a notation of our own: data.users[_].roles is
// what an OPA user would write to mean any user, and it can be pasted into a
// query as it is.
func normalize(ref ast.Ref) string {
	if len(ref) == 0 {
		return ""
	}

	path := make(ast.Ref, 0, len(ref))
	path = append(path, ref[0])
	for _, term := range ref[1:] {
		switch term.Value.(type) {
		case ast.String, ast.Number:
			path = append(path, term)
		default:
			path = append(path, ast.VarTerm("_"))
		}
	}
	return path.String()
}
