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
// rule of the bundle nor a document that rules with a reference in their head
// build.
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

	// UnderNegation is true when the reference is read inside a negated
	// expression.
	//
	// It is a plain bool in the AST, so this is exact rather than inferred,
	// and the taxonomy needs it: a value read to deny is not a value read to
	// grant. It says nothing about the way down from the decision to this rule,
	// which is a property of the walk and is reported in Decisions.
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
// rule holding the read goes through a negation. It is kept apart from the
// negation of the expression, which Read reports on its own, because the two
// combine differently depending on the question. A value that reaches a
// decision only to deny is not a value that grants, which is one combination; a
// check whose absence lets the request through is another, and there the two
// negations cancel out.
type ReachedDecision struct {
	// Name is the path of the decision rule.
	Name string

	// UnderNegation is true when every path from the decision down to the rule
	// goes through a negation, so what the rule finds can only deny.
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

// ReadSet is everything the decisions of a bundle read.
type ReadSet struct {
	Reads []Read

	// Closures are the places the decisions follow a relation transitively.
	Closures []Closure

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

	reader := &refReader{
		compiler:  bundle.Compiler,
		visited:   make(map[*ast.Rule]bool),
		pending:   decisions,
		underWith: make(map[string]bool),
		callSites: make(map[*ast.Rule][]callSite),
		edges:     make(map[*ast.Rule][]callEdge),
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
	result.Warnings = sortedUnique(append(result.Warnings, warnings...))

	for _, rule := range decisions {
		result.Decisions = append(result.Decisions, rulePath(rule).String())
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
			Decisions: reachedDecisions(reach[found.rule]),
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

// entrypointRules returns the decisions of a bundle: the rules the policy
// annotates as entrypoints, and the ones the caller declared.
//
// The two sources are merged rather than one overriding the other, which is
// what OPA itself does with an entrypoint given on the command line next to an
// annotated one (v1/compile/compile.go:383 at v1.19.0 dedups the two lists
// instead of preferring either).
func entrypointRules(bundle *Bundle) ([]*ast.Rule, error) {
	compiler := bundle.Compiler

	var rules []*ast.Rule
	seen := make(map[*ast.Rule]bool)
	keep := func(found []*ast.Rule) {
		for _, rule := range found {
			if !seen[rule] {
				seen[rule] = true
				rules = append(rules, rule)
			}
		}
	}

	for _, ref := range compiler.GetAnnotationSet().Flatten() {
		if ref.Annotations == nil || !ref.Annotations.Entrypoint {
			continue
		}
		keep(compiler.GetRulesExact(ref.Path))
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
		if len(found) == 0 {
			return nil, fmt.Errorf("%w: %s", ErrNoSuchEntrypoint, declared)
		}
		keep(found)
	}
	return rules, nil
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
