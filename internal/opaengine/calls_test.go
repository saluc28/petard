package opaengine

import (
	"slices"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
)

// TestReadsResolveThroughCallSites is the reason calls.go exists.
//
// is_member(user, proj) reads the profile of "user", and nothing in its body
// says who that is: the answer is in allow, which calls it with input.user.
// The fixture is written this way on purpose, because using a function is the
// normal way to write that policy, and it is the chain EXPECTED.md calls the
// central criterion.
func TestReadsResolveThroughCallSites(t *testing.T) {
	bundle, err := Load([]string{fixtureDir(t, "policy-v1")}, ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	reads, err := Reads(bundle, Limits{})
	if err != nil {
		t.Fatalf("Reads() error = %v", err)
	}

	var found bool
	for _, read := range reads.Reads {
		if read.Rule != "data.quill.authz.is_member" || read.Path != "data.users[_].profile.department" {
			continue
		}
		found = true

		if read.Provenance != ProvenanceInput {
			t.Errorf("provenance = %s, want input: the caller passes input.user", read.Provenance)
		}
		if read.Trace == nil {
			t.Fatal("no trace: the claim about input has to say where it comes from")
		}
		if !slices.Equal(read.Trace.Callers, []string{"data.quill.authz.allow"}) {
			t.Errorf("callers = %v, want [data.quill.authz.allow]", read.Trace.Callers)
		}
		if read.Trace.Term != "input.user" {
			t.Errorf("term = %q, want input.user: naming the field is what a pattern needs", read.Trace.Term)
		}
	}
	if !found {
		t.Fatal("the read inside is_member is missing")
	}
}

// A parameter passed on from one function to the next is the case a single hop
// would get wrong, and it is what makes this a walk rather than a lookup.
func TestParameterProvenanceWalksUpTheChain(t *testing.T) {
	reads := readsOf(t, `package t

# METADATA
# scope: document
# entrypoint: true
default allow := false

allow if outer(input.user)

outer(u) if inner(u)

inner(u) if data.users[u].active
`, Limits{})

	read := readOfRule(t, reads, "data.t.inner")
	if read.Provenance != ProvenanceInput {
		t.Errorf("provenance = %s, want input", read.Provenance)
	}
	if read.Trace == nil {
		t.Fatal("no trace")
	}
	if !slices.Equal(read.Trace.Callers, []string{"data.t.outer", "data.t.allow"}) {
		t.Errorf("callers = %v, want [data.t.outer data.t.allow]", read.Trace.Callers)
	}
	if read.Trace.Term != "input.user" {
		t.Errorf("term = %q, want input.user", read.Trace.Term)
	}
}

// A caller that passes a constant is not a caller that passes the request:
// the read names the same document every time, and saying "input" there would
// invent a way in.
func TestParameterProvenanceOfAConstantArgument(t *testing.T) {
	reads := readsOf(t, `package t

# METADATA
# scope: document
# entrypoint: true
default allow := false

allow if member("root")

member(p) if data.projects[p].members
`, Limits{})

	if read := readOfRule(t, reads, "data.t.member"); read.Provenance != ProvenanceStatic {
		t.Errorf("provenance = %s, want static", read.Provenance)
	}
}

// Reaching a limit is not an answer, and it must not look like one. The read
// stays unresolved and the run says which bound stopped it and how to raise
// it.
func TestLimitsStopTheWalkWithAWarning(t *testing.T) {
	const policy = `package t

# METADATA
# scope: document
# entrypoint: true
default allow := false

allow if outer(input.user)

outer(u) if inner(u)

inner(u) if data.users[u].active
`

	reads := readsOf(t, policy, Limits{MaxCallDepth: 1})

	if read := readOfRule(t, reads, "data.t.inner"); read.Provenance != ProvenanceUnresolved {
		t.Errorf("provenance = %s, want unresolved: one call is not enough to reach input", read.Provenance)
	}
	if len(reads.Warnings) == 0 {
		t.Fatal("no warning: a bound that stops the analysis has to say so")
	}
	warning := reads.Warnings[0]
	for _, expected := range []string{"MaxCallDepth", "data.t.outer"} {
		if !strings.Contains(warning, expected) {
			t.Errorf("warning %q does not mention %s", warning, expected)
		}
	}
}

func TestLimitsFallBackToDefaults(t *testing.T) {
	var zero Limits
	if got := zero.maxCallDepth(); got != defaultMaxCallDepth {
		t.Errorf("maxCallDepth() = %d, want %d", got, defaultMaxCallDepth)
	}
	if got := zero.maxCallPaths(); got != defaultMaxCallPaths {
		t.Errorf("maxCallPaths() = %d, want %d", got, defaultMaxCallPaths)
	}

	set := Limits{MaxCallDepth: 2, MaxCallPaths: 3}
	if got := set.maxCallDepth(); got != 2 {
		t.Errorf("maxCallDepth() = %d, want 2", got)
	}
	if got := set.maxCallPaths(); got != 3 {
		t.Errorf("maxCallPaths() = %d, want 3", got)
	}
}

// readsOf compiles one policy and returns what its decisions read.
func readsOf(t *testing.T, policy string, limits Limits) *ReadSet {
	t.Helper()

	bundle, err := Load([]string{writeSources(t, map[string]string{"policy.rego": policy})}, ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	reads, err := Reads(bundle, limits)
	if err != nil {
		t.Fatalf("Reads() error = %v", err)
	}
	return reads
}

// readOfRule returns the single read of a rule, failing if there is not
// exactly one.
func readOfRule(t *testing.T, reads *ReadSet, rule string) Read {
	t.Helper()
	return oneRead(t, reads, "rule "+rule, func(read Read) bool { return read.Rule == rule })
}

// readOfPath returns the single read of a path, failing if there is not
// exactly one.
func readOfPath(t *testing.T, reads *ReadSet, path string) Read {
	t.Helper()
	return oneRead(t, reads, "path "+path, func(read Read) bool { return read.Path == path })
}

func oneRead(t *testing.T, reads *ReadSet, what string, matches func(Read) bool) Read {
	t.Helper()

	var found []Read
	for _, read := range reads.Reads {
		if matches(read) {
			found = append(found, read)
		}
	}
	if len(found) != 1 {
		t.Fatalf("reads of %s = %d, want 1 (all reads: %v)", what, len(found), reads.Paths())
	}
	return found[0]
}

// A head can take an argument apart, and the value then sits inside what the
// caller writes out: owns([user, doc]) called with [input.user, input.doc]
// picks the document the request names, and so does the same with an object.
func TestParameterProvenanceGoesIntoAnArgumentTheHeadTakesApart(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "an array",
			body: `allow if owns([input.user, input.doc])

owns([user, doc]) if data.documents[doc].owner == user
`,
		},
		{
			name: "an object",
			body: `allow if owns({"who": input.user, "what": input.doc})

owns({"who": user, "what": doc}) if data.documents[doc].owner == user
`,
		},
		{
			name: "an array held in a variable first",
			body: `allow if {
	pair := [input.user, input.doc]
	owns(pair)
}

owns([user, doc]) if data.documents[doc].owner == user
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reads := readsOf(t, "package t\n\n# METADATA\n# entrypoint: true\n"+tt.body, Limits{})

			read := readOfRule(t, reads, "data.t.owns")
			if read.Provenance != ProvenanceInput {
				t.Errorf("provenance = %s, want input: the caller passes input.doc", read.Provenance)
			}
			if read.Trace == nil || read.Trace.Term != "input.doc" {
				t.Errorf("trace = %+v, want the term input.doc", read.Trace)
			}
		})
	}
}

// What a call passes for a parameter the head takes apart is found only where
// the call writes the array or the object out, or binds a variable to one
// first. Everything else is not followed, a value the policy computes included,
// and neither is a key the argument does not hold.
func TestParameterPlacePicksWhatTheCallWritesOut(t *testing.T) {
	bindings := map[ast.Var]binding{
		"pair":     {kind: bindingAlias, term: ast.MustParseTerm(`["alice", "doc"]`)},
		"computed": {kind: bindingRuleOutput, origin: ast.MustParseRef("data.t.pair")},
	}
	keys := func(path ...any) []*ast.Term {
		terms := make([]*ast.Term, 0, len(path))
		for _, key := range path {
			terms = append(terms, ast.NewTerm(ast.MustInterfaceToValue(key)))
		}
		return terms
	}

	tests := []struct {
		name  string
		place parameterPlace
		args  string

		// expected is the term picked, and empty when nothing is.
		expected string
	}{
		{"the argument itself", parameterPlace{position: 1}, `["x", "y"]`, `"y"`},
		{"an element of an array", parameterPlace{within: keys(1)}, `[["x", "y"]]`, `"y"`},
		{"a key of an object", parameterPlace{within: keys("who")}, `[{"who": "x"}]`, `"x"`},
		{"an array inside an object", parameterPlace{within: keys("who", 0)}, `[{"who": ["x"]}]`, `"x"`},
		{"an array held in a variable", parameterPlace{within: keys(1)}, `[pair]`, `"doc"`},
		{"an argument the call does not pass", parameterPlace{position: 1}, `["x"]`, ""},
		{"an index past the end", parameterPlace{within: keys(2)}, `[["x", "y"]]`, ""},
		{"a negative index", parameterPlace{within: keys(-1)}, `[["x", "y"]]`, ""},
		{"an index that is not whole", parameterPlace{within: keys(0.5)}, `[["x", "y"]]`, ""},
		{"a key where an array was", parameterPlace{within: keys("who")}, `[["x", "y"]]`, ""},
		{"a key the object does not hold", parameterPlace{within: keys("what")}, `[{"who": "x"}]`, ""},
		{"a string where an array was", parameterPlace{within: keys(0)}, `["xy"]`, ""},
		{"a value the policy computes", parameterPlace{within: keys(0)}, `[computed]`, ""},
		{"a variable nothing binds", parameterPlace{within: keys(0)}, `[free]`, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := ast.MustParseTerm(tt.args).Value.(*ast.Array)
			var passed []*ast.Term
			for i := range args.Len() {
				passed = append(passed, args.Elem(i))
			}

			got := ""
			if term, picked := tt.place.pick(passed, bindings); picked {
				got = term.String()
			}
			if got != tt.expected {
				t.Errorf("pick() = %q, want %q", got, tt.expected)
			}
		})
	}
}
