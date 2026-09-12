package opaengine

import (
	"slices"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
)

// compileRules compiles one module and returns its rules in source order. The
// resolver only ever sees compiled bodies, so the tests start where it starts.
func compileRules(t *testing.T, source string) []*ast.Rule {
	t.Helper()

	module, err := ast.ParseModuleWithOpts("test.rego", source, ast.ParserOptions{RegoVersion: ast.RegoV1})
	if err != nil {
		t.Fatalf("parsing the test policy: %v", err)
	}

	compiler := ast.NewCompiler()
	compiler.Compile(map[string]*ast.Module{"test.rego": module})
	if compiler.Failed() {
		t.Fatalf("compiling the test policy: %v", compiler.Errors)
	}
	return compiler.Modules["test.rego"].Rules
}

// resolvedTerms lists what the bound variables of a body stand for, as text.
// Naming the variables in the expectations would mean naming __local7__, which
// is a number the compiler is free to change.
func resolvedTerms(bindings map[ast.Var]binding) []string {
	var terms []string
	for v := range bindings {
		switch resolved := resolveVar(v, bindings); resolved.status {
		case resolvedTerm:
			terms = append(terms, resolved.term.String())
		case resolvedOutput:
			terms = append(terms, "output of "+resolved.source.origin.String())
		}
	}
	slices.Sort(terms)
	return terms
}

func TestCollectBindings(t *testing.T) {
	tests := []struct {
		name     string
		policy   string
		expected []string
	}{
		{
			name:     "an assignment binds the variable to the term",
			policy:   "package t\n\nallow if {\n\tu := input.user\n\tdata.users[u].active\n}\n",
			expected: []string{"input.user"},
		},
		{
			name:     "an index is lifted into a binding of its own",
			policy:   "package t\n\nallow if data.users[input.user].active\n",
			expected: []string{"input.user"},
		},
		{
			name:   "a builtin called for its value binds its output",
			policy: "package t\n\nallow if {\n\tr := http.send({\"method\": \"GET\", \"url\": \"https://example.invalid\"})\n\tr.body.ok\n}\n",
			// The alias r -> the output variable resolves through to the
			// origin, so both variables report the same builtin.
			expected: []string{"output of http.send", "output of http.send"},
		},
		{
			name:     "a negated expression binds nothing",
			policy:   "package t\n\nallow if {\n\tnot input.user == \"root\"\n\tinput.action == \"read\"\n}\n",
			expected: nil,
		},
		{
			name:     "an every body keeps its variables to itself",
			policy:   "package t\n\nallow if every d in data.documents {\n\td.owner == input.user\n}\n",
			expected: []string{"data.documents"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules := compileRules(t, tt.policy)
			got := resolvedTerms(collectBindings(rules[0].Body))

			if !slices.Equal(got, tt.expected) {
				t.Errorf("resolved terms = %v, want %v", got, tt.expected)
			}
		})
	}
}

// The compiler rewrites := into eq, so a compiled body never carries assign.
// A body that has not been compiled still does, and the resolver reads bodies
// wherever they come from, so both operators are accepted. This test is here
// to keep that branch honest: if the parser ever stops emitting assign, it
// fails instead of leaving dead code behind.
func TestCollectBindingsAcceptsUncompiledAssignment(t *testing.T) {
	body := ast.MustParseBody("x := input.user")
	if !body[0].IsAssignment() {
		t.Fatalf("expression is %v, no longer an assignment: the branch handling it can go", body[0])
	}

	if got := resolvedTerms(collectBindings(body)); !slices.Equal(got, []string{"input.user"}) {
		t.Errorf("resolved terms = %v, want [input.user]", got)
	}
}

func TestResolveVar(t *testing.T) {
	bindings := map[ast.Var]binding{
		"direct":   {kind: bindingAlias, term: ast.MustParseTerm("input.user")},
		"hop":      {kind: bindingAlias, term: ast.VarTerm("direct")},
		"far":      {kind: bindingAlias, term: ast.VarTerm("hop")},
		"fetched":  {kind: bindingOutput, origin: ast.MustParseRef("http.send")},
		"aliasing": {kind: bindingAlias, term: ast.VarTerm("fetched")},
		"loop":     {kind: bindingAlias, term: ast.VarTerm("knot")},
		"knot":     {kind: bindingAlias, term: ast.VarTerm("loop")},
	}

	tests := []struct {
		name           string
		variable       ast.Var
		expectedStatus resolutionStatus
		expected       string
	}{
		{name: "direct alias", variable: "direct", expectedStatus: resolvedTerm, expected: "input.user"},
		{name: "one hop", variable: "hop", expectedStatus: resolvedTerm, expected: "input.user"},
		{name: "two hops", variable: "far", expectedStatus: resolvedTerm, expected: "input.user"},
		{name: "builtin output", variable: "fetched", expectedStatus: resolvedOutput, expected: "http.send"},
		{name: "alias of an output", variable: "aliasing", expectedStatus: resolvedOutput, expected: "http.send"},
		{name: "nothing binds it", variable: "loose", expectedStatus: unresolvedUnbound},
		{name: "aliases in a loop", variable: "loop", expectedStatus: unresolvedCycle},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolved := resolveVar(tt.variable, bindings)

			if resolved.status != tt.expectedStatus {
				t.Fatalf("status = %d, want %d", resolved.status, tt.expectedStatus)
			}
			switch resolved.status {
			case resolvedTerm:
				if got := resolved.term.String(); got != tt.expected {
					t.Errorf("term = %q, want %q", got, tt.expected)
				}
			case resolvedOutput:
				if got := resolved.source.origin.String(); got != tt.expected {
					t.Errorf("origin = %q, want %q", got, tt.expected)
				}
			}
		})
	}
}

func TestSubstituteRef(t *testing.T) {
	bindings := map[ast.Var]binding{
		"subject":  {kind: bindingAlias, term: ast.MustParseTerm("input.user")},
		"document": {kind: bindingAlias, term: ast.MustParseTerm("data.documents[chosen]")},
		"chosen":   {kind: bindingAlias, term: ast.MustParseTerm("input.doc")},
		"fetched":  {kind: bindingOutput, origin: ast.MustParseRef("http.send")},
	}

	tests := []struct {
		name               string
		ref                string
		expected           string
		expectedOrigin     string
		expectedUnresolved []string
	}{
		{
			name:     "an index comes back",
			ref:      "data.users[subject].profile.department",
			expected: "data.users[input.user].profile.department",
		},
		{
			name: "an alias in head position brings its own indexes",
			// This is the fixture's shape: doc := data.documents[input.doc]
			// in one expression, doc.project in another.
			ref:      "document.project",
			expected: "data.documents[input.doc].project",
		},
		{
			name:           "rooted in what a builtin answered",
			ref:            "fetched.body.clearance",
			expected:       "fetched.body.clearance",
			expectedOrigin: "http.send",
		},
		{
			name:               "an index this body does not bind",
			ref:                "data.users[formal].roles",
			expected:           "data.users[formal].roles",
			expectedUnresolved: []string{"formal"},
		},
		{
			name:     "the roots are left alone",
			ref:      "input.action",
			expected: "input.action",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := substituteRef(ast.MustParseRef(tt.ref), bindings)

			if got.ref.String() != tt.expected {
				t.Errorf("ref = %q, want %q", got.ref, tt.expected)
			}
			origin := ""
			if got.root != nil {
				origin = got.root.origin.String()
			}
			if origin != tt.expectedOrigin {
				t.Errorf("origin = %q, want %q", origin, tt.expectedOrigin)
			}
			unresolved := make([]string, 0, len(got.unresolved))
			for _, v := range got.unresolved {
				unresolved = append(unresolved, string(v))
			}
			if !slices.Equal(unresolved, tt.expectedUnresolved) {
				t.Errorf("unresolved = %v, want %v", unresolved, tt.expectedUnresolved)
			}
		})
	}
}

// A loop between aliases must not be answered with a rewritten reference: the
// variable stays, and it is reported as unresolved rather than as a fact.
func TestSubstituteRefStopsOnCycles(t *testing.T) {
	bindings := map[ast.Var]binding{
		"loop": {kind: bindingAlias, term: ast.VarTerm("knot")},
		"knot": {kind: bindingAlias, term: ast.VarTerm("loop")},
	}

	got := substituteRef(ast.MustParseRef("data.users[loop].roles"), bindings)

	if got.ref.String() != "data.users[loop].roles" {
		t.Errorf("ref = %q, want it unchanged", got.ref)
	}
	if len(got.unresolved) != 1 || got.unresolved[0] != "loop" {
		t.Errorf("unresolved = %v, want [loop]", got.unresolved)
	}
}

// The fixture is the ground truth, and this is the path EXPECTED.md calls out
// as the one that verifies binding resolution: data.documents.{d}.project is
// read through an alias, and no single expression holds it whole.
func TestSubstituteRefRecoversFixtureAliasPath(t *testing.T) {
	bundle, err := Load([]string{fixtureDir(t, "policy-v1")}, ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	const expected = "data.documents[input.doc].project"
	for _, module := range bundle.Compiler.Modules {
		for _, rule := range module.Rules {
			bindings := collectBindings(rule.Body)

			found := false
			ast.WalkRefs(rule.Body, func(ref ast.Ref) bool {
				if substituteRef(ref, bindings).ref.String() == expected {
					found = true
				}
				return found
			})
			if found {
				return
			}
		}
	}
	t.Errorf("no rule yields %s: the alias was not followed", expected)
}

// Reading a reference under a formal parameter is what tells the two measures
// apart: the reference is found, its provenance is not, and saying so is the
// point. Anything else would report full coverage while an entire capability
// is missing.
func TestSubstituteRefLeavesFormalParametersUnresolved(t *testing.T) {
	rules := compileRules(t, "package t\n\nis_member(user, proj) if data.users[user].profile.department == data.projects[proj].department\n")
	rule := rules[0]
	bindings := collectBindings(rule.Body)

	var unresolved int
	ast.WalkRefs(rule.Body, func(ref ast.Ref) bool {
		result := substituteRef(ref, bindings)
		if strings.HasPrefix(result.ref.String(), "data.users") || strings.HasPrefix(result.ref.String(), "data.projects") {
			unresolved += len(result.unresolved)
		}
		return false
	})

	if unresolved != 2 {
		t.Errorf("unresolved variables = %d, want 2: both indexes are formal parameters", unresolved)
	}
}
