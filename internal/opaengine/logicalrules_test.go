package opaengine

import (
	"slices"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
)

// logicalPolicy holds the forms an and and an or take: an or of two reads, an
// and, two operands that bind the same name each for itself, an operand that
// binds a name a comprehension elsewhere binds too, an or inside an and, an or
// in a rule that collects, in a function, under a with modifier, and inside a
// not, and a function with an else, which is left as it is.
const logicalPolicy = `package t

import future.keywords.and
import future.keywords.not
import future.keywords.or

default either := false

either if {
	data.users[input.user].role == "admin" or data.users[input.user].role == "owner"
}

both if {
	data.users[input.user].role == "admin" and input.action == "write"
}

apart if {
	{ data.p[x] == 1 } and { data.q[x] == 2 }
}

shadowed if {
	{ data.p[y] == 1 } or input.z
	count([y | data.q[y]]) > 0
}

nested if {
	input.a == 1 and { input.b == 1 or input.c == 1 }
}

violations contains "flagged" if {
	input.a == 2 or data.flags.x == true
}

pick(v) if {
	v == 1 or v == 2
}

picked if pick(input.v)

withed if {
	input.x == 1 or input.y == 1 with input as {"y": 1}
}

nor if {
	not { input.a == 1 or input.b == 1 }
}

step(v) := 1 if { v == 1 or v == 3 } else := 2

stepped := step(input.v)
`

// The rewrite is only worth anything if it answers what the policy answers.
// Every rule is evaluated against the policy as written and against the
// rewritten one, for every input and every world, and the two have to agree.
// The worlds put the keys of p and q apart, which is what a rewrite that let
// two operands share a variable would get wrong.
func TestSplitLogicalKeepsTheAnswers(t *testing.T) {
	bundle, err := Load([]string{writeSources(t, map[string]string{"policy.rego": logicalPolicy})}, ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	rewritten, err := bundle.forPartial()
	if err != nil {
		t.Fatalf("forPartial() error = %v", err)
	}
	if rewritten == bundle.Compiler {
		t.Fatal("the policy has and and or in its bodies and nothing was rewritten")
	}

	queries := []string{
		"data.t.either", "data.t.both", "data.t.apart", "data.t.shadowed", "data.t.nested",
		"data.t.violations", "data.t.picked", "data.t.withed", "data.t.nor", "data.t.stepped",
	}
	inputs := []map[string]any{
		{},
		{"user": "alice"},
		{"user": "bob"},
		{"user": "carol"},
		{"user": "alice", "action": "write"},
		{"user": "bob", "action": "write"},
		{"a": 1},
		{"a": 1, "b": 1},
		{"a": 1, "c": 1},
		{"a": 2},
		{"b": 1},
		{"v": 1},
		{"v": 2},
		{"v": 3},
		{"v": 4},
		{"x": 1},
		{"z": true},
	}
	worlds := []string{
		`{"users": {"alice": {"role": "admin"}, "bob": {"role": "owner"}, "carol": {"role": "viewer"}}, "p": {"k1": 1}, "q": {"k2": 2}, "flags": {"x": true}}`,
		`{"users": {"alice": {"role": "viewer"}}, "p": {"k1": 1}, "q": {"k1": 2}, "flags": {"x": false}}`,
		`{"p": {"k1": 3}, "q": {}}`,
	}

	for _, world := range worlds {
		data := writeData(t, world)
		for _, query := range queries {
			for _, input := range inputs {
				written := evaluate(t, bundle.Compiler, data, query, input)
				alike := evaluate(t, rewritten, data, query, input)
				if written != alike {
					t.Errorf("%s with %v in %s:\n  as written: %s\n  rewritten:  %s", query, input, world, written, alike)
				}
			}
		}
	}

	for _, rule := range rewritten.GetRulesExact(ast.MustParseRef("data.t.step")) {
		if rule.Else == nil {
			t.Error("the function lost its else, and a function tries its branches against the value it is asked for")
		}
	}
}

// Taken apart, an or answers partial evaluation the way two bodies do: with the
// requests that make it hold, and without an operand the data already rules
// out. Both policies are asked the same questions, and the conditions have to
// be the same.
func TestSplitLogicalLeavesWhatTwoBodiesLeave(t *testing.T) {
	written := `package t

import future.keywords.and
import future.keywords.or

default either := false

either if {
	data.users[input.user].role == "admin" or data.users[input.user].role == "owner"
}

default mixed := false

mixed if {
	input.action == "read" or data.users[input.user].role == "admin"
}

default both := false

both if {
	data.users[input.user].role == "admin" and input.action == "write"
}
`
	bodies := `package t

default either := false

either if data.users[input.user].role == "admin"

either if data.users[input.user].role == "owner"

default mixed := false

mixed if input.action == "read"

mixed if data.users[input.user].role == "admin"

default both := false

both if {
	data.users[input.user].role == "admin"
	input.action == "write"
}
`
	data := writeData(t, `{"users": {"alice": {"role": "admin"}, "bob": {"role": "owner"}, "carol": {"role": "viewer"}}}`)
	questions := []Request{
		{Decision: "data.t.either"},
		{Decision: "data.t.mixed"},
		{Decision: "data.t.mixed", Unknowns: []string{"input.action"}, Input: map[string]any{"user": "carol"}},
		{Decision: "data.t.both"},
	}

	conditions := func(policy string, ask Request) []string {
		t.Helper()
		bundle, err := Load([]string{writeSources(t, map[string]string{"policy.rego": policy})}, ParseModeAuto)
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		residuals, err := Residuals(t.Context(), bundle, data, ask, Limits{})
		if err != nil {
			t.Fatalf("Residuals() error = %v", err)
		}
		var found []string
		for _, condition := range residuals.Conditions {
			found = append(found, condition.Query)
		}
		slices.Sort(found)
		return found
	}

	for _, ask := range questions {
		fromOr, fromBodies := conditions(written, ask), conditions(bodies, ask)
		if !slices.Equal(fromOr, fromBodies) {
			t.Errorf("%s with %v known:\n  written with and and or: %q\n  written as bodies:       %q",
				ask.Decision, ask.Input, fromOr, fromBodies)
		}
		for _, condition := range fromOr {
			if strings.Contains(condition, "data.") {
				t.Errorf("%s: the condition %q still reads the data, which partial evaluation had in hand", ask.Decision, condition)
			}
		}
	}
}

// Each or of a body doubles the rules it becomes. Past the bound the rule is
// left as it is written, and it still answers what it answered.
func TestSplitLogicalStopsAtTheBound(t *testing.T) {
	var body strings.Builder
	for _, field := range []string{"a", "b", "c", "d", "e", "f", "g"} {
		body.WriteString("\tinput." + field + " == 1 or input." + field + " == 2\n")
	}
	policy := "package t\n\nimport future.keywords.or\n\nmany if {\n" + body.String() + "}\n\nfew if {\n\tinput.a == 1 or input.b == 1\n}\n"

	bundle, err := Load([]string{writeSources(t, map[string]string{"policy.rego": policy})}, ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	rewritten, err := bundle.forPartial()
	if err != nil {
		t.Fatalf("forPartial() error = %v", err)
	}

	if many := rewritten.GetRulesExact(ast.MustParseRef("data.t.many")); len(many) != 1 || logicalAt(many[0].Body) < 0 {
		t.Errorf("many became %d rules, want it left as written", len(many))
	}
	if few := rewritten.GetRulesExact(ast.MustParseRef("data.t.few")); len(few) != 2 {
		t.Errorf("few became %d rules, want one per operand", len(few))
	}

	data := writeData(t, `{"settings": {}}`)
	for _, input := range []map[string]any{{}, {"a": 1, "b": 2, "c": 1, "d": 1, "e": 2, "f": 1, "g": 1}} {
		written := evaluate(t, bundle.Compiler, data, "data.t.many", input)
		alike := evaluate(t, rewritten, data, "data.t.many", input)
		if written != alike {
			t.Errorf("many with %v: as written %s, rewritten %s", input, written, alike)
		}
	}
}
