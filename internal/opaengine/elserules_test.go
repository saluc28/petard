package opaengine

import (
	"fmt"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
)

// elsePolicy holds the forms an else takes: a chain of three, a default next to
// one, a head that is a reference, a branch that binds a variable, two
// definitions of one rule that can disagree, and a function, which is left as
// it is.
const elsePolicy = `package t

tier := "gold" if input.points > 100 else := "silver" if input.points > 10 else := "bronze"

default open := false

open := true if data.settings.open else := false if input.closed

limits.max := 10 if input.premium else := 5

grade := g if {
	g := input.score
	g > 50
} else := 0

conflict := 1 if input.a else := 2

conflict := 1 if input.b else := 2

step(x) := 1 if x > 0 else := 2

stepped := step(input.points)
`

// The rewrite is only worth anything if it answers what the policy answers.
// Every rule is evaluated against the policy as written and against the
// rewritten one, for every input and both worlds, and the two have to agree,
// a conflict between definitions included.
func TestExclusiveElseKeepsTheAnswers(t *testing.T) {
	bundle, err := Load([]string{writeSources(t, map[string]string{"policy.rego": elsePolicy})}, ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if bundle.partialCompiler == nil {
		t.Fatal("the policy has rules with an else and nothing was rewritten")
	}

	queries := []string{"data.t.tier", "data.t.open", "data.t.limits", "data.t.grade", "data.t.conflict", "data.t.stepped"}
	inputs := []map[string]any{
		{},
		{"points": 5},
		{"points": 50},
		{"points": 500, "premium": true},
		{"closed": true},
		{"score": 70},
		{"score": 20},
		{"a": true},
		{"b": true},
		{"a": true, "b": true},
		{"a": true, "b": false},
	}
	worlds := []string{`{"settings": {"open": true}}`, `{"settings": {"open": false}}`}

	for _, world := range worlds {
		data := writeData(t, world)
		for _, query := range queries {
			for _, input := range inputs {
				written := evaluate(t, bundle.Compiler, data, query, input)
				rewritten := evaluate(t, bundle.forPartial(), data, query, input)
				if written != rewritten {
					t.Errorf("%s with %v in %s:\n  as written: %s\n  rewritten:  %s", query, input, world, written, rewritten)
				}
			}
		}
	}

	for _, rule := range bundle.forPartial().GetRulesExact(ast.MustParseRef("data.t.step")) {
		if rule.Else == nil {
			t.Error("the function lost its else, and a function tries its branches against the value it is asked for")
		}
	}
}

// A policy with no else is compiled once.
func TestExclusiveElseLeavesAPolicyWithoutElse(t *testing.T) {
	bundle, err := Load([]string{fixtureDir(t, "policy-v1")}, ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if bundle.partialCompiler != nil {
		t.Error("the fixture has no else and was compiled a second time")
	}
}

// evaluate writes what a query answers, or that it failed, in a form two
// answers can be compared by.
func evaluate(t *testing.T, compiler *ast.Compiler, data *Data, query string, input map[string]any) string {
	t.Helper()
	results, err := rego.New(
		rego.Compiler(compiler),
		rego.Store(data.store),
		rego.Query(query),
		rego.Input(input),
	).Eval(t.Context())
	if err != nil {
		return "error"
	}
	if len(results) == 0 {
		return "undefined"
	}
	return fmt.Sprint(results[0].Expressions[0].Value)
}
