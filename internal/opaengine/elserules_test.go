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
	rewritten, err := bundle.forPartial()
	if err != nil {
		t.Fatalf("forPartial() error = %v", err)
	}
	if rewritten == bundle.Compiler {
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

// A policy with no else and no answer written out as an object is compiled
// once, and a policy nothing partially evaluates is compiled once whatever it
// holds.
func TestPartialEvaluationCompilesAgainOnlyWhenItHasTo(t *testing.T) {
	bundle, err := Load([]string{fixtureDir(t, "policy-v1")}, ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if compiler, err := bundle.forPartial(); err != nil || compiler != bundle.Compiler {
		t.Errorf("forPartial() built a second compiler (error %v), and the fixture has nothing to rewrite", err)
	}

	bundle, err = Load([]string{writeSources(t, map[string]string{"policy.rego": elsePolicy})}, ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if bundle.partialCompiler != nil {
		t.Error("the policy was compiled a second time before anything asked for it")
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

// fieldsPolicy answers with objects: one with a default, a list of violations
// and a field that can fail, and one with no body at all.
const fieldsPolicy = `package t

default decision := {"allowed": false, "violations": []}

decision := {
	"allowed": count(violations) == 0,
	"violations": [v | some v in violations],
	"contact": data.settings.contact,
} if input.active

violations contains "blocked" if data.blocklist[input.user]

report := {"user": input.user, "ok": true}
`

// A field asked at the rule written for it answers what the field of the object
// answers, a field that fails the whole object included. A field that not every
// definition has is asked at the object, as it is.
func TestFieldRulesKeepTheAnswers(t *testing.T) {
	bundle, err := Load([]string{writeSources(t, map[string]string{"policy.rego": fieldsPolicy})}, ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	rewritten, err := bundle.forPartial()
	if err != nil {
		t.Fatalf("forPartial() error = %v", err)
	}

	fields := []string{"data.t.decision.allowed", "data.t.decision.violations", "data.t.report.user", "data.t.report.ok"}
	for _, field := range fields {
		if _, written := bundle.fieldQueries[field]; !written {
			t.Errorf("%s has no rule of its own", field)
		}
	}
	if _, written := bundle.fieldQueries["data.t.decision.contact"]; written {
		t.Error("contact has a rule of its own, and the default answers without it")
	}

	inputs := []map[string]any{{}, {"active": true, "user": "a"}, {"active": true, "user": "b"}}
	worlds := []string{
		`{"settings": {"contact": "help@example.org"}, "blocklist": {"a": true}}`,
		`{"blocklist": {"a": true}}`,
	}
	for _, world := range worlds {
		data := writeData(t, world)
		for _, field := range fields {
			for _, input := range inputs {
				asked := evaluate(t, bundle.Compiler, data, field, input)
				alone := evaluate(t, rewritten, data, bundle.query(field), input)
				if asked != alone {
					t.Errorf("%s with %v in %s:\n  the field:     %s\n  its own rule:  %s", field, input, world, asked, alone)
				}
			}
		}
	}
}
