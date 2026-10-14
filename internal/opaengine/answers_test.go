package opaengine

import (
	"errors"
	"slices"
	"testing"
)

// verdictPolicy answers every request with one of four words, the way an
// admission gate does: two of them let the artifact through, one refuses it and
// one, the default, sends it to be scanned.
const verdictPolicy = `package gate

default verdict := "scan"

verdict := "blocked" if not input.trusted

verdict := "allowed" if {
	input.trusted
	input.listed
}

verdict := "clean" if {
	input.trusted
	not input.listed
	input.scan == "ok"
}
`

// resultPolicy answers with an object two functions build, the allow and the
// deny of a decision contract, over a default that denies.
const resultPolicy = `package sts

default result := {"decision": "deny", "why": []}

allow_result(policy) := {"decision": "allow", "why": [policy]}

deny_result(reason) := {"decision": "deny", "why": [reason]}

result := allow_result("owner") if input.owner == "alice"

result := deny_result(reason) if {
	not input.owner
	reason := input.reason
}
`

func bundleDeclaring(t *testing.T, policy string, grants, denies []string) *Bundle {
	t.Helper()

	bundle, err := Load([]string{writeSources(t, map[string]string{"policy.rego": policy})}, ParseModeV1)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	bundle.Entrypoints, bundle.DenyEntrypoints = grants, denies
	return bundle
}

// An entrypoint can end in the answer the decision is on its side for. A bare
// word is the string, and a value written out is that value.
func TestAnsweredEntrypoint(t *testing.T) {
	tests := []struct {
		declared string
		path     string
		answer   string
		err      error
	}{
		{declared: "data.gate.verdict", path: "data.gate.verdict"},
		{declared: "data.gate.verdict=allowed", path: "data.gate.verdict", answer: `"allowed"`},
		{declared: "gate/verdict=allowed", path: "gate/verdict", answer: `"allowed"`},
		{declared: `data.gate.verdict="allowed"`, path: "data.gate.verdict", answer: `"allowed"`},
		{declared: "data.gate.level=2", path: "data.gate.level", answer: "2"},
		{declared: `data.gate.level="2"`, path: "data.gate.level", answer: `"2"`},
		{declared: "data.gate.open=true", path: "data.gate.open", answer: "true"},
		{declared: "data.gate.verdict=allowed with a warning", path: "data.gate.verdict", answer: `"allowed with a warning"`},
		{declared: "data.gate.verdict=input.verdict", path: "data.gate.verdict", answer: `"input.verdict"`},
		{declared: "data.gate.verdict=", err: ErrBadEntrypoint},
		{declared: "=allowed", err: ErrBadEntrypoint},
	}
	for _, tt := range tests {
		t.Run(tt.declared, func(t *testing.T) {
			path, answer, err := answeredEntrypoint(tt.declared)
			if !errors.Is(err, tt.err) {
				t.Fatalf("answeredEntrypoint() error = %v, want %v", err, tt.err)
			}
			got := ""
			if answer != nil {
				got = answer.String()
			}
			if path != tt.path || got != tt.answer {
				t.Errorf("answeredEntrypoint() = %q and %q, want %q and %q", path, got, tt.path, tt.answer)
			}
		})
	}
}

// A decision declared with answers is listed with them, in the order they were
// named, and one named twice with two answers is one decision with both.
func TestReadsListTheAnswersOfADecision(t *testing.T) {
	bundle := bundleDeclaring(t, verdictPolicy, []string{"data.gate.verdict=allowed", "gate/verdict=clean", "gate/verdict=allowed"}, nil)

	reads, err := Reads(bundle, Limits{})
	if err != nil {
		t.Fatalf("Reads() error = %v", err)
	}
	if !slices.Equal(reads.Decisions, []string{"data.gate.verdict"}) {
		t.Errorf("decisions = %v, want the verdict once", reads.Decisions)
	}
	if expected := []string{`"allowed"`, `"clean"`}; !slices.Equal(reads.Answers["data.gate.verdict"], expected) {
		t.Errorf("answers = %v, want %v", reads.Answers["data.gate.verdict"], expected)
	}
	if !slices.Equal(bundle.Answers("data.gate.verdict"), reads.Answers["data.gate.verdict"]) {
		t.Errorf("Bundle.Answers() = %v, want what the reads carry", bundle.Answers("data.gate.verdict"))
	}
	if answers := bundle.Answers("data.gate.other"); len(answers) != 0 {
		t.Errorf("Bundle.Answers() of a decision nobody declared = %v, want none", answers)
	}
}

// The rules of a decision declared with answers are on two sides. One that
// gives a declared answer grants, and one that gives another refuses, so a check
// that keeps a request out of it lifts a refusal, the way a check under a not
// does. With no answer declared every rule is on the side that grants, the
// refusal included.
func TestReadsTakeTheSideOfARuleFromItsAnswer(t *testing.T) {
	type side struct {
		line              int
		request           string
		grants, exception bool
	}
	tests := []struct {
		name     string
		policy   string
		grants   []string
		denies   []string
		expected []side
	}{
		{
			name:   "the answers that grant",
			policy: verdictPolicy,
			grants: []string{"data.gate.verdict=allowed", "data.gate.verdict=clean"},
			expected: []side{
				// Being trusted keeps the request out of the rule that blocks.
				{line: 5, request: "input.trusted", grants: true, exception: true},
				{line: 8, request: "input.trusted", grants: true},
				{line: 9, request: "input.listed", grants: true},
				{line: 13, request: "input.trusted", grants: true},
				{line: 14, request: "input.listed"},
				{line: 15, request: "input.scan", grants: true},
			},
		},
		{
			name:   "no answer declared",
			policy: verdictPolicy,
			grants: []string{"data.gate.verdict"},
			expected: []side{
				{line: 5, request: "input.trusted"},
				{line: 8, request: "input.trusted", grants: true},
				{line: 9, request: "input.listed", grants: true},
				{line: 13, request: "input.trusted", grants: true},
				{line: 14, request: "input.listed"},
				{line: 15, request: "input.scan", grants: true},
			},
		},
		{
			name:   "the answer that refuses",
			policy: verdictPolicy,
			denies: []string{"data.gate.verdict=blocked"},
			expected: []side{
				{line: 5, request: "input.trusted", grants: true, exception: true},
				{line: 8, request: "input.trusted", grants: true},
				{line: 9, request: "input.listed", grants: true},
				{line: 13, request: "input.trusted", grants: true},
				{line: 14, request: "input.listed"},
				{line: 15, request: "input.scan", grants: true},
			},
		},
		{
			// The answer is two calls away: the rule returns what a function
			// builds, and the field is inside that.
			name:   "a field of an object a function builds",
			policy: resultPolicy,
			grants: []string{"sts/result/decision=allow"},
			expected: []side{
				{line: 9, request: "input.owner", grants: true},
				{line: 12, request: "input.owner", grants: true, exception: true},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reads, err := Reads(bundleDeclaring(t, tt.policy, tt.grants, tt.denies), Limits{})
			if err != nil {
				t.Fatalf("Reads() error = %v", err)
			}
			var got []side
			for _, check := range reads.Checks {
				if len(check.Decisions) != 1 {
					t.Fatalf("the check at line %d reaches %v, want the one decision", check.Line, check.Decisions)
				}
				got = append(got, side{check.Line, check.Request, check.Decisions[0].Grants, check.Decisions[0].Exception})
			}
			if !slices.Equal(got, tt.expected) {
				t.Errorf("sides =\n%+v\nwant\n%+v", got, tt.expected)
			}
		})
	}
}

// A decision declared with answers holds for a request it gives one of them
// to, and for no other: the refusal and the default are answers too, and a
// defined value is not a grant.
func TestHoldsOnADeclaredAnswer(t *testing.T) {
	tests := []struct {
		name     string
		policy   string
		grants   []string
		denies   []string
		decision string
		input    map[string]any
		expected bool
	}{
		{"an answer that grants", verdictPolicy, []string{"gate/verdict=allowed", "gate/verdict=clean"}, nil, "data.gate.verdict", map[string]any{"trusted": true, "listed": true}, true},
		{"the other answer that grants", verdictPolicy, []string{"gate/verdict=allowed", "gate/verdict=clean"}, nil, "data.gate.verdict", map[string]any{"trusted": true, "scan": "ok"}, true},
		{"the refusal", verdictPolicy, []string{"gate/verdict=allowed", "gate/verdict=clean"}, nil, "data.gate.verdict", map[string]any{}, false},
		{"the default", verdictPolicy, []string{"gate/verdict=allowed", "gate/verdict=clean"}, nil, "data.gate.verdict", map[string]any{"trusted": true}, false},
		{"declared to refuse, the refusal", verdictPolicy, nil, []string{"gate/verdict=blocked"}, "data.gate.verdict", map[string]any{}, true},
		{"declared to refuse, an answer that grants", verdictPolicy, nil, []string{"gate/verdict=blocked"}, "data.gate.verdict", map[string]any{"trusted": true, "listed": true}, false},
		{"a field, the allow", resultPolicy, []string{"sts/result/decision=allow"}, nil, "data.sts.result.decision", map[string]any{"owner": "alice"}, true},
		{"a field, a deny that is not the default", resultPolicy, []string{"sts/result/decision=allow"}, nil, "data.sts.result.decision", map[string]any{"reason": "no owner"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bundle := bundleDeclaring(t, tt.policy, tt.grants, tt.denies)
			holds, err := Holds(t.Context(), bundle, NoData(), tt.decision, tt.input)
			if err != nil {
				t.Fatalf("Holds() error = %v", err)
			}
			if holds != tt.expected {
				t.Errorf("Holds(%v) = %t, want %t", tt.input, holds, tt.expected)
			}
		})
	}
}

// What partial evaluation leaves of a decision declared with answers are the
// conditions under which it gives one of them, each with the answer, and
// nothing of the rules that give another.
func TestResidualsOfADeclaredAnswer(t *testing.T) {
	bundle := bundleDeclaring(t, verdictPolicy, []string{"gate/verdict=allowed", "gate/verdict=clean"}, nil)

	residuals, err := Residuals(t.Context(), bundle, NoData(), Request{Decision: "data.gate.verdict"}, Limits{})
	if err != nil {
		t.Fatalf("Residuals() error = %v", err)
	}
	expected := []Condition{
		{Query: "input.trusted; input.listed", Value: `"allowed"`},
		{Query: `input.trusted; not input.listed; input.scan = "ok"`, Value: `"clean"`},
	}
	if !slices.Equal(residuals.Conditions, expected) {
		t.Errorf("conditions =\n%+v\nwant\n%+v", residuals.Conditions, expected)
	}
	// The default is not among the conditions, and is still what the decision
	// says when none of them holds.
	if residuals.Always || residuals.Default != `"scan"` {
		t.Errorf("always = %t and default = %s, want a decision that does not always hold and falls back to \"scan\"",
			residuals.Always, residuals.Default)
	}

	// Asked whole, the same decision comes back with every rule, the one that
	// blocks among them, which is what a declared answer is for.
	whole := bundleDeclaring(t, verdictPolicy, []string{"gate/verdict"}, nil)
	all, err := Residuals(t.Context(), whole, NoData(), Request{Decision: "data.gate.verdict"}, Limits{})
	if err != nil {
		t.Fatalf("Residuals() error = %v", err)
	}
	if len(all.Conditions) != 3 || all.Default != `"scan"` {
		t.Errorf("asked whole, %d conditions and default %s, want the three rules and \"scan\"", len(all.Conditions), all.Default)
	}
}

// A decision that names an answer is on one side. Declared to grant on some
// answers and to refuse on others, or to grant whenever it holds and to refuse
// on an answer, it says two things that cannot both be meant. A rule the policy
// annotates carries no side, so it takes the one it is declared with.
func TestReadsRefusesAnswersOnBothSides(t *testing.T) {
	annotated := "package gate\n\n# METADATA\n# entrypoint: true\n" + verdictPolicy[len("package gate\n\n"):]

	tests := []struct {
		name   string
		policy string
		grants []string
		denies []string
		err    error
	}{
		{name: "answers on both sides", policy: verdictPolicy, grants: []string{"gate/verdict=allowed"}, denies: []string{"gate/verdict=blocked"}, err: ErrBadEntrypoint},
		{name: "to refuse whenever it holds, and to grant on an answer", policy: verdictPolicy, grants: []string{"gate/verdict=allowed"}, denies: []string{"gate/verdict"}, err: ErrBadEntrypoint},
		{name: "named with an answer and without one, on one side", policy: verdictPolicy, grants: []string{"gate/verdict", "gate/verdict=allowed"}},
		{name: "annotated, and declared to refuse on an answer", policy: annotated, denies: []string{"gate/verdict=blocked"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reads, err := Reads(bundleDeclaring(t, tt.policy, tt.grants, tt.denies), Limits{})
			if !errors.Is(err, tt.err) {
				t.Fatalf("Reads() error = %v, want %v", err, tt.err)
			}
			if tt.err == nil && len(reads.Answers["data.gate.verdict"]) != 1 {
				t.Errorf("answers = %v, want the one declared", reads.Answers["data.gate.verdict"])
			}
		})
	}
}
