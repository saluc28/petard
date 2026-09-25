package opaengine

import (
	"slices"
	"testing"
)

// A check is a part of the request held against a value the policy writes, and
// what matters about it is the side it lands on: the same comparison grants in
// one rule and refuses in another, and lifts a refusal when it sits under a
// negation inside something that would refuse.
func TestReadsFindTheChecksOnTheRequest(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		deny     []string
		expected []Check
	}{
		{
			// The login policy of the Spacelift starter repository.
			name: "a list of names compared with one",
			body: "allow if input.session.teams[_] == \"DevOps\"\n",
			expected: []Check{{
				Request: "input.session.teams[_]", Value: `"DevOps"`, Operator: CheckEqual, Rule: "data.checks.allow", Line: 5,
				Decisions: []CheckedDecision{{Name: "data.checks.allow", Grants: true}},
			}},
		},
		{
			name: "a value searched in the request",
			body: "allow if \"DevOps\" in input.session.teams\n",
			expected: []Check{{
				Request: "input.session.teams", Value: `"DevOps"`, Operator: CheckContains, Rule: "data.checks.allow", Line: 5,
				Decisions: []CheckedDecision{{Name: "data.checks.allow", Grants: true}},
			}},
		},
		{
			name: "the request searched in a list the policy writes",
			body: "allow if input.environment in {\"prod\", \"staging\"}\n",
			expected: []Check{{
				Request: "input.environment", Value: `{"prod", "staging"}`, Operator: CheckIn, Rule: "data.checks.allow", Line: 5,
				Decisions: []CheckedDecision{{Name: "data.checks.allow", Grants: true}},
			}},
		},
		{
			// What is asked for grants when it holds, the ticket rule refuses
			// when it holds, and the flag lifts that refusal.
			name: "an exemption from a rule the decision asks not to hold",
			body: `allow if {
	input.action == "deploy"
	not needs_ticket
}

needs_ticket if {
	input.environment == "production"
	not input.emergency
}
`,
			expected: []Check{
				{
					Request: "input.action", Value: `"deploy"`, Operator: CheckEqual, Rule: "data.checks.allow", Line: 6,
					Decisions: []CheckedDecision{{Name: "data.checks.allow", Grants: true}},
				},
				{
					Request: "input.environment", Value: `"production"`, Operator: CheckEqual, Rule: "data.checks.needs_ticket", Line: 11,
					Decisions: []CheckedDecision{{Name: "data.checks.allow"}},
				},
				{
					Request: "input.emergency", Rule: "data.checks.needs_ticket", Line: 12, UnderNegation: true,
					Decisions: []CheckedDecision{{Name: "data.checks.allow", Grants: true, Exception: true}},
				},
			},
		},
		{
			// The shape of lib.exempt_container in the gatekeeper-library: the
			// refusal is the decision, and the exemption is a function it asks
			// not to hold.
			name: "an exemption a violation asks not to hold",
			body: `violation contains "not allowed" if {
	some container in input.containers
	not exempt(container.image)
}

exempt(image) if image == "registry.example/debug"
`,
			deny: []string{"checks/violation"},
			expected: []Check{
				{
					Request: "input.containers[_].image", Value: `"registry.example/debug"`, Operator: CheckEqual, Rule: "data.checks.exempt", Line: 10,
					Decisions: []CheckedDecision{{Name: "data.checks.violation", Grants: true, Exception: true}},
				},
			},
		},
		{
			name:     "a part of the request compared with a document",
			body:     "allow if input.user == data.settings.owner\n",
			expected: nil,
		},
		{
			name:     "a part of the request compared with what the policy computes",
			body:     "allow if input.user == upper(data.settings.owner)\n",
			expected: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := "package checks\n\n# METADATA\n# entrypoint: true\n" + tt.body
			bundle, err := Load([]string{writeSources(t, map[string]string{"policy.rego": policy})}, ParseModeV1)
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if tt.deny != nil {
				bundle.DenyEntrypoints = tt.deny
			}
			reads, err := Reads(bundle, Limits{})
			if err != nil {
				t.Fatalf("Reads() error = %v", err)
			}

			var got []Check
			for _, check := range reads.Checks {
				check.File = ""
				got = append(got, check)
			}
			if !slices.EqualFunc(got, tt.expected, sameCheck) {
				t.Errorf("checks =\n%+v\nwant\n%+v", got, tt.expected)
			}
		})
	}
}

func sameCheck(a, b Check) bool {
	return a.Request == b.Request && a.Value == b.Value && a.Operator == b.Operator && a.Rule == b.Rule &&
		a.Line == b.Line && a.UnderNegation == b.UnderNegation && slices.Equal(a.Decisions, b.Decisions)
}

// With not imported the negation holds a body of its own, and the check inside
// it lands on the same side as the one written the old way.
func TestReadsFindTheChecksInsideAnImportedNot(t *testing.T) {
	policy := `package checks

import future.keywords.not

# METADATA
# entrypoint: true
allow if {
	input.action == "deploy"
	not needs_ticket
}

needs_ticket if {
	input.environment == "production"
	not input.emergency
}
`
	var emergency []Check
	for _, check := range readsOf(t, policy, Limits{}).Checks {
		if check.Request == "input.emergency" {
			emergency = append(emergency, check)
		}
	}
	expected := []CheckedDecision{{Name: "data.checks.allow", Grants: true, Exception: true}}
	if len(emergency) != 1 || !slices.Equal(emergency[0].Decisions, expected) {
		t.Errorf("checks on input.emergency = %+v, want one that lifts the refusal of data.checks.allow", emergency)
	}
}
