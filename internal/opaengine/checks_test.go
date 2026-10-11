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
			// The shape of K8sBlockWildcardIngress in the gatekeeper-library. A
			// field read with object.get and a default is that field, and what a
			// function then tests is a check on it.
			name: "a field read with a default, tested in a function",
			body: `violation contains "wildcard" if {
	hostname := object.get(input.review.object.spec.rules[_], "host", "")
	wildcard(hostname)
}

wildcard(hostname) if hostname == ""

wildcard(hostname) if contains(hostname, "*")
`,
			deny: []string{"checks/violation"},
			expected: []Check{
				{
					Request: "input.review.object.spec.rules[_].host", Value: `""`, Operator: CheckEqual, Rule: "data.checks.wildcard", Line: 10,
					Decisions: []CheckedDecision{{Name: "data.checks.violation"}},
				},
				{
					Request: "input.review.object.spec.rules[_].host", Value: `"*"`, Operator: CheckSubstring, Rule: "data.checks.wildcard", Line: 12,
					Decisions: []CheckedDecision{{Name: "data.checks.violation"}},
				},
			},
		},
		{
			// lib.exempt_container again, as it is written: the list of exempt
			// images is read out of the parameters with one object.get inside
			// another, and the exemption is an element of it.
			name: "an element of a list read with a default, tested in a function",
			body: `violation contains "not allowed" if {
	some container in input.review.object.spec.containers
	not exempt(container)
}

exempt(container) if {
	exempt_images := object.get(object.get(input, "parameters", {}), "exemptImages", [])
	exemption := exempt_images[_]
	matches(container.image, exemption)
}

matches(image, exemption) if {
	endswith(exemption, "*")
	startswith(image, trim_suffix(exemption, "*"))
}
`,
			deny: []string{"checks/violation"},
			expected: []Check{{
				Request: "input.parameters.exemptImages[_]", Value: `"*"`, Operator: CheckSuffix, Rule: "data.checks.matches", Line: 17,
				Decisions: []CheckedDecision{{Name: "data.checks.violation", Grants: true, Exception: true}},
			}},
		},
		{
			// The exemption of the fixture, read the way a policy reads a
			// request it does not trust to be complete.
			name: "an exemption read with a default",
			body: `allow if {
	input.action == "export"
	not needs_second_factor
}

needs_second_factor if {
	scheduled := object.get(input, "scheduled", false)
	not scheduled
}
`,
			expected: []Check{
				{
					Request: "input.action", Value: `"export"`, Operator: CheckEqual, Rule: "data.checks.allow", Line: 6,
					Decisions: []CheckedDecision{{Name: "data.checks.allow", Grants: true}},
				},
				{
					Request: "input.scheduled", Rule: "data.checks.needs_second_factor", Line: 12, UnderNegation: true,
					Decisions: []CheckedDecision{{Name: "data.checks.allow", Grants: true, Exception: true}},
				},
			},
		},
		{
			// The lookup of the budget rule in the FinOps policies of
			// rego_policy_libraries: a key the policy computes picks an element
			// of the part it is looked up in.
			name: "an element read under a key the policy computes",
			body: `allow if {
	some cost_center, _ in input.budget_registry
	spend := object.get(input.current_spend, cost_center, 0)
	spend == 0
}
`,
			expected: []Check{{
				Request: "input.current_spend[_]", Value: "0", Operator: CheckEqual, Rule: "data.checks.allow", Line: 8,
				Decisions: []CheckedDecision{{Name: "data.checks.allow", Grants: true}},
			}},
		},
		{
			name: "an exemption read under a key the request picks",
			body: `allow if not needs_review

needs_review if {
	exempt := object.get(input.exemptions, input.kind, false)
	not exempt
}
`,
			expected: []Check{{
				Request: "input.exemptions[_]", Rule: "data.checks.needs_review", Line: 9, UnderNegation: true,
				Decisions: []CheckedDecision{{Name: "data.checks.allow", Grants: true, Exception: true}},
			}},
		},
		{
			// The shape of app_restriction_present in the Entra policy of
			// rego_policy_libraries: the collection is a parameter, and what the
			// function tests is an entry of whichever collection it is handed.
			name: "elements read under a key a function is handed",
			body: `violation contains "not restricted" if {
	not restricted("password_credentials", "passwordAddition")
}

restricted(collection, kind) if {
	some r in object.get(input.app_management, collection, [])
	r.restrictionType == kind
	r.state == "enabled"
}
`,
			deny: []string{"checks/violation"},
			expected: []Check{
				{
					Request: "input.app_management[_][_].restrictionType", Value: `"passwordAddition"`, Operator: CheckEqual, Rule: "data.checks.violation", Line: 6, UnderNegation: true,
					Decisions: []CheckedDecision{{Name: "data.checks.violation", Grants: true, Exception: true}},
				},
				{
					Request: "input.app_management[_][_].state", Value: `"enabled"`, Operator: CheckEqual, Rule: "data.checks.restricted", Line: 12,
					Decisions: []CheckedDecision{{Name: "data.checks.violation", Grants: true, Exception: true}},
				},
			},
		},
		{
			name: "a path the policy computes below a field it names",
			body: `allow if {
	role := object.get(input, ["user", data.settings.field], "")
	role == "admin"
}
`,
			expected: []Check{{
				Request: "input.user[_]", Value: `"admin"`, Operator: CheckEqual, Rule: "data.checks.allow", Line: 7,
				Decisions: []CheckedDecision{{Name: "data.checks.allow", Grants: true}},
			}},
		},
		{
			// Looked up in the request itself, a key the policy computes could
			// be any field of it, so what the call returned names no part.
			name: "a field of the request read under a key the policy computes",
			body: `allow if {
	flag := object.get(input, data.settings.field, false)
	flag == "on"
}
`,
			expected: nil,
		},
		{
			// A function handed a part of the request tests a field of it, and
			// the check is on that field of the part each call hands over.
			name: "a field of a part of the request handed to a function",
			body: `allow if allowed(input.user)

allowed(user) if user.role == "admin"

allowed(user) if startswith(user.email, "ops-")
`,
			expected: []Check{
				{
					Request: "input.user.role", Value: `"admin"`, Operator: CheckEqual, Rule: "data.checks.allowed", Line: 7,
					Decisions: []CheckedDecision{{Name: "data.checks.allow", Grants: true}},
				},
				{
					Request: "input.user.email", Value: `"ops-"`, Operator: CheckPrefix, Rule: "data.checks.allowed", Line: 9,
					Decisions: []CheckedDecision{{Name: "data.checks.allow", Grants: true}},
				},
			},
		},
		{
			// What another builtin made of the request has the request behind it
			// and no path in it. The call site can name the builtin and not a
			// part of the request, and a check names a part or it is not one.
			name: "a value a builtin made of the request, tested in a function",
			body: `violation contains "wildcard" if {
	hostname := trim_prefix(input.review.object.spec.host, "www.")
	wildcard(hostname)
}

wildcard(hostname) if contains(hostname, "*")
`,
			deny:     []string{"checks/violation"},
			expected: nil,
		},
		{
			// A case fold is the same part of the request with its letters
			// changed, in the body that folds it and in a function handed it.
			name: "a case fold of the request, tested in a function",
			body: `violation contains "wildcard" if {
	hostname := lower(input.review.object.spec.host)
	wildcard(hostname)
}

wildcard(hostname) if contains(hostname, "*")
`,
			deny: []string{"checks/violation"},
			expected: []Check{{
				Request: "input.review.object.spec.host", Value: `"*"`, Operator: CheckSubstring, Rule: "data.checks.wildcard", Line: 10,
				Decisions: []CheckedDecision{{Name: "data.checks.violation"}},
			}},
		},
		{
			name: "a case fold compared with a value the policy writes",
			body: "allow if upper(input.method) == \"GET\"\n",
			expected: []Check{{
				Request: "input.method", Value: `"GET"`, Operator: CheckEqual, Rule: "data.checks.allow", Line: 5,
				Decisions: []CheckedDecision{{Name: "data.checks.allow", Grants: true}},
			}},
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

// A loose string match is a check too: the request held against a value the
// policy writes with an operator wider than equality. The engine reads the form,
// so a pattern can tell a substring from a prefix, and reads through a case fold.
func TestReadsFindTheLooseMatches(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected []Check
	}{
		{
			name: "a substring of the request",
			body: "allow if contains(input.path, \"/admin\")\n",
			expected: []Check{{
				Request: "input.path", Value: `"/admin"`, Operator: CheckSubstring, Rule: "data.checks.allow", Line: 5,
				Decisions: []CheckedDecision{{Name: "data.checks.allow", Grants: true}},
			}},
		},
		{
			// The compiler hoists lower(input.path) into a binding, and the fold
			// is followed back to the part it was given.
			name: "a case-folded match",
			body: "allow if contains(lower(input.path), \"/admin\")\n",
			expected: []Check{{
				Request: "input.path", Value: `"/admin"`, Operator: CheckSubstring, Rule: "data.checks.allow", Line: 5,
				Decisions: []CheckedDecision{{Name: "data.checks.allow", Grants: true}},
			}},
		},
		{
			name: "a prefix of the request",
			body: "allow if startswith(input.path, \"/admin/\")\n",
			expected: []Check{{
				Request: "input.path", Value: `"/admin/"`, Operator: CheckPrefix, Rule: "data.checks.allow", Line: 5,
				Decisions: []CheckedDecision{{Name: "data.checks.allow", Grants: true}},
			}},
		},
		{
			name: "a glob over the request",
			body: "allow if glob.match(\"/do/**\", [], input.path)\n",
			expected: []Check{{
				Request: "input.path", Value: `"/do/**"`, Operator: CheckGlob, Rule: "data.checks.allow", Line: 5,
				Decisions: []CheckedDecision{{Name: "data.checks.allow", Grants: true}},
			}},
		},
		{
			name: "an unanchored regex over the request",
			body: "allow if regex.match(\"admin\", input.path)\n",
			expected: []Check{{
				Request: "input.path", Value: `"admin"`, Operator: CheckRegex, Rule: "data.checks.allow", Line: 5,
				Decisions: []CheckedDecision{{Name: "data.checks.allow", Grants: true}},
			}},
		},
		{
			name:     "an anchored regex is a whole-string test, not a loose match",
			body:     "allow if regex.match(\"^/admin$\", input.path)\n",
			expected: nil,
		},
		{
			name: "a regex anchored at the start is a prefix",
			body: "allow if regex.match(`^/admin`, input.path)\n",
			expected: []Check{{
				Request: "input.path", Value: `"^/admin"`, Operator: CheckRegexAnchored, Rule: "data.checks.allow", Line: 5,
				Decisions: []CheckedDecision{{Name: "data.checks.allow", Grants: true}},
			}},
		},
		{
			// Each branch pins one end and neither pins both, so a value only
			// has to start one way or end the other.
			name: "an alternation anchored at one end in each branch",
			body: "allow if regex.match(`^/public|/health$`, input.path)\n",
			expected: []Check{{
				Request: "input.path", Value: `"^/public|/health$"`, Operator: CheckRegexAnchored, Rule: "data.checks.allow", Line: 5,
				Decisions: []CheckedDecision{{Name: "data.checks.allow", Grants: true}},
			}},
		},
		{
			name: "both ends pinned and opened again",
			body: "allow if regex.match(`^.*admin.*$`, input.path)\n",
			expected: []Check{{
				Request: "input.path", Value: `"^.*admin.*$"`, Operator: CheckRegex, Rule: "data.checks.allow", Line: 5,
				Decisions: []CheckedDecision{{Name: "data.checks.allow", Grants: true}},
			}},
		},
		{
			name: "a glob with a wildcard at each end",
			body: "allow if glob.match(\"*admin*\", [], input.path)\n",
			expected: []Check{{
				Request: "input.path", Value: `"*admin*"`, Operator: CheckGlobEmbedded, Rule: "data.checks.allow", Line: 5,
				Decisions: []CheckedDecision{{Name: "data.checks.allow", Grants: true}},
			}},
		},
		{
			name: "a glob with no wildcard is an equality",
			body: "allow if glob.match(\"/admin\", [\"/\"], input.path)\n",
			expected: []Check{{
				Request: "input.path", Value: `"/admin"`, Operator: CheckEqual, Rule: "data.checks.allow", Line: 5,
				Decisions: []CheckedDecision{{Name: "data.checks.allow", Grants: true}},
			}},
		},
		{
			name:     "a match against a value from the data is not a value the policy writes",
			body:     "allow if contains(input.path, data.markers.admin)\n",
			expected: nil,
		},
		{
			name:     "an assigned match asserts nothing",
			body:     "allow if {\n\tok := startswith(input.path, \"/admin\")\n\tok\n}\n",
			expected: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := "package checks\n\n# METADATA\n# entrypoint: true\n" + tt.body
			reads := readsOf(t, policy, Limits{})

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
