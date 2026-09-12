package opaengine

import "testing"

// The provenance of a read is a claim about who chooses the document, and each
// of these cases is a way the answer arrives from somewhere other than the
// expression doing the reading.
func TestReadProvenanceSources(t *testing.T) {
	tests := []struct {
		name     string
		policy   string
		path     string
		expected Provenance
	}{
		{
			name: "the requester chooses",
			policy: `allow if data.users[input.user].active
`,
			path:     "data.users[_].active",
			expected: ProvenanceInput,
		},
		{
			name: "a free index iterates over the collection",
			// p is bound by nothing: in Rego that means every project, and the
			// keys come from data.
			policy: `allow if {
	some p
	data.projects[p].members
}
`,
			path:     "data.projects[_].members",
			expected: ProvenanceData,
		},
		{
			name: "a pure builtin passes on what it was given",
			// count returns a number nobody outside the policy controls, so
			// the provenance is that of its argument, not a taint.
			policy: `allow if {
	n := count(data.projects)
	data.users[n].active
}
`,
			path:     "data.users[_].active",
			expected: ProvenanceData,
		},
		{
			name: "a nondeterministic builtin is where the policy stops deciding",
			policy: `allow if {
	r := http.send({"method": "GET", "url": "https://idp.invalid/who"})
	data.users[r.body.id].active
}
`,
			path:     "data.users[_].active",
			expected: ProvenanceBuiltin,
		},
		{
			name: "a constant index names one document",
			policy: `allow if data.users.root.active
`,
			path:     "data.users.root.active",
			expected: ProvenanceStatic,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reads := readsOf(t, decisionPolicy(tt.policy), Limits{})

			read := readOfPath(t, reads, tt.path)
			if read.Provenance != tt.expected {
				t.Errorf("provenance = %s, want %s (read %s)", read.Provenance, tt.expected, read.Ref)
			}
		})
	}
}

// http.send is nondeterministic and graph.reachable is not, and the difference
// is what keeps taint from being invented. Both are calls that return a value
// the policy did not write down; only one of them has an answer somebody else
// controls.
func TestOnlyNondeterministicBuiltinsAreExternal(t *testing.T) {
	reads := readsOf(t, decisionPolicy(`allow if {
	reachable := graph.reachable(data.hierarchy, {"root"})
	some p in reachable
	data.projects[p].members
}
`), Limits{})

	read := readOfPath(t, reads, "data.projects[_].members")
	if read.Provenance != ProvenanceData {
		t.Errorf("provenance = %s, want data: graph.reachable only rearranges data", read.Provenance)
	}
	if read.Origin != "" {
		t.Errorf("origin = %q, want empty: a pure builtin is not an external source", read.Origin)
	}
}

// The origin is named only where naming it is true. A value that came through
// a rule of the policy is attributed to that rule, not to whatever the rule
// called: an analyst following the report has to land where the value entered.
func TestOriginNamesTheExternalSourceOnly(t *testing.T) {
	reads := readsOf(t, decisionPolicy(`allow if {
	r := http.send({"method": "GET", "url": "https://idp.invalid/who"})
	data.users[r.body.id].active
}
`), Limits{})

	if read := readOfPath(t, reads, "data.users[_].active"); read.Origin != "http.send" {
		t.Errorf("origin = %q, want http.send", read.Origin)
	}
}

// decisionPolicy wraps a rule body into a package with a declared entrypoint,
// which is what the walk starts from.
func decisionPolicy(rules string) string {
	return `package t

# METADATA
# scope: document
# entrypoint: true
default allow := false

` + rules
}
