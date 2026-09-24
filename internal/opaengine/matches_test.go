package opaengine

import (
	"context"
	"slices"
	"testing"
)

// A request picks a document by value as often as by key, and each of these is
// a way a policy writes it. The ones that come back empty matter as much: a
// value in a document the request names is a check on that document, and a
// comparison nothing asserts is not a lookup at all.
func TestReadsFindTheRequestByValue(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		path     string
		expected []Match
	}{
		{
			name: "an element compared with the request",
			body: `allow if {
	some binding in data.bindings
	binding.user == input.user
}
`,
			path:     "data.bindings[_].user",
			expected: []Match{{Term: "input.user", Position: 2}},
		},
		{
			name:     "a collection searched for the request",
			body:     "allow if input.user in data.teams[input.team].members\n",
			path:     "data.teams[_].members",
			expected: []Match{{Term: "input.user", Position: 4, Member: true}},
		},
		{
			// The shape of Chef Automate: every member of every policy against
			// every subject of the request, compared inside a function that only
			// ever sees its two parameters.
			name: "a comparison a function makes between its parameters",
			body: `allow if has_member[_]

has_member contains policy if {
	member := data.policies[policy].members[_]
	subject := input.subjects[_]
	matches(subject, member)
}

matches(value, stored) if value == stored
`,
			path:     "data.policies[_].members[_]",
			expected: []Match{{Term: "input.subjects[_]", Position: 4}},
		},
		{
			// The shape of the fixture: the search is inside the function, and
			// only the call site knows the element is the requester.
			name: "the request reaches the comparison through the caller",
			body: `allow if is_member(input.user, input.project)

is_member(user, project) if user in data.projects[project].members
`,
			path:     "data.projects[_].members",
			expected: []Match{{Term: "input.user", Position: 4, Member: true}},
		},
		{
			// The shape of InfraBox: the requester and the project travel in one
			// array, which the head of the function takes apart, and the
			// comparison is written with a single =.
			name: "the request reaches the comparison inside an array argument",
			body: `allow if collab([input.user, input.project])

collab([user, project]) if {
	some i
	data.collaborators[i].project_id = project
	data.collaborators[i].user_id = user
}
`,
			path:     "data.collaborators[_].user_id",
			expected: []Match{{Term: "input.user", Position: 2}},
		},
		{
			name: "the request reaches the comparison inside an object argument",
			body: `allow if named({"who": input.user})

named({"who": user}) if data.admins[_] == user
`,
			path:     "data.admins[_]",
			expected: []Match{{Term: "input.user", Position: 2}},
		},
		{
			name: "a function that compares its parameter with the request",
			body: `allow if {
	some binding in data.bindings
	is_requester(binding.user)
}

is_requester(name) if name == input.user
`,
			path:     "data.bindings[_].user",
			expected: []Match{{Term: "input.user", Position: 2}},
		},
		{
			name:     "a value in a document the request names",
			body:     "allow if input.user == data.documents[input.doc].owner\n",
			path:     "data.documents[_].owner",
			expected: nil,
		},
		{
			name: "a comparison whose result is kept rather than asserted",
			body: `allow if {
	some binding in data.bindings
	same := binding.user == input.user
	is_boolean(same)
}
`,
			path:     "data.bindings[_].user",
			expected: nil,
		},
		{
			name: "a prefix of the request",
			body: `allow if {
	some prefix in data.prefixes
	startswith(input.user, prefix)
}
`,
			path:     "data.prefixes[_]",
			expected: nil,
		},
		{
			name: "two documents compared with each other",
			body: `allow if {
	some team in data.teams
	team.owner == data.users[input.user].manager
}
`,
			path:     "data.teams[_].owner",
			expected: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := "package lookup\n\n# METADATA\n# entrypoint: true\n" + tt.body
			read := readOfPath(t, readsOf(t, policy, Limits{}), tt.path)

			if !slices.Equal(read.Matches, tt.expected) {
				t.Errorf("matches of %s = %+v, want %+v", tt.path, read.Matches, tt.expected)
			}
		})
	}
}

// A function that compares in an operand of an or holds through that comparison
// as much as through a body of its own, and the lookup is found the same way:
// once for each part of the request the operands compare with.
func TestReadsFindTheRequestByValueInsideAnOr(t *testing.T) {
	policy := `package lookup

import future.keywords.or

# METADATA
# entrypoint: true
allow if {
	some binding in data.bindings
	is_requester(binding.user)
}

is_requester(name) if {
	name == input.user or name == input.delegate
}
`
	read := readOfPath(t, readsOf(t, policy, Limits{}), "data.bindings[_].user")

	var terms []string
	for _, match := range read.Matches {
		terms = append(terms, match.Term)
	}
	slices.Sort(terms)
	if expected := []string{"input.delegate", "input.user"}; !slices.Equal(terms, expected) {
		t.Errorf("matches of data.bindings[_].user = %+v, want one for each of %v", read.Matches, expected)
	}
}

// A lookup by value says who is compared with the document, and leaves alone
// who names its key: the policies of Chef are still chosen by the data.
func TestAMatchLeavesTheProvenanceAlone(t *testing.T) {
	reads := readsOf(t, `package lookup

# METADATA
# entrypoint: true
allow if {
	some policy
	input.subjects[_] == data.policies[policy].members[_]
}
`, Limits{})

	read := readOfPath(t, reads, "data.policies[_].members[_]")
	if read.Provenance != ProvenanceData {
		t.Errorf("provenance = %s, want data", read.Provenance)
	}
	if len(read.Matches) != 1 || read.Matches[0].Term != "input.subjects[_]" {
		t.Errorf("matches = %+v, want one on input.subjects[_]", read.Matches)
	}
}

// The members are who a policy that looks its requesters up knows about, and
// the walk that finds them is the one Presence uses.
func TestValuesOnFixture(t *testing.T) {
	values, err := fixtureData(t).Values(context.Background(), "data.projects[_].members[_]")
	if err != nil {
		t.Fatalf("Values() error = %v", err)
	}

	// The walk goes through the projects in the order of their keys, root
	// before the teams.
	expected := []any{"dave", "alice", "carol"}
	if !slices.Equal(values, expected) {
		t.Errorf("Values() = %v, want %v", values, expected)
	}
}

func TestValuesOfAPathThatIsNotUnderData(t *testing.T) {
	if _, err := fixtureData(t).Values(context.Background(), "input.user"); err == nil {
		t.Error("Values() on a path into input returned no error")
	}
}
