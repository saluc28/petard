package taxonomy

import (
	"reflect"
	"slices"
	"testing"

	"github.com/saluc28/petard/internal/opaengine"
)

func TestRequestNaming(t *testing.T) {
	tests := []struct {
		name     string
		subject  string
		expected map[string]any
	}{
		{
			name:     "a field of the request",
			subject:  "input.user",
			expected: map[string]any{"user": "alice"},
		},
		{
			name:     "a field deeper in the request",
			subject:  "input.subject.id",
			expected: map[string]any{"subject": map[string]any{"id": "alice"}},
		},
		{
			name:     "a list that holds the principal alone",
			subject:  "input.subjects[_]",
			expected: map[string]any{"subjects": []any{"alice"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fields, named := subjectFieldsOf(opaengine.Shape{Subject: tt.subject})
			if !named {
				t.Fatalf("subjectFieldsOf(%q) says a request cannot name it", tt.subject)
			}
			if got := requestNaming(fields, "alice"); !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("requestNaming() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// A request that quietly named nobody would measure every principal as an
// anonymous caller, so what cannot be written into a request is refused.
func TestSubjectFieldsRefuseWhatARequestCannotName(t *testing.T) {
	for _, subject := range []string{"", "data.users", "input.users[input.tenant]", "input.groups[_].name"} {
		if _, named := subjectFieldsOf(opaengine.Shape{Subject: subject}); named {
			t.Errorf("subjectFieldsOf(%q) says a request can name it", subject)
		}
	}
}

// A request naming one principal fixes the whole list, so none of it is left
// open, whatever part of it the policy reads.
func TestUnknownsBesidesAList(t *testing.T) {
	paths := []string{"input.action", "input.subjects", "input.subjects[_]", "input.subjects[_].id", "input.subjectsx"}
	got := unknownsBesides(opaengine.Shape{Subject: "input.subjects[_]"}, paths)

	expected := []string{"input.action", "input.subjectsx"}
	if !slices.Equal(got, expected) {
		t.Errorf("unknownsBesides() = %v, want %v", got, expected)
	}
}

// End to end: the principals of a policy that looks its requesters up are the
// members it searches, and a list naming one of them is a request the decision
// answers for that member and for nobody else.
func TestAListOfSubjectsIsMeasuredMemberByMember(t *testing.T) {
	a := analysisOf(t, &FalsePositiveCase{
		Policy: `package lists

# METADATA
# scope: document
# title: Decision on the members of a policy
# entrypoint: true
default allow := false

allow if {
	some policy
	input.subjects[_] == data.policies[policy].members[_]
	input.action in data.policies[policy].actions
}
`,
		Data: `{"policies": {"readers": {"members": ["user:alice", "team:admins"], "actions": ["read"]}}}`,
	})

	principals, err := principalsOf(t.Context(), a.Shape, a.Reads, a.Data)
	if err != nil {
		t.Fatalf("principalsOf() error = %v", err)
	}
	if !slices.Equal(principals, []string{"team:admins", "user:alice"}) {
		t.Fatalf("principals = %v, want the two members", principals)
	}

	fields, named := subjectFieldsOf(a.Shape)
	if !named {
		t.Fatalf("subject %q cannot be named in a request", a.Shape.Subject)
	}
	unknowns := unknownsBesides(a.Shape, a.Reads.InputPaths)
	for principal, grants := range map[string]bool{"user:alice": true, "user:bob": false} {
		got, err := reachOf(t.Context(), a.Bundle, a.Data, "data.lists.allow", requestNaming(fields, principal), unknowns, opaengine.Limits{})
		if err != nil {
			t.Fatalf("reachOf(%s) error = %v", principal, err)
		}
		if got.nothing() == grants {
			t.Errorf("%s reaches %+v, want granted %v", principal, got, grants)
		}
	}
}
