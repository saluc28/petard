package zanzibar

import (
	"slices"
	"testing"
	"time"
)

// documents is the schema the closure tests write against: a document with an
// owner, an editor, a viewer that also admits a team's members and a wildcard,
// edit over owner and editor, and view over the viewer and edit.
func documents(t *testing.T) *Model {
	t.Helper()
	document := &Type{
		Name: "document",
		Relations: []*Relation{
			{Name: "owner", Allowed: []Allowed{{Type: "user"}}},
			{Name: "editor", Allowed: []Allowed{{Type: "user"}}},
			{Name: "viewer", Allowed: []Allowed{
				{Type: "user"},
				{Type: "team", Relation: "member"},
				{Type: "user", Wildcard: true},
			}},
		},
		Permissions: []*Permission{
			{Name: "edit", Expr: Union{Children: []Expr{Computed{Name: "owner"}, Computed{Name: "editor"}}}},
			{Name: "view", Expr: Union{Children: []Expr{Computed{Name: "viewer"}, Computed{Name: "edit"}}}},
		},
	}
	team := &Type{Name: "team", Relations: []*Relation{{Name: "member", Allowed: []Allowed{{Type: "user"}}}}}
	m, err := NewModel([]*Type{{Name: "user"}, team, document}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func rel(resource, relation, subject string) Relationship {
	return Relationship{
		Resource: object(resource),
		Relation: relation,
		Subject:  subjectOf(subject),
	}
}

func object(s string) Object {
	for i := range len(s) {
		if s[i] == ':' {
			return Object{Type: s[:i], ID: s[i+1:]}
		}
	}
	return Object{Type: s}
}

func subjectOf(s string) Subject {
	for i := range len(s) {
		if s[i] == '#' {
			return Subject{Object: object(s[:i]), Relation: s[i+1:]}
		}
	}
	return Subject{Object: object(s)}
}

func TestClosure(t *testing.T) {
	model := documents(t)
	roadmap := object("document:roadmap")
	mallory := object("user:mallory")

	tests := []struct {
		name      string
		writes    []*WriteRule
		creates   []*CreationRule
		start     []Relationship
		coalition []Object
		wantAdded []Relationship
		wantView  Level
	}{
		{
			name: "self-write into viewer",
			writes: []*WriteRule{
				{Resource: "document", Relation: "viewer", Operations: []Operation{Create}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Self: true}},
			},
			start:     []Relationship{rel("document:roadmap", "owner", "user:olivia")},
			coalition: []Object{mallory},
			wantAdded: []Relationship{rel("document:roadmap", "viewer", "user:mallory")},
			wantView:  Yes,
		},
		{
			name: "gate opens after a write",
			writes: []*WriteRule{
				{Resource: "document", Relation: "editor", Operations: []Operation{Create}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Self: true}},
				{Resource: "document", Relation: "viewer", Operations: []Operation{Create}, Gate: Gate{Holds: "edit"}, Subject: SubjectSpec{Self: true}},
			},
			start:     []Relationship{rel("document:roadmap", "owner", "user:olivia")},
			coalition: []Object{mallory},
			wantAdded: []Relationship{
				rel("document:roadmap", "editor", "user:mallory"),
				rel("document:roadmap", "viewer", "user:mallory"),
			},
			wantView: Yes,
		},
		{
			name: "wildcard subject is a global switch",
			writes: []*WriteRule{
				{Resource: "document", Relation: "viewer", Operations: []Operation{Create}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Any: true}, Wildcard: true},
			},
			start:     []Relationship{rel("document:roadmap", "owner", "user:olivia")},
			coalition: []Object{mallory},
			wantAdded: []Relationship{
				rel("document:roadmap", "viewer", "user:mallory"),
				rel("document:roadmap", "viewer", "user:*"),
			},
			wantView: Yes,
		},
		{
			name: "created team assumed into viewer",
			writes: []*WriteRule{
				{Resource: "document", Relation: "viewer", Operations: []Operation{Create}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Types: []string{"team#member"}}},
			},
			creates: []*CreationRule{
				{Creates: "team", Gate: Gate{Anyone: true}, Writes: []CreationWrite{
					{Resource: CreatedPlaceholder, Relation: "member", Subject: CreatorPlaceholder},
				}},
			},
			start:     []Relationship{rel("document:roadmap", "owner", "user:olivia")},
			coalition: []Object{mallory},
			wantAdded: []Relationship{
				rel("team:created-0", "member", "user:mallory"),
				rel("document:roadmap", "viewer", "team:created-0#member"),
			},
			wantView: Yes,
		},
		{
			name: "service gate is out of reach",
			writes: []*WriteRule{
				{Resource: "document", Relation: "viewer", Operations: []Operation{Create}, Gate: Gate{Service: "sharing"}, Subject: SubjectSpec{Self: true}},
			},
			start:     []Relationship{rel("document:roadmap", "owner", "user:olivia")},
			coalition: []Object{mallory},
			wantAdded: nil,
			wantView:  No,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wm := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: tt.writes, Creates: tt.creates}
			reach, err := Closure(model, wm, nil, tt.start, tt.coalition, Options{Now: time.Unix(0, 0)})
			if err != nil {
				t.Fatalf("Closure: %v", err)
			}

			added := addedTuples(tt.start, reach.State)
			if !sameTuples(added, tt.wantAdded) {
				t.Errorf("added tuples = %v, want %v", keysOf(added), keysOf(tt.wantAdded))
			}

			view, err := reach.Holds(roadmap, "view")
			if err != nil {
				t.Fatalf("Holds view: %v", err)
			}
			if view != tt.wantView {
				t.Errorf("coalition view = %s, want %s", view, tt.wantView)
			}

			assertSaturated(t, model, wm, nil, tt.start, tt.coalition, reach)
		})
	}
}

// addedTuples is the tuples of the reachable state that the start did not have.
func addedTuples(start, state []Relationship) []Relationship {
	was := map[string]bool{}
	for _, r := range start {
		was[tupleKey(r)] = true
	}
	var added []Relationship
	for _, r := range state {
		if !was[tupleKey(r)] {
			added = append(added, r)
		}
	}
	return added
}

func sameTuples(a, b []Relationship) bool {
	ka, kb := keysOf(a), keysOf(b)
	slices.Sort(ka)
	slices.Sort(kb)
	return slices.Equal(ka, kb)
}

func keysOf(rels []Relationship) []string {
	out := make([]string, 0, len(rels))
	for _, r := range rels {
		out = append(out, tupleKey(r))
	}
	return out
}
