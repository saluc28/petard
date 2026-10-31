package openfga

import (
	"errors"
	"reflect"
	"testing"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/saluc28/petard/internal/zanzibar"
)

func TestLowerTuple(t *testing.T) {
	context, err := structpb.NewStruct(map[string]any{"age": 3})
	if err != nil {
		t.Fatal(err)
	}
	inline, err := structpb.NewStruct(map[string]any{"expression": "true", "parameters": map[string]any{"x": "int"}, "x": 1})
	if err != nil {
		t.Fatal(err)
	}
	pos := zanzibar.Position{File: "store.fga.yaml", Line: 7}

	tests := []struct {
		name string
		key  *openfgav1.TupleKey
		want zanzibar.Relationship
	}{
		{
			name: "an object",
			key:  &openfgav1.TupleKey{User: "user:alice", Relation: "viewer", Object: "document:1"},
			want: zanzibar.Relationship{
				Resource: zanzibar.Object{Type: "document", ID: "1"},
				Relation: "viewer",
				Subject:  zanzibar.Subject{Object: zanzibar.Object{Type: "user", ID: "alice"}},
				Position: pos,
			},
		},
		{
			name: "a userset",
			key:  &openfgav1.TupleKey{User: "group:eng#member", Relation: "viewer", Object: "document:1"},
			want: zanzibar.Relationship{
				Resource: zanzibar.Object{Type: "document", ID: "1"},
				Relation: "viewer",
				Subject:  zanzibar.Subject{Object: zanzibar.Object{Type: "group", ID: "eng"}, Relation: "member"},
				Position: pos,
			},
		},
		{
			name: "a wildcard",
			key:  &openfgav1.TupleKey{User: "user:*", Relation: "viewer", Object: "document:1"},
			want: zanzibar.Relationship{
				Resource: zanzibar.Object{Type: "document", ID: "1"},
				Relation: "viewer",
				Subject:  zanzibar.Subject{Object: zanzibar.Object{Type: "user", ID: zanzibar.WildcardID}},
				Position: pos,
			},
		},
		{
			name: "a condition and its context",
			key: &openfgav1.TupleKey{User: "user:alice", Relation: "viewer", Object: "document:1",
				Condition: &openfgav1.RelationshipCondition{Name: "under_ten", Context: context}},
			want: zanzibar.Relationship{
				Resource: zanzibar.Object{Type: "document", ID: "1"},
				Relation: "viewer",
				Subject:  zanzibar.Subject{Object: zanzibar.Object{Type: "user", ID: "alice"}},
				Caveat:   &zanzibar.CaveatUse{Name: "under_ten", Context: map[string]any{"age": float64(3)}},
				Position: pos,
			},
		},
		{
			// OpenFGA evaluates an inline expression against the context of the check
			// alone, so a value written beside the expression counts for nothing and
			// must not reach the merge a check does.
			name: "an inline condition keeps the expression and its parameters",
			key: &openfgav1.TupleKey{User: "user:alice", Relation: "viewer", Object: "document:1",
				Condition: &openfgav1.RelationshipCondition{Name: "$expression", Context: inline}},
			want: zanzibar.Relationship{
				Resource: zanzibar.Object{Type: "document", ID: "1"},
				Relation: "viewer",
				Subject:  zanzibar.Subject{Object: zanzibar.Object{Type: "user", ID: "alice"}},
				Caveat: &zanzibar.CaveatUse{Name: "$expression", Context: map[string]any{
					"expression": "true",
					"parameters": map[string]any{"x": "int"},
				}},
				Position: pos,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := LowerTuple(pos, tt.key); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LowerTuple() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// Admit asks what a write of OpenFGA asks. The form of the subject and the condition
// are one question: a relation that admits user with a condition does not admit user
// without one, nor user:* with it.
func TestAdmit(t *testing.T) {
	s := compile(t, `model
  schema 1.1
type user
type group
  relations
    define member: [user]
type folder
type document
  relations
    define parent: [folder]
    define plain: [user]
    define conditioned: [user with under_ten]
    define wild: [user:*]
    define grouped: [group#member]
    define inline: [user with $expression]
    define can_read: plain

condition under_ten(age: int) {
  age < 10
}
`)
	rel := func(relation, user string, caveat *zanzibar.CaveatUse) zanzibar.Relationship {
		key := &openfgav1.TupleKey{User: user, Relation: relation, Object: "document:1"}
		r := LowerTuple(zanzibar.Position{}, key)
		r.Caveat = caveat
		return r
	}
	underTen := func(values map[string]any) *zanzibar.CaveatUse {
		return &zanzibar.CaveatUse{Name: "under_ten", Context: values}
	}

	tests := []struct {
		name string
		r    zanzibar.Relationship
		ok   bool
	}{
		{name: "an allowed object", r: rel("plain", "user:alice", nil), ok: true},
		{name: "a type it does not allow", r: rel("plain", "group:g", nil)},
		{name: "a userset of an object relation", r: rel("plain", "group:g#member", nil)},
		{name: "a wildcard of an object relation", r: rel("plain", "user:*", nil)},
		{name: "an allowed wildcard", r: rel("wild", "user:*", nil), ok: true},
		{name: "an object of a wildcard relation", r: rel("wild", "user:alice", nil)},
		{name: "an allowed userset", r: rel("grouped", "group:g#member", nil), ok: true},
		{name: "another userset", r: rel("grouped", "group:g#other", nil)},
		{name: "a walked relation", r: rel("parent", "folder:f", nil), ok: true},
		{name: "a computed relation takes no tuples", r: rel("can_read", "user:alice", nil)},
		{name: "a relation nobody declared", r: rel("nope", "user:alice", nil)},
		{name: "a condition it requires", r: rel("conditioned", "user:alice", underTen(nil)), ok: true},
		{name: "without the condition it requires", r: rel("conditioned", "user:alice", nil)},
		{name: "a condition it does not admit", r: rel("plain", "user:alice", underTen(nil))},
		{name: "a parameter the writer fills", r: rel("conditioned", "user:alice", underTen(map[string]any{"age": 3})), ok: true},
		{name: "a parameter the condition does not declare", r: rel("conditioned", "user:alice", underTen(map[string]any{"other": 3}))},
		{name: "a value of the wrong type", r: rel("conditioned", "user:alice", underTen(map[string]any{"age": "old"}))},
		{name: "an inline expression", r: rel("inline", "user:alice", &zanzibar.CaveatUse{Name: "$expression", Context: map[string]any{"expression": "true"}}), ok: true},
		{name: "a type nobody declared", r: zanzibar.Relationship{Resource: zanzibar.Object{Type: "nope", ID: "1"}, Relation: "plain"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := s.Admit(tt.r)
			if tt.ok && err != nil {
				t.Errorf("Admit() error = %v", err)
			}
			if !tt.ok && !errors.Is(err, ErrTuple) {
				t.Errorf("Admit() error = %v, want ErrTuple", err)
			}
		})
	}
}
