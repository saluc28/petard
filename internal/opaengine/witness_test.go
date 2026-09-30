package opaengine

import (
	"encoding/json"
	"reflect"
	"testing"
)

// A witness is a request that satisfies the readable fields of a way one grant
// has and the other lacks, written over the part of the request the question
// fixed, with each value in the type the policy wrote it in.
func TestWitnessesWriteTheRequestsAGainNeeds(t *testing.T) {
	fixed := map[string]any{"user": "alice"}
	tests := []struct {
		name  string
		grant []string
		other []string
		want  []map[string]any
	}{
		{
			// The readable fields show a delete the other lacks, behind a
			// generated negation that may refuse it: the delete is the request
			// to ask about.
			name: "a way behind a generated negation",
			grant: []string{
				`"read" = input.action; not data.partial.__not1_1_3__`,
				`"delete" = input.action; not data.partial.__not1_1_6__`,
			},
			other: []string{`"read" = input.action; not data.partial.__not1_1_3__`},
			want:  []map[string]any{{"user": "alice", "action": "delete"}},
		},
		{
			name:  "a way the other covers has nothing to prove",
			grant: []string{`"read" = input.action; not data.partial.__not1_1_8__`},
			other: []string{`"read" = input.action; not data.partial.__not1_1_3__`},
			want:  nil,
		},
		{
			name:  "a number stays a number",
			grant: []string{`30 = input.level; not data.partial.__not1_1_3__`},
			other: []string{`10 = input.level`},
			want:  []map[string]any{{"user": "alice", "level": json.Number("30")}},
		},
		{
			// A path held against a list is written element by element, and an
			// element the condition leaves open still has to be there.
			name:  "a path is written as a list",
			grant: []string{`input.path = ["api", "teams", __local1__]; not data.partial.__not1_1_3__`},
			other: []string{`input.path = ["api", "users"]`},
			want:  []map[string]any{{"user": "alice", "path": []any{"api", "teams", "petard"}}},
		},
		{
			name:  "a membership is a list holding the value",
			grant: []string{`"proj-y" = input.projects[_]; not data.partial.__not1_1_3__`},
			other: []string{`"proj-x" = input.projects[_]`},
			want:  []map[string]any{{"user": "alice", "projects": []any{"proj-y"}}},
		},
		{
			// Nothing says what satisfies a truth test, so the field is left
			// out and the evaluation decides.
			name:  "a field read only opaquely is left out",
			grant: []string{`"write" = input.action; input.mfa`},
			other: []string{`"read" = input.action`},
			want:  []map[string]any{{"user": "alice", "action": "write"}},
		},
		{
			name:  "the fixed part of the request is kept",
			grant: []string{`"write" = input.action; "bob" = input.user; not data.partial.__not1_1_3__`},
			other: []string{`"read" = input.action`},
			want:  []map[string]any{{"user": "alice", "action": "write"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GrantContentOf(residual(tt.grant...)).Witnesses(GrantContentOf(residual(tt.other...)), fixed)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Witnesses() = %#v, want %#v", got, tt.want)
			}
		})
	}
	if !reflect.DeepEqual(fixed, map[string]any{"user": "alice"}) {
		t.Errorf("the fixed part of the request was written into: %v", fixed)
	}
}
