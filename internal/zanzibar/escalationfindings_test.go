package zanzibar

import "testing"

// stepText renders one write of a witness for the evidence view. Each kind of
// step reads differently: a rule write and a delete name the gate they pass, a
// creation names the object it makes, and a tuple a creation writes rides on the
// creation's own gate rather than carrying one of its own.
func TestStepTextDescribesEachKindOfWrite(t *testing.T) {
	tests := []struct {
		name string
		step WriteStep
		want string
	}{
		{
			name: "a rule write names the tuple, the gate and the endpoint",
			step: WriteStep{
				Relationship: rel("document:roadmap", "viewer", "user:*"),
				Rule:         &WriteRule{Gate: Gate{Anyone: true}, Via: "POST /viewers"},
			},
			want: "write document:roadmap#viewer@user:* (anyone, through POST /viewers)",
		},
		{
			name: "a gated write names who holds the gate",
			step: WriteStep{
				Relationship: rel("document:roadmap", "editor", "user:mallory"),
				Rule:         &WriteRule{Gate: Gate{Holds: "view"}},
			},
			want: "write document:roadmap#editor@user:mallory (whoever holds view)",
		},
		{
			name: "a delete says delete",
			step: WriteStep{
				Relationship: rel("document:roadmap", "banned", "user:mallory"),
				Delete:       true,
				Rule:         &WriteRule{Gate: Gate{Anyone: true}},
			},
			want: "delete document:roadmap#banned@user:mallory (anyone)",
		},
		{
			name: "a creation names the object it brings into being",
			step: WriteStep{
				Creation: &CreationRule{Gate: Gate{Anyone: true}, Via: "POST /folders"},
				Created:  object("folder:created-0"),
			},
			want: "create folder:created-0 (anyone, through POST /folders)",
		},
		{
			name: "a tuple a creation writes rides on the creation's gate",
			step: WriteStep{
				Relationship: rel("folder:created-0", "viewer", "user:mallory"),
				Creation:     &CreationRule{Gate: Gate{Anyone: true}, Via: "POST /folders"},
				Created:      object("folder:created-0"),
			},
			want: "write folder:created-0#viewer@user:mallory (anyone, through POST /folders)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := stepText(tt.step); got != tt.want {
				t.Errorf("stepText() = %q, want %q", got, tt.want)
			}
		})
	}
}
