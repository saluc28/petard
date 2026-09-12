package opaengine

import (
	"slices"
	"testing"
)

// The conditions below are the ones the fixture actually produces, copied from
// a run rather than imagined: the evaluator writes the ground side first as
// often as it writes it second, and a reader matching strings would have got
// half of them.
func TestBindingsOf(t *testing.T) {
	tests := []struct {
		name        string
		condition   string
		paths       []string
		expected    map[string][]string
		unexplained int
	}{
		{
			name:      "the ground side comes first",
			condition: `"d-t11-1" = input.doc`,
			paths:     []string{"input.doc"},
			expected:  map[string][]string{"input.doc": {"d-t11-1"}},
		},
		{
			name:      "the ground side comes second",
			condition: `input.action = "read"`,
			paths:     []string{"input.action"},
			expected:  map[string][]string{"input.action": {"read"}},
		},
		{
			name:      "a condition that pins two parts of the request",
			condition: `input.action = "read"; "d-t11-1" = input.doc`,
			paths:     []string{"input.doc", "input.action"},
			expected:  map[string][]string{"input.doc": {"d-t11-1"}, "input.action": {"read"}},
		},
		{
			// The half about a second factor is the half that decides whether
			// the capability is one, so it has to be counted rather than
			// dropped.
			name:        "a condition that asks for something else too",
			condition:   `input.action = "read"; input.mfa`,
			paths:       []string{"input.action"},
			expected:    map[string][]string{"input.action": {"read"}},
			unexplained: 1,
		},
		{
			name:        "a part the condition says nothing about",
			condition:   `input.action = "read"`,
			paths:       []string{"input.doc"},
			expected:    map[string][]string{},
			unexplained: 1,
		},
		{
			// The two have to agree, and which value they agree on is not in
			// the condition. Naming one would be an invention.
			name:        "a condition tying two parts of the request together",
			condition:   `input.doc = input.other`,
			paths:       []string{"input.doc"},
			expected:    map[string][]string{},
			unexplained: 1,
		},
		{
			name:        "a condition that is not an equality",
			condition:   `input.count > 3`,
			paths:       []string{"input.count"},
			expected:    map[string][]string{},
			unexplained: 1,
		},
		{
			// A negated equality says which value is refused, not which is
			// allowed, and reporting it would turn a denial into a capability.
			name:        "a negated equality",
			condition:   `not "berq" = input.tenant`,
			paths:       []string{"input.tenant"},
			expected:    map[string][]string{},
			unexplained: 1,
		},
		{
			name:      "a number",
			condition: `input.level = 3`,
			paths:     []string{"input.level"},
			expected:  map[string][]string{"input.level": {"3"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bindings, err := BindingsOf(tt.condition, tt.paths...)
			if err != nil {
				t.Fatalf("BindingsOf() error = %v", err)
			}
			if bindings.Unexplained != tt.unexplained {
				t.Errorf("unexplained = %d, want %d", bindings.Unexplained, tt.unexplained)
			}
			if len(bindings.Values) != len(tt.expected) {
				t.Fatalf("values = %v, want %v", bindings.Values, tt.expected)
			}
			for path, expected := range tt.expected {
				if !slices.Equal(bindings.Values[path], expected) {
					t.Errorf("values[%s] = %v, want %v", path, bindings.Values[path], expected)
				}
			}
		})
	}
}

func TestBindingsOfRejectsWhatItCannotRead(t *testing.T) {
	if _, err := BindingsOf("input.doc =", "input.doc"); err == nil {
		t.Error("a condition that does not parse was accepted")
	}
	if _, err := BindingsOf(`input.doc = "d-1"`, "input doc"); err == nil {
		t.Error("a path that is not a reference was accepted")
	}
}
