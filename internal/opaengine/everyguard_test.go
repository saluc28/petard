package opaengine

import (
	"errors"
	"strings"
	"testing"
)

// lineOf returns the line a piece of text sits on in a policy, counted from 1.
func lineOf(t *testing.T, policy, text string) int {
	t.Helper()

	before, _, found := strings.Cut(policy, text)
	if !found {
		t.Fatalf("the policy does not hold %q", text)
	}
	return strings.Count(before, "\n") + 1
}

// policyFile is the file a bundle of one policy was loaded from, as the
// expressions of that policy carry it.
func policyFile(t *testing.T, bundle *Bundle) string {
	t.Helper()

	if len(bundle.Files) != 1 {
		t.Fatalf("files = %v, want the one policy", bundle.Files)
	}
	return bundle.Files[0]
}

const mergePolicy = `package merge

# METADATA
# entrypoint: true
default allow := false

allow if {
	input.author != ""
	every review in input.reviews {
		review.approved
	}
}

# METADATA
# entrypoint: true
default allow_listed := false

allow_listed if {
	listed := [review | some review in input.reviews; every flag in review.flags { flag != "blocker" }]
	count(listed) > 0
}
`

// The copy differs from the policy in one thing: the every at the place named
// does not hold over an empty domain. With an element in the domain it answers
// as the policy does, and the policy it was copied from is left as it was.
func TestWithGuardedEvery(t *testing.T) {
	bundle := bundleDeclaring(t, mergePolicy, nil, nil)
	file := policyFile(t, bundle)

	guarded, err := bundle.WithGuardedEvery(EveryPlace{File: file, Line: lineOf(t, mergePolicy, "every review in input.reviews")})
	if err != nil {
		t.Fatalf("WithGuardedEvery() error = %v", err)
	}

	tests := []struct {
		name    string
		input   map[string]any
		asIs    bool
		guarded bool
	}{
		{"no review at all", map[string]any{"author": "alice", "reviews": []any{}}, true, false},
		{"an object with nothing in it", map[string]any{"author": "alice", "reviews": map[string]any{}}, true, false},
		{"one approved review", map[string]any{"author": "alice", "reviews": []any{map[string]any{"approved": true}}}, true, true},
		{"one review that does not approve", map[string]any{"author": "alice", "reviews": []any{map[string]any{"approved": false}}}, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for name, ask := range map[string]struct {
				bundle *Bundle
				want   bool
			}{"the policy": {bundle, tt.asIs}, "the copy": {guarded, tt.guarded}} {
				holds, err := Holds(t.Context(), ask.bundle, NoData(), "data.merge.allow", tt.input)
				if err != nil {
					t.Fatalf("Holds() error = %v", err)
				}
				if holds != ask.want {
					t.Errorf("%s grants %t, want %t", name, holds, ask.want)
				}
			}
		})
	}

	if _, err := bundle.WithGuardedEvery(EveryPlace{File: file, Line: 1}); !errors.Is(err, ErrNoSuchEvery) {
		t.Errorf("WithGuardedEvery() at a line with no every, error = %v, want ErrNoSuchEvery", err)
	}
}

// An every inside a comprehension is guarded where it sits, in the body of the
// comprehension, and the rule around it is untouched.
func TestWithGuardedEveryInsideAComprehension(t *testing.T) {
	bundle := bundleDeclaring(t, mergePolicy, nil, nil)
	guarded, err := bundle.WithGuardedEvery(EveryPlace{File: policyFile(t, bundle), Line: lineOf(t, mergePolicy, "every flag in review.flags")})
	if err != nil {
		t.Fatalf("WithGuardedEvery() error = %v", err)
	}

	// A review with no flag is listed by the policy, vacuously, and not by the
	// copy. A review with a harmless flag is listed by both.
	unflagged := map[string]any{"reviews": []any{map[string]any{"flags": []any{}}}}
	flagged := map[string]any{"reviews": []any{map[string]any{"flags": []any{"nit"}}}}
	for _, ask := range []struct {
		name   string
		bundle *Bundle
		input  map[string]any
		want   bool
	}{
		{"the policy, a review with no flag", bundle, unflagged, true},
		{"the copy, a review with no flag", guarded, unflagged, false},
		{"the policy, a review with a flag", bundle, flagged, true},
		{"the copy, a review with a flag", guarded, flagged, true},
	} {
		holds, err := Holds(t.Context(), ask.bundle, NoData(), "data.merge.allow_listed", ask.input)
		if err != nil {
			t.Fatalf("%s: Holds() error = %v", ask.name, err)
		}
		if holds != ask.want {
			t.Errorf("%s: granted %t, want %t", ask.name, holds, ask.want)
		}
	}
}

// Several places are guarded in one copy, and a place with no every in it is an
// error whatever the others hold.
func TestWithGuardedEveryAtSeveralPlaces(t *testing.T) {
	bundle := bundleDeclaring(t, mergePolicy, nil, nil)
	file := policyFile(t, bundle)
	reviews := EveryPlace{File: file, Line: lineOf(t, mergePolicy, "every review in input.reviews")}
	flags := EveryPlace{File: file, Line: lineOf(t, mergePolicy, "every flag in review.flags")}

	guarded, err := bundle.WithGuardedEvery(reviews, flags)
	if err != nil {
		t.Fatalf("WithGuardedEvery() error = %v", err)
	}
	// Each decision is granted by the policy on the vacuous truth of its own
	// every, and by the copy on neither.
	for decision, input := range map[string]map[string]any{
		"data.merge.allow":        {"author": "alice", "reviews": []any{}},
		"data.merge.allow_listed": {"reviews": []any{map[string]any{"flags": []any{}}}},
	} {
		for name, ask := range map[string]struct {
			bundle *Bundle
			want   bool
		}{"the policy": {bundle, true}, "the copy": {guarded, false}} {
			holds, err := Holds(t.Context(), ask.bundle, NoData(), decision, input)
			if err != nil {
				t.Fatalf("Holds(%s) error = %v", decision, err)
			}
			if holds != ask.want {
				t.Errorf("%s grants %s: %t, want %t", name, decision, holds, ask.want)
			}
		}
	}

	if _, err := bundle.WithGuardedEvery(reviews, EveryPlace{File: file, Line: 1}); !errors.Is(err, ErrNoSuchEvery) {
		t.Errorf("WithGuardedEvery() with a place that holds no every, error = %v, want ErrNoSuchEvery", err)
	}
}

// A decision that answers with a value is the same when the value is, and not
// when it is merely defined in both.
func TestSameAnswer(t *testing.T) {
	const policy = `package merge

# METADATA
# entrypoint: true
report := {"compliant": approved}

default approved := false

approved if {
	every review in input.reviews {
		review.approved
	}
}
`
	bundle := bundleDeclaring(t, policy, nil, nil)
	guarded, err := bundle.WithGuardedEvery(EveryPlace{File: policyFile(t, bundle), Line: lineOf(t, policy, "every review")})
	if err != nil {
		t.Fatalf("WithGuardedEvery() error = %v", err)
	}

	for name, tt := range map[string]struct {
		input map[string]any
		same  bool
	}{
		"no review, compliant in the policy alone": {map[string]any{"reviews": []any{}}, false},
		"an approved review, compliant in both":    {map[string]any{"reviews": []any{map[string]any{"approved": true}}}, true},
		"a rejected review, compliant in neither":  {map[string]any{"reviews": []any{map[string]any{"approved": false}}}, true},
	} {
		same, err := SameAnswer(t.Context(), bundle, guarded, NoData(), "data.merge.report", tt.input)
		if err != nil {
			t.Fatalf("%s: SameAnswer() error = %v", name, err)
		}
		if same != tt.same {
			t.Errorf("%s: same = %t, want %t", name, same, tt.same)
		}
	}
}

// What partial evaluation leaves is compared whole, and an answer that still
// names a rule the copy changed is not shown equal, however alike the two
// read.
func TestSameResiduals(t *testing.T) {
	tests := []struct {
		name   string
		policy string
		every  string
		input  map[string]any
		same   bool
	}{
		{
			// The release manager is granted either way, and the developer in
			// neither: the guard next to the every already refuses no review.
			name: "a guarded every, next to a rule that grants anyway",
			policy: `package merge

# METADATA
# entrypoint: true
default allow := false

allow if input.role == "release-manager"

allow if {
	input.reviews[_]
	every review in input.reviews {
		review.approved
	}
}
`,
			every: "every review",
			input: map[string]any{"reviews": []any{}},
			same:  true,
		},
		{
			name: "an every nothing guards",
			policy: `package merge

# METADATA
# entrypoint: true
default allow := false

allow if {
	input.author != ""
	every review in input.reviews {
		review.approved
	}
}
`,
			every: "every review",
			input: map[string]any{"reviews": []any{}},
			same:  false,
		},
		{
			// The comprehension comes back as it is written on both sides, and the
			// rule it names is the one the copy changed.
			name: "a comprehension that names the rule with the every",
			policy: `package merge

# METADATA
# entrypoint: true
score := count([check |
	checks := [staffed, approved]
	check := checks[_]
	check == true
])

staffed if input.author != ""

approved if {
	every review in input.reviews {
		review.approved
	}
}
`,
			every: "every review",
			input: map[string]any{"reviews": []any{}},
			same:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bundle := bundleDeclaring(t, tt.policy, nil, nil)
			guarded, err := bundle.WithGuardedEvery(EveryPlace{File: policyFile(t, bundle), Line: lineOf(t, tt.policy, tt.every)})
			if err != nil {
				t.Fatalf("WithGuardedEvery() error = %v", err)
			}
			reads, err := Reads(bundle, Limits{})
			if err != nil {
				t.Fatalf("Reads() error = %v", err)
			}
			var unknowns []string
			for _, path := range reads.InputPaths {
				if !strings.HasPrefix(path, "input.reviews") {
					unknowns = append(unknowns, path)
				}
			}

			same, err := SameResiduals(t.Context(), bundle, guarded, NoData(),
				Request{Decision: reads.Decisions[0], Unknowns: unknowns, Input: tt.input})
			if err != nil {
				t.Fatalf("SameResiduals() error = %v", err)
			}
			if same != tt.same {
				t.Errorf("same = %t, want %t", same, tt.same)
			}

			// A bundle is the same as itself, whatever it holds.
			if same, err := SameResiduals(t.Context(), bundle, bundle, NoData(),
				Request{Decision: reads.Decisions[0], Unknowns: unknowns, Input: tt.input}); err != nil || !same {
				t.Errorf("the policy against itself: same = %t, error = %v, want it equal", same, err)
			}
		})
	}
}

// A path the policy builds is told from one the documents hold, whichever
// element of it is asked about.
func TestBundleComputes(t *testing.T) {
	const policy = `package app

required := {"lint", "test"}

by_team[team] := checks if {
	some team, checks in data.teams
}

# METADATA
# entrypoint: true
allow if input.user
`
	bundle := bundleDeclaring(t, policy, nil, nil)
	for path, computed := range map[string]bool{
		"data.app.required":   true,
		"data.app.by_team[_]": true,
		"data.teams":          false,
		"data.teams[_]":       false,
		"input.user":          false,
		"data.app.":           false,
	} {
		if got := bundle.Computes(path); got != computed {
			t.Errorf("Computes(%s) = %t, want %t", path, got, computed)
		}
	}
}
