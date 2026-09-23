package opaengine

import "testing"

// The counts are asserted one by one rather than as a whole struct, because a
// single wrong number should name itself: a diff of two structs says the
// bundle is not the bundle, which is the least useful thing it could say.
func TestBundleConstructs(t *testing.T) {
	dir := writeSources(t, map[string]string{
		"policy.rego": `package t

# METADATA
# scope: document
# entrypoint: true
default allow := false

allow if {
	not blocked
	count(owned) > 0
	every doc in data.documents { doc.classification != "secret" }
	active(input.user)
}

blocked if data.blocklist[input.user]

owned := [doc | some doc in data.documents; doc.owner == input.user]

active(user) if data.users[user].active

measure if allow with input as {"user": "mallory"}
`,
	})
	bundle, err := Load([]string{dir}, ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	counts := bundle.Constructs()
	expected := []struct {
		name string
		got  int
		want int
	}{
		{"Packages", counts.Packages, 1},
		{"Rules", counts.Rules, 6},
		{"Functions", counts.Functions, 1},
		{"With", counts.With, 1},
		{"Every", counts.Every, 1},
		{"Comprehensions", counts.Comprehensions, 1},
		{"Negations", counts.Negations, 1},
		{"Defaults", counts.Defaults, 1},
	}
	for _, count := range expected {
		if count.got != count.want {
			t.Errorf("Constructs().%s = %d, want %d", count.name, count.got, count.want)
		}
	}
}

// With the not keyword imported, a negation holds a body of its own instead of
// carrying a flag, the plain form included, and it is counted all the same.
func TestBundleConstructsCountANotWithABody(t *testing.T) {
	dir := writeSources(t, map[string]string{
		"policy.rego": `package t

import future.keywords.not

allow if {
	not data.blocklist[input.user]
	not {
		data.suspended[input.user]
		input.strict
	}
}
`,
	})
	bundle, err := Load([]string{dir}, ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got := bundle.Constructs().Negations; got != 2 {
		t.Errorf("Constructs().Negations = %d, want 2", got)
	}
}
