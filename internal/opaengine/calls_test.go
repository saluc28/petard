package opaengine

import (
	"slices"
	"strings"
	"testing"
)

// TestReadsResolveThroughCallSites is the reason calls.go exists.
//
// is_member(user, proj) reads the profile of "user", and nothing in its body
// says who that is: the answer is in allow, which calls it with input.user.
// The fixture is written this way on purpose, because using a function is the
// normal way to write that policy, and it is the chain EXPECTED.md calls the
// central criterion.
func TestReadsResolveThroughCallSites(t *testing.T) {
	bundle, err := Load([]string{fixtureDir(t, "policy-v1")}, ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	reads, err := Reads(bundle, Limits{})
	if err != nil {
		t.Fatalf("Reads() error = %v", err)
	}

	var found bool
	for _, read := range reads.Reads {
		if read.Rule != "data.quill.authz.is_member" || read.Path != "data.users[_].profile.department" {
			continue
		}
		found = true

		if read.Provenance != ProvenanceInput {
			t.Errorf("provenance = %s, want input: the caller passes input.user", read.Provenance)
		}
		if read.Trace == nil {
			t.Fatal("no trace: the claim about input has to say where it comes from")
		}
		if !slices.Equal(read.Trace.Callers, []string{"data.quill.authz.allow"}) {
			t.Errorf("callers = %v, want [data.quill.authz.allow]", read.Trace.Callers)
		}
		if read.Trace.Term != "input.user" {
			t.Errorf("term = %q, want input.user: naming the field is what a pattern needs", read.Trace.Term)
		}
	}
	if !found {
		t.Fatal("the read inside is_member is missing")
	}
}

// A parameter passed on from one function to the next is the case a single hop
// would get wrong, and it is what makes this a walk rather than a lookup.
func TestParameterProvenanceWalksUpTheChain(t *testing.T) {
	reads := readsOf(t, `package t

# METADATA
# scope: document
# entrypoint: true
default allow := false

allow if outer(input.user)

outer(u) if inner(u)

inner(u) if data.users[u].active
`, Limits{})

	read := readOfRule(t, reads, "data.t.inner")
	if read.Provenance != ProvenanceInput {
		t.Errorf("provenance = %s, want input", read.Provenance)
	}
	if read.Trace == nil {
		t.Fatal("no trace")
	}
	if !slices.Equal(read.Trace.Callers, []string{"data.t.outer", "data.t.allow"}) {
		t.Errorf("callers = %v, want [data.t.outer data.t.allow]", read.Trace.Callers)
	}
	if read.Trace.Term != "input.user" {
		t.Errorf("term = %q, want input.user", read.Trace.Term)
	}
}

// A caller that passes a constant is not a caller that passes the request:
// the read names the same document every time, and saying "input" there would
// invent a way in.
func TestParameterProvenanceOfAConstantArgument(t *testing.T) {
	reads := readsOf(t, `package t

# METADATA
# scope: document
# entrypoint: true
default allow := false

allow if member("root")

member(p) if data.projects[p].members
`, Limits{})

	if read := readOfRule(t, reads, "data.t.member"); read.Provenance != ProvenanceStatic {
		t.Errorf("provenance = %s, want static", read.Provenance)
	}
}

// Reaching a limit is not an answer, and it must not look like one. The read
// stays unresolved and the run says which bound stopped it and how to raise
// it.
func TestLimitsStopTheWalkWithAWarning(t *testing.T) {
	const policy = `package t

# METADATA
# scope: document
# entrypoint: true
default allow := false

allow if outer(input.user)

outer(u) if inner(u)

inner(u) if data.users[u].active
`

	reads := readsOf(t, policy, Limits{MaxCallDepth: 1})

	if read := readOfRule(t, reads, "data.t.inner"); read.Provenance != ProvenanceUnresolved {
		t.Errorf("provenance = %s, want unresolved: one call is not enough to reach input", read.Provenance)
	}
	if len(reads.Warnings) == 0 {
		t.Fatal("no warning: a bound that stops the analysis has to say so")
	}
	warning := reads.Warnings[0]
	for _, expected := range []string{"MaxCallDepth", "data.t.outer"} {
		if !strings.Contains(warning, expected) {
			t.Errorf("warning %q does not mention %s", warning, expected)
		}
	}
}

func TestLimitsFallBackToDefaults(t *testing.T) {
	var zero Limits
	if got := zero.maxCallDepth(); got != defaultMaxCallDepth {
		t.Errorf("maxCallDepth() = %d, want %d", got, defaultMaxCallDepth)
	}
	if got := zero.maxCallPaths(); got != defaultMaxCallPaths {
		t.Errorf("maxCallPaths() = %d, want %d", got, defaultMaxCallPaths)
	}

	set := Limits{MaxCallDepth: 2, MaxCallPaths: 3}
	if got := set.maxCallDepth(); got != 2 {
		t.Errorf("maxCallDepth() = %d, want 2", got)
	}
	if got := set.maxCallPaths(); got != 3 {
		t.Errorf("maxCallPaths() = %d, want 3", got)
	}
}

// readsOf compiles one policy and returns what its decisions read.
func readsOf(t *testing.T, policy string, limits Limits) *ReadSet {
	t.Helper()

	bundle, err := Load([]string{writeSources(t, map[string]string{"policy.rego": policy})}, ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	reads, err := Reads(bundle, limits)
	if err != nil {
		t.Fatalf("Reads() error = %v", err)
	}
	return reads
}

// readOfRule returns the single read of a rule, failing if there is not
// exactly one.
func readOfRule(t *testing.T, reads *ReadSet, rule string) Read {
	t.Helper()
	return oneRead(t, reads, "rule "+rule, func(read Read) bool { return read.Rule == rule })
}

// readOfPath returns the single read of a path, failing if there is not
// exactly one.
func readOfPath(t *testing.T, reads *ReadSet, path string) Read {
	t.Helper()
	return oneRead(t, reads, "path "+path, func(read Read) bool { return read.Path == path })
}

func oneRead(t *testing.T, reads *ReadSet, what string, matches func(Read) bool) Read {
	t.Helper()

	var found []Read
	for _, read := range reads.Reads {
		if matches(read) {
			found = append(found, read)
		}
	}
	if len(found) != 1 {
		t.Fatalf("reads of %s = %d, want 1 (all reads: %v)", what, len(found), reads.Paths())
	}
	return found[0]
}
