package spicedb

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/saluc28/petard/internal/zanzibar"
)

// fixtureProof is the proof of one escalation of the SpiceDB fixture.
type fixtureProof struct {
	heading string
	proof   *zanzibar.Proof
}

// fixtureProofs are the proofs of every escalation the fixture holds, with the schema
// they were found in. Every escalation of the fixture has one.
func fixtureProofs(t *testing.T) (*Schema, []fixtureProof) {
	t.Helper()
	f := findOne(t, fixtureValidation)
	wm, err := zanzibar.LoadWriteModel(fixtureWrites)
	if err != nil {
		t.Fatal(err)
	}
	var out []fixtureProof
	for _, m := range zanzibar.Run(f.Sample(time.Now()), wm) {
		if m.Raise == nil {
			continue
		}
		heading := m.PatternID + " " + m.Subject
		if m.Raise.Proof == nil {
			t.Fatalf("%s has no proof: %s", heading, m.Raise.NoProof)
		}
		out = append(out, fixtureProof{heading: heading, proof: m.Raise.Proof})
	}
	if len(out) == 0 {
		t.Fatal("the fixture has no escalation")
	}
	return f.Schema, out
}

// writeProof writes the files of a proof under dir and returns their paths.
func writeProof(t *testing.T, s *Schema, dir, name string, p *zanzibar.Proof) []string {
	t.Helper()
	files, err := s.ProofFiles(dir, name, []string{"A proof."}, p)
	if err != nil {
		t.Fatalf("ProofFiles(%s): %v", name, err)
	}
	paths := make([]string, 0, len(files))
	for _, f := range files {
		full := filepath.Join(dir, filepath.FromSlash(f.Path))
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, f.Content, 0o600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, full)
	}
	return paths
}

// The files of a proof read back as the proof they were written from: each holds the
// relationships of its state, and asserts each check of the state at the level the
// engine expects, which the engine gives again over what the file holds.
func TestProofFilesReadBackAsTheProof(t *testing.T) {
	schema, proofs := fixtureProofs(t)
	dir := t.TempDir()
	for i, fp := range proofs {
		paths := writeProof(t, schema, dir, "p"+string(rune('a'+i)), fp.proof)
		if len(paths) != len(fp.proof.States) {
			t.Fatalf("%s: %d files for %d states", fp.heading, len(paths), len(fp.proof.States))
		}
		for j, path := range paths {
			state := fp.proof.States[j]
			read := findOne(t, path)
			if got, want := relationshipTexts(t, read.Relationships), relationshipTexts(t, state.Relationships); !slices.Equal(got, want) {
				t.Errorf("%s, %s: reads back %v, want %v", fp.heading, path, got, want)
			}
			var asked []string
			for _, c := range state.Checks {
				asked = append(asked, c.String()+" "+c.Level.String())
			}
			var got []string
			checker := zanzibar.NewChecker(read.Schema.Model, read.Relationships, read.Schema, time.Now())
			for _, a := range read.Assertions {
				got = append(got, a.String()+" "+a.Level.String())
				answer, err := checker.Check(a.Resource, a.Name, a.Subject, a.Context)
				if err != nil {
					t.Fatal(err)
				}
				if answer.Level != a.Level {
					t.Errorf("%s, %s: asserts %s %v and the engine gives %v over the file", fp.heading, path, a, a.Level, answer.Level)
				}
			}
			slices.Sort(asked)
			slices.Sort(got)
			if !slices.Equal(got, asked) {
				t.Errorf("%s, %s: asserts %v, want %v", fp.heading, path, got, asked)
			}
		}
	}
}

// relationshipTexts are relationships as SpiceDB writes them, caveat and expiration
// included, so two lists compare on everything a relationship holds.
func relationshipTexts(t *testing.T, rels []zanzibar.Relationship) []string {
	t.Helper()
	out := make([]string, 0, len(rels))
	for _, r := range rels {
		text, err := relationshipText(r)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, text)
	}
	slices.Sort(out)
	return out
}

// The proofs against SpiceDB itself: zed validate passes on every proof of the fixture,
// and fails on each once its last state holds the store before the writes, so a proof
// that passes says what the writes do and not what the store already held.
func TestOracleProofs(t *testing.T) {
	zed := os.Getenv(zedEnv)
	if zed == "" {
		t.Skipf("%s is not set: the oracle needs the zed binary", zedEnv)
	}
	schema, proofs := fixtureProofs(t)
	dir := t.TempDir()
	for i, fp := range proofs {
		name := "p" + string(rune('a'+i))
		if out, err := exec.Command(zed, append([]string{"validate"}, writeProof(t, schema, dir, name, fp.proof)...)...).CombinedOutput(); err != nil {
			t.Errorf("%s: zed validate fails: %v\n%s", fp.heading, err, tail(out))
		}

		undone := *fp.proof
		undone.States = slices.Clone(fp.proof.States)
		last := len(undone.States) - 1
		undone.States[last].Relationships = undone.States[0].Relationships
		if out, err := exec.Command(zed, append([]string{"validate"}, writeProof(t, schema, dir, name+"-undone", &undone)...)...).CombinedOutput(); err == nil {
			t.Errorf("%s: zed validate passes without the writes\n%s", fp.heading, tail(out))
		}
	}
}

// What SpiceDB asks of a relationship before it stores one is what a proof asks of the
// relationships it writes.
func TestAdmit(t *testing.T) {
	schema, err := Compile("admit.zed", nil, 1, `use expiration

caveat open(allowed bool) {
	allowed
}

definition user {}

definition group {
	relation member: user
}

definition document {
	relation viewer: user | user:* | group#member | user with open
	relation editor: user with expiration
	relation owner: user with open
	permission view = viewer + editor + owner
}`)
	if err != nil {
		t.Fatal(err)
	}
	tomorrow := time.Now().Add(24 * time.Hour)
	tuple := func(subject string, caveat *zanzibar.CaveatUse, expires *time.Time, relation string) zanzibar.Relationship {
		r := zanzibar.Relationship{Resource: zanzibar.Object{Type: "document", ID: "readme"}, Relation: relation, Caveat: caveat, Expires: expires}
		typ, rest, _ := strings.Cut(subject, ":")
		id, userset, _ := strings.Cut(rest, "#")
		r.Subject = zanzibar.Subject{Object: zanzibar.Object{Type: typ, ID: id}, Relation: userset}
		return r
	}
	tests := []struct {
		name     string
		r        zanzibar.Relationship
		expected string
	}{
		{name: "a plain subject", r: tuple("user:alice", nil, nil, "viewer")},
		{name: "a wildcard", r: tuple("user:*", nil, nil, "viewer")},
		{name: "a userset", r: tuple("group:eng#member", nil, nil, "viewer")},
		{name: "a caveat with its context", r: tuple("user:alice", &zanzibar.CaveatUse{Name: "open", Context: map[string]any{"allowed": true}}, nil, "viewer")},
		{name: "a caveat without a context", r: tuple("user:alice", &zanzibar.CaveatUse{Name: "open"}, nil, "viewer")},
		{name: "an expiration", r: tuple("user:alice", nil, &tomorrow, "editor")},
		{name: "a permission", r: tuple("user:alice", nil, nil, "view"), expected: "is not a relation"},
		{name: "a type the relation does not allow", r: tuple("group:eng", nil, nil, "viewer"), expected: "does not allow this subject without a caveat"},
		{name: "no expiration where one is required", r: tuple("user:alice", nil, nil, "editor"), expected: "does not allow this subject without a caveat"},
		{name: "no caveat where one is required", r: tuple("user:alice", nil, nil, "owner"), expected: "does not allow this subject without a caveat"},
		{name: "a caveat the relation does not allow", r: tuple("user:alice", &zanzibar.CaveatUse{Name: "open"}, nil, "editor"), expected: "with caveat open"},
		{name: "a context of the wrong type", r: tuple("user:alice", &zanzibar.CaveatUse{Name: "open", Context: map[string]any{"allowed": "yes"}}, nil, "viewer"), expected: "allowed"},
		{name: "a context naming no parameter", r: tuple("user:alice", &zanzibar.CaveatUse{Name: "open", Context: map[string]any{"other": true}}, nil, "viewer"), expected: "other"},
		{name: "a resource identifier SpiceDB cannot store", r: zanzibar.Relationship{Resource: zanzibar.Object{Type: "document", ID: "read me"}, Relation: "viewer", Subject: zanzibar.Subject{Object: zanzibar.Object{Type: "user", ID: "alice"}}}, expected: "resource id"},
		{name: "a subject identifier a validation file cannot hold", r: tuple("user:al ice", nil, nil, "viewer"), expected: "cannot hold it"},
		{name: "an undefined subject type", r: tuple("team:eng", nil, nil, "viewer"), expected: "the subject is not defined"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := schema.Admit(tt.r)
			switch {
			case tt.expected == "" && err != nil:
				t.Errorf("Admit(%s) = %v, want nil", tt.r, err)
			case tt.expected != "" && (err == nil || !strings.Contains(err.Error(), tt.expected)):
				t.Errorf("Admit(%s) = %v, want an error saying %q", tt.r, err, tt.expected)
			case err != nil && !errors.Is(err, ErrProof):
				t.Errorf("Admit(%s) = %v, want it to wrap %v", tt.r, err, ErrProof)
			}
		})
	}
}

// SpiceDB follows a loop of relationships to its depth limit and fails the check where
// it waits for every result, so a proof whose store holds a loop a check can follow is
// not written. A loop no check reaches, or one through a relation no arrow walks, which a
// check never follows, does not stop it.
func TestAProofThroughALoopIsNotWritten(t *testing.T) {
	schema, err := Compile("loop.zed", nil, 1, `definition user {}

definition session {
	relation owner: user
	relation parent: session
	relation child: session
	permission approve = owner + parent->approve
}`)
	if err != nil {
		t.Fatal(err)
	}
	link := func(child, parent string) zanzibar.Relationship {
		return zanzibar.Relationship{
			Resource: zanzibar.Object{Type: "session", ID: child},
			Relation: "parent",
			Subject:  zanzibar.Subject{Object: zanzibar.Object{Type: "session", ID: parent}},
		}
	}
	ask := zanzibar.ProofCheck{Assertion: zanzibar.Assertion{
		Resource: zanzibar.Object{Type: "session", ID: "p"},
		Name:     "approve",
		Subject:  zanzibar.Subject{Object: zanzibar.Object{Type: "user", ID: "bob"}},
	}}
	proof := func(rels ...zanzibar.Relationship) *zanzibar.Proof {
		return &zanzibar.Proof{States: []zanzibar.ProofState{{Relationships: rels, Checks: []zanzibar.ProofCheck{ask}}}}
	}

	if _, err := schema.ProofFiles("proofs", "loop", nil, proof(link("p", "c"), link("c", "p"))); err == nil || !strings.Contains(err.Error(), "loop") {
		t.Errorf("a loop the check reaches: %v, want an error naming the loop", err)
	}
	if _, err := schema.ProofFiles("proofs", "aside", nil, proof(link("p", "c"), link("x", "y"), link("y", "x"))); err != nil {
		t.Errorf("a loop no check reaches: %v, want the proof written", err)
	}
	child := zanzibar.Relationship{
		Resource: zanzibar.Object{Type: "session", ID: "c"},
		Relation: "child",
		Subject:  zanzibar.Subject{Object: zanzibar.Object{Type: "session", ID: "p"}},
	}
	if _, err := schema.ProofFiles("proofs", "child", nil, proof(link("p", "c"), child)); err != nil {
		t.Errorf("a loop through a relation no arrow walks: %v, want the proof written", err)
	}
}

// An empty line of a comment loses the space the generator leaves after //, and nothing
// else on any line changes.
func TestTrimComments(t *testing.T) {
	text := "// a comment\n// \ndefinition user {} \n\t// \ncaveat c(x int) {\n\tx > 1 \n}"
	want := "// a comment\n//\ndefinition user {} \n\t//\ncaveat c(x int) {\n\tx > 1 \n}"
	if got := trimComments(text); got != want {
		t.Errorf("trimComments = %q, want %q", got, want)
	}
}
