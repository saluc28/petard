package openfga

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"github.com/openfga/openfga/pkg/server"
	yaml "go.yaml.in/yaml/v3"

	"github.com/saluc28/petard/internal/zanzibar"
)

// fgaEnv names the fga binary TestOracleProofs runs.
const fgaEnv = "PETARD_FGA"

// fixtureProof is the proof of one escalation of the OpenFGA fixture.
type fixtureProof struct {
	heading string
	proof   *zanzibar.Proof
}

// fixtureProofs are the proofs of every escalation the fixture holds, with its schema.
// Every escalation of the fixture has one.
func fixtureProofs(t *testing.T) (*Schema, []fixtureProof) {
	t.Helper()
	store, wm := fixtureStore(t)
	var out []fixtureProof
	for _, m := range zanzibar.Run(sampleOf(store), wm) {
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
	return store.Schema, out
}

// writeProof writes the store file of a proof under dir and returns its path.
func writeProof(t *testing.T, s *Schema, dir, name string, p *zanzibar.Proof) string {
	t.Helper()
	files, err := s.ProofFiles(dir, name, []string{"A proof."}, p)
	if err != nil {
		t.Fatalf("ProofFiles(%s): %v", name, err)
	}
	if len(files) != 1 {
		t.Fatalf("ProofFiles(%s) writes %d files, want one store file", name, len(files))
	}
	path := filepath.Join(dir, filepath.FromSlash(files[0].Path))
	if err := os.WriteFile(path, files[0].Content, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// undone is a proof whose last state holds the store before the writes, which no product
// should pass: a proof that passes says what the writes do, not what the store held.
func undone(p *zanzibar.Proof) *zanzibar.Proof {
	out := *p
	out.States = slices.Clone(p.States)
	out.States[len(out.States)-1].Relationships = out.States[0].Relationships
	return &out
}

// runStoreFile runs a store file the way fga model test runs it with a model in the
// file: each test on a store of its own, written with the model of the file and the
// tuples of the test, and every check asked of it, where an error fails the check
// (internal/storetest/tests.go:33, localtest.go:244 and testresult.go:24 at openfga/cli
// v0.8.2). It returns the checks that fail.
func runStoreFile(ctx context.Context, t *testing.T, s *server.Server, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Model string `yaml:"model"`
	}
	if err := yaml.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	tests, err := Find([]string{path})
	if err != nil {
		t.Fatalf("Find(%s): %v", path, err)
	}

	var failed []string
	for _, test := range tests {
		if test.Test == "" {
			if len(test.Relationships) > 0 || len(test.Assertions) > 0 {
				t.Errorf("%s holds tuples or checks outside its tests", path)
			}
			continue
		}
		store, err := s.CreateStore(ctx, &openfgav1.CreateStoreRequest{Name: "petard-proof"})
		if err != nil {
			t.Fatal(err)
		}
		model := oracleModel{server: s, store: store.GetId()}
		model.write(ctx, t, file.Model)
		keys := make([]*openfgav1.TupleKey, 0, len(test.Relationships))
		for _, r := range test.Relationships {
			keys = append(keys, tupleKeyOf(t, r))
		}
		model.writeTuples(ctx, t, keys)
		for _, a := range test.Assertions {
			allowed, err := model.check(ctx, t, a)
			if err != nil || allowed != (a.Level == zanzibar.Yes) {
				failed = append(failed, test.Test+": "+a.String())
			}
		}
	}
	return failed
}

// The proofs against OpenFGA's Check in the test process, asked the way fga model test
// asks them: every proof of the fixture passes, and fails once its last state holds the
// store before the writes.
func TestProofsPassOnCheck(t *testing.T) {
	ctx := t.Context()
	s := newFixtureServer(t)
	schema, proofs := fixtureProofs(t)
	dir := t.TempDir()
	for i, fp := range proofs {
		name := "p" + string(rune('a'+i))
		if failed := runStoreFile(ctx, t, s, writeProof(t, schema, dir, name, fp.proof)); len(failed) > 0 {
			t.Errorf("%s: OpenFGA fails %v", fp.heading, failed)
		}
		if failed := runStoreFile(ctx, t, s, writeProof(t, schema, dir, name+"-undone", undone(fp.proof))); len(failed) == 0 {
			t.Errorf("%s: OpenFGA passes it without the writes", fp.heading)
		}
	}
}

// The proofs against fga model test itself, when its binary is named.
func TestOracleProofs(t *testing.T) {
	fga := os.Getenv(fgaEnv)
	if fga == "" {
		t.Skipf("%s is not set: the oracle needs the fga binary", fgaEnv)
	}
	schema, proofs := fixtureProofs(t)
	dir := t.TempDir()
	for i, fp := range proofs {
		name := "p" + string(rune('a'+i))
		if out, err := exec.Command(fga, "model", "test", "--tests", writeProof(t, schema, dir, name, fp.proof)).CombinedOutput(); err != nil {
			t.Errorf("%s: fga model test fails: %v\n%s", fp.heading, err, out)
		}
		if out, err := exec.Command(fga, "model", "test", "--tests", writeProof(t, schema, dir, name+"-undone", undone(fp.proof))).CombinedOutput(); err == nil {
			t.Errorf("%s: fga model test passes without the writes\n%s", fp.heading, out)
		}
	}
}

// A tuple OpenFGA would refuse makes no proof: fga model test would stop on it before any
// check. A viewer written with no condition is one the model admits; an owner with a
// condition is not.
func TestAProofWithATupleOpenFGARefusesIsNotWritten(t *testing.T) {
	schema, proofs := fixtureProofs(t)
	refused := *proofs[0].proof
	refused.States = slices.Clone(refused.States)
	last := len(refused.States) - 1
	owner := zanzibar.Relationship{
		Resource: zanzibar.Object{Type: "document", ID: "roadmap"},
		Relation: "owner",
		Subject:  zanzibar.Subject{Object: zanzibar.Object{Type: "user", ID: "olivia"}},
		Caveat:   &zanzibar.CaveatUse{Name: "not_expired"},
	}
	refused.States[last].Relationships = append(slices.Clone(refused.States[last].Relationships), owner)
	if _, err := schema.ProofFiles("proofs", "refused", nil, &refused); err == nil || !strings.Contains(err.Error(), "not_expired") {
		t.Errorf("ProofFiles = %v, want the tuple refused", err)
	}
}

// OpenFGA answers a check that waits on a condition with an error, so a proof with such
// a check is asked under the context that decides it, and is not written without one.
func TestAConditionNoContextDecidesHasNoProof(t *testing.T) {
	schema, proofs := fixtureProofs(t)
	var waiting *zanzibar.Proof
	for _, fp := range proofs {
		for _, state := range fp.proof.States {
			for _, c := range state.Checks {
				if c.Level == zanzibar.Conditional && c.Decided != nil {
					waiting = fp.proof
				}
			}
		}
	}
	if waiting == nil {
		t.Fatal("no proof of the fixture has a check that waits on a condition")
	}
	if _, err := schema.ProofFiles("proofs", "decided", nil, waiting); err != nil {
		t.Errorf("decided by a context of the store: %v, want the proof written", err)
	}

	undecided := *waiting
	undecided.States = slices.Clone(waiting.States)
	for i, state := range undecided.States {
		checks := slices.Clone(state.Checks)
		for j := range checks {
			checks[j].Decided = nil
		}
		undecided.States[i].Checks = checks
	}
	if _, err := schema.ProofFiles("proofs", "undecided", nil, &undecided); err == nil || !strings.Contains(err.Error(), "condition") {
		t.Errorf("decided by no context: %v, want an error naming the condition", err)
	}
}
