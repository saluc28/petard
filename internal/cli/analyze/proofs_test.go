package analyze

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/saluc28/petard/internal/cli/zanzibarsetup"
	"github.com/saluc28/petard/internal/zanzibar"
)

// escalationsOf counts the escalations a run over paths finds, the proofs it should write.
func escalationsOf(t *testing.T, paths ...string) int {
	t.Helper()
	found, err := zanzibarsetup.Load(t.Context(), paths, "")
	if err != nil {
		t.Fatal(err)
	}
	run, err := runZanzibar(found, time.Now(), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(run.escalations) == 0 {
		t.Fatalf("%v holds no escalation", paths)
	}
	return len(run.escalations)
}

// Every escalation of either fixture has a proof, in the files of its product: a
// directory of validation files for SpiceDB, a store file for OpenFGA.
func TestRunWritesAProofOfEachEscalation(t *testing.T) {
	openfgaFixture := filepath.Join("..", "..", "..", "fixtures", "vulnerable-openfga")
	tests := []struct {
		name    string
		fixture string
		file    string
	}{
		{name: "spicedb", fixture: spicedbFixture, file: filepath.Join("ptd-zan-007-document-edit", "1-before.yaml")},
		{name: "openfga", fixture: openfgaFixture, file: "ptd-zan-007-document-edit.fga.yaml"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "proofs")
			var stdout, stderr bytes.Buffer
			if code := Run([]string{"-fail-on", failOnNone, "-proofs", dir, tt.fixture}, &stdout, &stderr); code != exitOK {
				t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
			}
			want := escalationsOf(t, tt.fixture)
			if line := strconv.Itoa(want) + " proofs written to " + dir; !strings.Contains(stdout.String(), line) {
				t.Errorf("the report does not say %q:\n%s", line, stdout.String())
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != want {
				t.Errorf("%d proofs in %s, want %d", len(entries), dir, want)
			}
			raw, err := os.ReadFile(filepath.Join(dir, tt.file))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(raw), "PTD-ZAN-007: document#edit") || !strings.Contains(string(raw), filepath.ToSlash(dir)) {
				t.Errorf("%s does not say what it proves and how to run it:\n%s", tt.file, raw)
			}
		})
	}
}

// A run over policies and a schema together writes the proofs of the schema too.
func TestARunWithPoliciesWritesTheProofsOfTheSchema(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "policy.rego"), []byte("package authz\n\ndefault allow := false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"schema.zed", "validation.yaml", "writes.yaml"} {
		raw, err := os.ReadFile(filepath.Join(spicedbFixture, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	proofs := filepath.Join(t.TempDir(), "proofs")
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"-fail-on", failOnNone, "-proofs", proofs, dir}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}
	if line := strconv.Itoa(escalationsOf(t, dir)) + " proofs written to " + proofs; !strings.Contains(stdout.String(), line) {
		t.Errorf("the report does not say %q:\n%s", line, stdout.String())
	}
}

// A proof carries the schema it was written from and goes on passing after the schema
// is fixed, so -proofs takes a directory with nothing in it, and says so before the
// analysis.
func TestProofsNeedAnEmptyDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "old.yaml"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"-proofs", dir, spicedbFixture}, &stdout, &stderr); code != exitFailure {
		t.Fatalf("exit code = %d, want %d", code, exitFailure)
	}
	if !strings.Contains(stderr.String(), "holds files already") || stdout.Len() != 0 {
		t.Errorf("stdout %q, stderr %q: want the directory refused before any report", stdout.String(), stderr.String())
	}
}

// Quiet, the proofs are written and the run says nothing of them.
func TestRunQuietWritesProofs(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "proofs")
	var stdout, stderr bytes.Buffer
	Run([]string{"-quiet", "-fail-on", failOnNone, "-proofs", dir, spicedbFixture}, &stdout, &stderr)
	if strings.Contains(stdout.String(), "proofs written") {
		t.Errorf("-quiet printed:\n%s", stdout.String())
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) == 0 {
		t.Errorf("no proof written: %v", err)
	}
}

// An escalation without a proof is named with the reason, whether the engine could not
// replay it or the product would not take it.
func TestAnEscalationWithoutAProofSaysWhy(t *testing.T) {
	match := func(subject string, raise zanzibar.Raise) zanzibar.Match {
		return zanzibar.Match{PatternID: "PTD-ZAN-007", Subject: subject, Raise: &raise}
	}
	refuses := func(string, string, []string, *zanzibar.Proof) ([]zanzibar.ProofFile, error) {
		return nil, errors.New("the product refuses it")
	}
	escalations := []provable{
		{match: match("document#edit, a", zanzibar.Raise{Type: "document", Permission: "edit", NoProof: "no replay"})},
		{match: match("document#view, b", zanzibar.Raise{Type: "document", Permission: "view", Proof: &zanzibar.Proof{}}), prove: refuses},
	}
	written, without, err := writeProofs(t.TempDir(), escalations)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"PTD-ZAN-007: document#edit, a: no replay", "PTD-ZAN-007: document#view, b: the product refuses it"}
	if written != 0 || strings.Join(without, "\n") != strings.Join(want, "\n") {
		t.Errorf("written %d, without %q, want 0 and %q", written, without, want)
	}

	var out bytes.Buffer
	reportProofs(&out, "proofs", written, without)
	if !strings.Contains(out.String(), "2 escalations without a proof:\n  PTD-ZAN-007: document#edit, a: no replay") {
		t.Errorf("the report says:\n%s", out.String())
	}
}

// Two escalations of the same pattern, type and permission, from two schemas, are two
// proofs, the second numbered.
func TestTwoProofsOfOneNameAreKeptApart(t *testing.T) {
	writes := func(_, name string, _ []string, _ *zanzibar.Proof) ([]zanzibar.ProofFile, error) {
		return []zanzibar.ProofFile{{Path: name + ".yaml", Content: []byte(name)}}, nil
	}
	m := zanzibar.Match{PatternID: "PTD-ZAN-007", Raise: &zanzibar.Raise{Type: "document", Permission: "edit", Proof: &zanzibar.Proof{}}}
	dir := t.TempDir()
	written, _, err := writeProofs(dir, []provable{{schema: "a.zed", match: m, prove: writes}, {schema: "b.zed", match: m, prove: writes}})
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if written != 2 || len(entries) != 2 {
		t.Errorf("written %d, %d files, want two proofs", written, len(entries))
	}
}

// A proof is named after its pattern, type and permission in letters every system takes,
// and a second one of the same three gets a number.
func TestProofName(t *testing.T) {
	m := zanzibar.Match{PatternID: "PTD-ZAN-004", Raise: &zanzibar.Raise{Type: "tenant/agent_session", Permission: "approve"}}
	taken := map[string]bool{}
	first := proofName(taken, m)
	taken[first] = true
	second := proofName(taken, m)
	if first != "ptd-zan-004-tenant-agent-session-approve" || second != first+"-2" {
		t.Errorf("proofName = %q then %q", first, second)
	}
}
