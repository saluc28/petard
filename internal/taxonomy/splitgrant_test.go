package taxonomy

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/saluc28/petard/internal/writemodel"
)

// The case of PTD-OPA-006 on the real fixture: carol holds support and nothing
// else, support may assign editor to anybody including herself, and editors
// publish. So carol can write herself into the position alice holds. The whole
// claim comes out of the two decisions and the write model, not out of a
// ReadSet written to produce it.
func TestSplitGrantOnFixture(t *testing.T) {
	findings, err := SplitGrant(t.Context(), fixtureAnalysis(t))
	if err != nil {
		t.Fatalf("SplitGrant() error = %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("findings = %d, want the one the fixture injects:\n%v", len(findings), findings)
	}
	f := findings[0]

	if f.Principal != "carol" || f.Target != "alice" {
		t.Errorf("escalation = %s to %s, want carol to alice", f.Principal, f.Target)
	}
	if f.Verdict != VerdictFinding {
		t.Errorf("verdict = %s, want a finding: the write model names the decision behind the write", f.Verdict)
	}
	if f.PatternID != WriteAllowedByAnotherDecision {
		t.Errorf("pattern = %s, want %s", f.PatternID, WriteAllowedByAnotherDecision)
	}
	if f.Decision != "data.quill.publish.allow" {
		t.Errorf("decision = %q, want the publishing decision", f.Decision)
	}
	if f.AuthorizedBy != "data.quill.admin.allow" {
		t.Errorf("authorized by = %q, want the assignment decision", f.AuthorizedBy)
	}
	if f.Value != "editor" {
		t.Errorf("value = %q, want editor: the role support may write and admin may not", f.Value)
	}
	if f.ViaWritePath != "data.users.{owner}.roles" {
		t.Errorf("via write path = %q, want the roles entry of the write model", f.ViaWritePath)
	}
	if f.Via != "PUT /api/v1/users/{id}/roles" {
		t.Errorf("via = %q, want how the write happens", f.Via)
	}
	if len(f.Reads) == 0 {
		t.Error("the finding points at no line of policy to check it against")
	}
}

// The counter case is the withdraw branch, which grants on admin. The
// assignment decision does not let support write admin, so no allowed write
// reaches it, and no edge to the principal who holds admin comes out. This is
// what signal 4 is for: without it the pattern would report every branch that
// reads a field somebody can write.
func TestSplitGrantLeavesTheCounterCaseAlone(t *testing.T) {
	findings, err := SplitGrant(t.Context(), fixtureAnalysis(t))
	if err != nil {
		t.Fatalf("SplitGrant() error = %v", err)
	}
	for _, f := range findings {
		if f.Value == "admin" {
			t.Errorf("admin was reported as a writable value: support cannot assign it (%s)", f)
		}
		if f.Target == "bob" {
			t.Errorf("an edge to bob, who holds admin, came out: %s", f)
		}
	}
}

// The escalation rests on the write model naming the authorizing decision.
// Take that declaration away and the same reads are still there, but nobody
// said one decision governs the write another depends on, so there is nothing
// to claim.
func TestSplitGrantNeedsTheAuthorization(t *testing.T) {
	a := fixtureAnalysis(t)
	a.Model = modelWithoutAuthorization(t)

	findings, err := SplitGrant(t.Context(), a)
	if err != nil {
		t.Fatalf("SplitGrant() error = %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("findings = %v, want none: no decision was named behind the write", findings)
	}
}

// Without any write model the pattern cannot run at all.
func TestSplitGrantNeedsTheWriteModel(t *testing.T) {
	a := fixtureAnalysis(t)
	a.Model = nil

	findings, err := SplitGrant(t.Context(), a)
	if err != nil {
		t.Fatalf("SplitGrant() error = %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("findings = %v, want none without a write model", findings)
	}
}

func TestSplitGrantNeedsData(t *testing.T) {
	a := fixtureAnalysis(t)
	a.Data = nil

	if _, err := SplitGrant(t.Context(), a); !errors.Is(err, ErrNeedsData) {
		t.Errorf("SplitGrant() error = %v, want ErrNeedsData", err)
	}
}

// modelWithoutAuthorization declares the same roles field as writable by
// support, but says nothing about which decision bounds the write.
func modelWithoutAuthorization(t *testing.T) *writemodel.Model {
	t.Helper()

	const content = `schema_version: 1
model: write-paths
entries:
  - path: data.users.{owner}.roles
    writable_by:
      - principal: role:support
        via: PUT /api/v1/users/{id}/roles
`
	path := filepath.Join(t.TempDir(), "write-model.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing the model: %v", err)
	}
	model, err := writemodel.Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	return model
}
