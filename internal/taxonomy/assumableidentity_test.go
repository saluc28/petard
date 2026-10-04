package taxonomy

import (
	"slices"
	"testing"

	"github.com/saluc28/petard/internal/pep"
)

// The case and the counter case sit in one decision of the fixture, written the
// same way: the internal sync grants on the SPIFFE id of a service account and
// on an agent identity bound to a verified credential. Only the declaration of
// the gateway tells them apart, and the finding has to be the one somebody can
// assume by deploying the service account.
func TestAssumableIdentityOnFixture(t *testing.T) {
	a := fixtureAnalysis(t)

	findings := GrantsOnAssumableIdentities(a)
	if len(findings) != 1 {
		t.Fatalf("findings = %v, want one", findings)
	}
	finding := findings[0]
	if finding.Path != "input.caller.spiffe" || finding.Decision != "data.quill.mesh.allow_sync" {
		t.Errorf("finding on %s for %s, want input.caller.spiffe for the sync decision", finding.Path, finding.Decision)
	}
	if finding.Verdict != VerdictFinding || finding.Confidence != "A" {
		t.Errorf("verdict %s at confidence %s, want a finding at A: the gateway declares who can assume it", finding.Verdict, finding.Confidence)
	}
	if len(finding.Reads) != 1 || finding.Reads[0].Rule != "data.quill.mesh.allow_sync" {
		t.Errorf("places to look = %+v, want the rule holding the check", finding.Reads)
	}
}

// Without the declaration the pattern does not run, and says so: nothing tells a
// runtime identity apart from any other value the policy holds a request against.
func TestAssumableIdentityWithoutADeclaration(t *testing.T) {
	a := fixtureAnalysis(t)
	a.EnforcementPoint = nil

	found, err := Run(t.Context(), a)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(found.AssumableIdentity) != 0 {
		t.Errorf("findings = %v, want none with nothing declared", found.AssumableIdentity)
	}
	if found.Skipped[GrantOnAssumableIdentity] != needsEnforcementPoint {
		t.Errorf("skipped = %q, want the pattern to say it needs the enforcement point", found.Skipped[GrantOnAssumableIdentity])
	}
}

// A declaration that names the identity but nobody who can assume it leaves the
// match a candidate, with the question of who can assume it still open. The
// identity the declaration pins stays nothing either way.
func TestAssumableIdentityWithoutAnAssumer(t *testing.T) {
	a := fixtureAnalysis(t)
	point := *a.EnforcementPoint
	point.Fields = slices.Clone(point.Fields)
	for i := range point.Fields {
		if point.Fields[i].Path == "input.caller.spiffe" {
			point.Fields[i].AssumableBy = nil
		}
	}
	a.EnforcementPoint = &point

	var got []string
	for _, finding := range GrantsOnAssumableIdentities(a) {
		got = append(got, string(finding.Verdict)+" "+finding.Path)
	}
	if expected := []string{"candidate input.caller.spiffe"}; !slices.Equal(got, expected) {
		t.Errorf("findings = %v, want %v", got, expected)
	}
}

// The pinned identity is left alone on its own, so a declaration can carry an
// assumable identity and a pinned one side by side and only the first comes out.
func TestAssumableIdentityLeavesAPinnedOneAlone(t *testing.T) {
	a := fixtureAnalysis(t)

	for _, finding := range GrantsOnAssumableIdentities(a) {
		if finding.Path == "input.caller.attested" {
			t.Errorf("the pinned identity was reported: %s", finding)
		}
	}

	// Removing the field entirely leaves the finding on the assumable identity
	// unchanged, which is the proof the pinned entry is what kept it quiet.
	point := *a.EnforcementPoint
	point.Fields = slices.DeleteFunc(slices.Clone(point.Fields), func(field pep.Field) bool {
		return field.Path == "input.caller.attested"
	})
	a.EnforcementPoint = &point
	if findings := GrantsOnAssumableIdentities(a); len(findings) != 1 {
		t.Errorf("findings = %v, want the one on the assumable identity", findings)
	}
}
