package taxonomy

import (
	"slices"
	"testing"

	"github.com/saluc28/petard/internal/pep"
)

// fixtureGateway is the declaration of the gateway in front of Quill, the one
// part of the fixture that says who sets each part of the request.
func fixtureGateway(t *testing.T) *pep.EnforcementPoint {
	t.Helper()

	point, err := pep.Load(fixturePath("pep.yaml"))
	if err != nil {
		t.Fatalf("pep.Load() error = %v", err)
	}
	return point
}

// The case and the counter case sit in one rule of the fixture, written the
// same way: the scheduled export and the second factor both lift the refusal
// of an export. Only the declaration of the gateway tells them apart, and the
// finding has to be the one the caller writes.
func TestSelfAssertedExemptionOnFixture(t *testing.T) {
	a := fixtureAnalysis(t)

	findings := SelfAssertedExemptions(a)
	if len(findings) != 1 {
		t.Fatalf("findings = %v, want one", findings)
	}
	finding := findings[0]
	if finding.Path != "input.scheduled" || finding.Decision != "data.quill.tenant_policy.allow_export" {
		t.Errorf("finding on %s for %s, want input.scheduled for the export", finding.Path, finding.Decision)
	}
	if finding.Verdict != VerdictFinding || finding.Confidence != "A" {
		t.Errorf("verdict %s at confidence %s, want a finding at A: the gateway declares the field", finding.Verdict, finding.Confidence)
	}
	if len(finding.Reads) != 1 || finding.Reads[0].Rule != "data.quill.tenant_policy.export_needs_mfa" {
		t.Errorf("places to look = %+v, want the rule holding the check", finding.Reads)
	}
}

// Without the declaration the pattern does not run, and says so: nothing tells
// a part of the request the caller asserts from one it has to set to comply.
func TestSelfAssertedExemptionWithoutADeclaration(t *testing.T) {
	a := fixtureAnalysis(t)
	a.EnforcementPoint = nil

	found, err := Run(t.Context(), a)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(found.SelfAsserted) != 0 {
		t.Errorf("findings = %v, want none with nothing declared", found.SelfAsserted)
	}
	if found.Skipped[SelfAssertedExemption] != needsEnforcementPoint {
		t.Errorf("skipped = %q, want the pattern to say it needs the enforcement point", found.Skipped[SelfAssertedExemption])
	}
}

// A declaration that does not cover a part leaves it a candidate, since whoever
// sets it may be the caller. Here it speaks about the second factor alone.
func TestSelfAssertedExemptionOnAPartNobodyDeclared(t *testing.T) {
	a := fixtureAnalysis(t)
	point := *a.EnforcementPoint
	point.Fields = slices.DeleteFunc(slices.Clone(point.Fields), func(field pep.Field) bool {
		return field.Path != "input.mfa"
	})
	a.EnforcementPoint = &point

	var got []string
	for _, finding := range SelfAssertedExemptions(a) {
		got = append(got, string(finding.Verdict)+" "+finding.Path)
	}
	if expected := []string{"candidate input.scheduled"}; !slices.Equal(got, expected) {
		t.Errorf("findings = %v, want %v", got, expected)
	}
}
