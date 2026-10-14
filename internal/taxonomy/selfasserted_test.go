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

// A part of the request read under a key the policy computes stands for every
// field the key could name. Where the declaration gives all of them to the
// caller the exemption is the caller's to claim; where it gives one of them to
// the gateway, as the fixture gives the second factor, the key decides which is
// read and the caller does not by that, so it is a candidate; and where it
// gives them all to somebody else there is nothing to report.
func TestSelfAssertedExemptionOnAPartThatStandsForSeveral(t *testing.T) {
	gateway := `schema_version: 1
id: test-gateway
engine: opa
source:
  kind: documentation
  note: a gateway for the test
decisions:
  - rule: allow
    side: grants
fields:
  - path: input.mfa
    set_by: enforcement-point
    evidence:
      - the test
  - path: input.session.*
    set_by: enforcement-point
    evidence:
      - the test
  - path: input.*
    set_by: caller
    evidence:
      - the test
`
	tests := []struct {
		name     string
		part     string
		expected []string
	}{
		{name: "any field of the request", part: "input[data.settings.flag]", expected: []string{"candidate input[_]"}},
		{name: "any flag of the body", part: "input.flags[data.settings.flag]", expected: []string{"finding input.flags[_]"}},
		{name: "any field of the session", part: "input.session[data.settings.flag]", expected: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := `package p

# METADATA
# entrypoint: true
default allow := false

allow if not needs_second_factor

needs_second_factor if not ` + tt.part + `
`
			a := analysisWithGateway(t, policy, gateway)

			var got []string
			for _, finding := range SelfAssertedExemptions(a) {
				got = append(got, string(finding.Verdict)+" "+finding.Path)
			}
			if !slices.Equal(got, tt.expected) {
				t.Errorf("findings = %v, want %v", got, tt.expected)
			}
		})
	}
}

// A declaration that gives a part of the request to an issuer gives it the
// fields of that part too: a flag of the user the single sign-on hands over is
// not the caller's to assert, whatever a later entry says about the rest of the
// request. A field of the user an earlier entry gives to the caller is.
func TestSelfAssertedExemptionOnAFieldOfADeclaredPart(t *testing.T) {
	gateway := `schema_version: 1
id: test-gateway
engine: opa
source:
  kind: documentation
  note: a gateway for the test
decisions:
  - rule: allow
    side: grants
fields:
  - path: input.user.note
    set_by: caller
    evidence:
      - the test
  - path: input.user
    set_by: issuer
    issuer: the single sign-on
    evidence:
      - the test
  - path: input.*
    set_by: caller
    evidence:
      - the test
`
	tests := []struct {
		name     string
		part     string
		expected []string
	}{
		{name: "a field of what the issuer sets", part: "input.user.vip", expected: nil},
		{name: "a field declared ahead of it", part: `input.user.note == "urgent"`, expected: []string{"finding input.user.note"}},
		{name: "a field beside it", part: "input.vip", expected: []string{"finding input.vip"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := `package p

# METADATA
# entrypoint: true
default allow := false

allow if not needs_review

needs_review if not ` + tt.part + `
`
			a := analysisWithGateway(t, policy, gateway)

			var got []string
			for _, finding := range SelfAssertedExemptions(a) {
				got = append(got, string(finding.Verdict)+" "+finding.Path)
			}
			if !slices.Equal(got, tt.expected) {
				t.Errorf("findings = %v, want %v", got, tt.expected)
			}
		})
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
