package taxonomy

import (
	"path/filepath"
	"testing"

	"github.com/saluc28/petard/internal/opaengine"
	"github.com/saluc28/petard/internal/pep"
)

// analysisWithGateway compiles an inline policy and declares an inline gateway
// over it, for the request-side patterns that need one. The policy annotates its
// own entrypoint, so the gateway is only there to say who sets each part of the
// request.
func analysisWithGateway(t *testing.T, policy, gateway string) Analysis {
	t.Helper()

	dir := t.TempDir()
	writeCaseFile(t, filepath.Join(dir, "policy", "p.rego"), policy)
	bundle, err := opaengine.Load([]string{filepath.Join(dir, "policy")}, opaengine.ParseModeAuto)
	if err != nil {
		t.Fatalf("the policy does not compile: %v", err)
	}
	reads, err := opaengine.Reads(bundle, opaengine.Limits{})
	if err != nil {
		t.Fatalf("Reads() error = %v", err)
	}

	file := filepath.Join(dir, "pep.yaml")
	writeCaseFile(t, file, gateway)
	point, err := pep.Load(file)
	if err != nil {
		t.Fatalf("the gateway does not load: %v", err)
	}
	shape, err := ShapeOf(reads, "", point)
	if err != nil {
		t.Fatalf("ShapeOf() error = %v", err)
	}
	return Analysis{Bundle: bundle, Reads: reads, Shape: shape, EnforcementPoint: point}
}

// Reading the loose-match builtins closes a false negative in PTD-OPA-010: a
// group name matched by a prefix is a name an issuer hands over just as a whole
// name is, and whoever can make the issuer say a name starting with the prefix
// reaches the grant. Only == and in were read before, so this went unseen.
func TestUncontrolledNameReadsALoosePrefix(t *testing.T) {
	policy := `package p

# METADATA
# entrypoint: true
default allow := false

allow if startswith(input.groups[_], "admin-")
`
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
  - path: input.groups.*
    set_by: issuer
    issuer: the directory
    identifier: name
    evidence:
      - the test
`
	a := analysisWithGateway(t, policy, gateway)
	findings, err := GrantsOnUncontrolledNames(a)
	if err != nil {
		t.Fatalf("GrantsOnUncontrolledNames() error = %v", err)
	}
	if len(findings) != 1 || findings[0].Path != "input.groups[_]" {
		t.Fatalf("findings = %v, want one on input.groups[_]: the prefix match is now read", findings)
	}
}

// The same reading closes a false negative in PTD-OPA-009: an exemption lifted by
// a prefix match on a part the caller writes is now read as a check that lifts a
// refusal, where only == and in were read before.
func TestSelfAssertedExemptionReadsALoosePrefix(t *testing.T) {
	policy := `package p

# METADATA
# entrypoint: true
default allow := false

allow if {
	input.action == "deploy"
	not blocked
}

blocked if {
	input.environment == "production"
	not startswith(input.change_ticket, "EMERGENCY-")
}
`
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
  - path: input.*
    set_by: caller
    note: what the caller asks for
    evidence:
      - the test
`
	a := analysisWithGateway(t, policy, gateway)
	var lifted []Finding
	for _, finding := range SelfAssertedExemptions(a) {
		if finding.Path == "input.change_ticket" {
			lifted = append(lifted, finding)
		}
	}
	if len(lifted) != 1 {
		t.Fatalf("findings on input.change_ticket = %v, want one: the prefix match lifts the refusal", lifted)
	}
}
