package taxonomy

import (
	"path/filepath"
	"testing"

	"github.com/saluc28/petard/internal/opaengine"
	"github.com/saluc28/petard/internal/pep"
)

// delegationAnalysis compiles an inline policy, declares an inline gateway over
// it, and gives it inline data, for the delegation pattern, which asks the
// decision about a witness and so needs all three.
func delegationAnalysis(t *testing.T, policy, gateway, data string) Analysis {
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

	writeCaseFile(t, filepath.Join(dir, "data", "data.json"), data)
	documents, err := opaengine.LoadData([]string{filepath.Join(dir, "data")})
	if err != nil {
		t.Fatalf("LoadData() error = %v", err)
	}
	return Analysis{Bundle: bundle, Reads: reads, Shape: shape, EnforcementPoint: point, Data: documents}
}

// bounded_by names two ceilings. The decision narrows the requested scopes by
// the agent's own role but never by the delegating edge, so a request asking for
// one scope outside the edge is granted all the same, and the pattern reports
// the edge as the ceiling that is not enforced.
func TestDelegationFindsAnUnboundedScope(t *testing.T) {
	policy := `package p

# METADATA
# entrypoint: true
default allow := false

allow if {
	every scope in input.requested_scopes {
		scope in input.role_scopes
	}
}
`
	a := delegationAnalysis(t, policy, delegationGateway, `{"unused": true}`)

	findings, err := GrantsBeyondDelegatedScope(t.Context(), a)
	if err != nil {
		t.Fatalf("GrantsBeyondDelegatedScope() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %v, want one", findings)
	}
	finding := findings[0]
	if finding.Verdict != VerdictFinding {
		t.Errorf("verdict %s, want a finding: the edge does not bound the request", finding.Verdict)
	}
	if finding.Path != "input.requested_scopes" || finding.Decision != "data.p.allow" {
		t.Errorf("finding on %s for %s, want input.requested_scopes for data.p.allow", finding.Path, finding.Decision)
	}
	if finding.Summary == "" || finding.Reads == nil {
		t.Errorf("finding carries no summary or no place to look: %+v", finding)
	}
}

// The same decision, narrowed by the delegating edge as well, bounds the
// request both ways. A scope outside the edge is refused, so the pattern leaves
// it alone.
func TestDelegationLeavesANarrowedScopeAlone(t *testing.T) {
	policy := `package p

# METADATA
# entrypoint: true
default allow := false

allow if {
	every scope in input.requested_scopes {
		scope in input.delegation_edge.scopes
	}
	every scope in input.requested_scopes {
		scope in input.role_scopes
	}
}
`
	a := delegationAnalysis(t, policy, delegationGateway, `{"unused": true}`)

	findings, err := GrantsBeyondDelegatedScope(t.Context(), a)
	if err != nil {
		t.Fatalf("GrantsBeyondDelegatedScope() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("findings = %v, want none: the edge bounds the request", findings)
	}
}

// With a requested authority declared and no ceiling, the question is open: what
// bounds this authority? The pattern reports a candidate rather than a finding.
func TestDelegationWithoutACeilingIsACandidate(t *testing.T) {
	policy := `package p

# METADATA
# entrypoint: true
default allow := false

allow if {
	every scope in input.requested_scopes {
		scope in input.role_scopes
	}
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
  - path: input.requested_scopes
    set_by: caller
    authority: requested
    evidence:
      - the test
`
	a := delegationAnalysis(t, policy, gateway, `{"unused": true}`)

	findings, err := GrantsBeyondDelegatedScope(t.Context(), a)
	if err != nil {
		t.Fatalf("GrantsBeyondDelegatedScope() error = %v", err)
	}
	if len(findings) != 1 || findings[0].Verdict != VerdictCandidate {
		t.Fatalf("findings = %v, want one candidate: nothing says what bounds the authority", findings)
	}
}

// delegationGateway declares the requested authority and the two ceilings it
// must sit under, the delegating edge and the agent's own role.
const delegationGateway = `schema_version: 1
id: test-gateway
engine: opa
source:
  kind: documentation
  note: a gateway for the test
decisions:
  - rule: allow
    side: grants
fields:
  - path: input.requested_scopes
    set_by: caller
    authority: requested
    bounded_by:
      - input.delegation_edge.scopes
      - input.role_scopes
    evidence:
      - the test
`
