package taxonomy

import (
	"fmt"
	"path/filepath"
	"slices"
	"testing"

	"github.com/saluc28/petard/internal/pep"
)

// The case and the counter case sit in one decision of the fixture, written the
// same way: the group called security, and the same group by the id the
// directory gave it. The declaration of the gateway says which of the two is a
// name, and the write model says who can pick it.
func TestGrantOnUncontrolledNameOnFixture(t *testing.T) {
	findings, err := GrantsOnUncontrolledNames(fixtureAnalysis(t))
	if err != nil {
		t.Fatalf("GrantsOnUncontrolledNames() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %v, want one", findings)
	}
	finding := findings[0]
	if finding.Path != "input.groups[_]" || finding.Decision != "data.quill.platform.allow_audit_log" {
		t.Errorf("finding on %s for %s, want input.groups[_] for the audit log", finding.Path, finding.Decision)
	}
	if finding.Verdict != VerdictFinding || finding.Confidence != "A" {
		t.Errorf("verdict %s at confidence %s, want a finding at A: both halves are declared", finding.Verdict, finding.Confidence)
	}
	if finding.ViaWritePath != "input.groups[_]" || finding.Via != "POST /api/v1/groups" {
		t.Errorf("written at %s via %s, want the entry of the write model on the groups", finding.ViaWritePath, finding.Via)
	}
}

// Without the declaration the pattern does not run, and says so.
func TestGrantOnUncontrolledNameWithoutADeclaration(t *testing.T) {
	a := fixtureAnalysis(t)
	a.EnforcementPoint = nil

	found, err := Run(t.Context(), a)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(found.UncontrolledName) != 0 {
		t.Errorf("findings = %v, want none with nothing declared", found.UncontrolledName)
	}
	if found.Skipped[GrantOnUncontrolledName] != needsEnforcementPoint {
		t.Errorf("skipped = %q, want the pattern to say it needs the enforcement point", found.Skipped[GrantOnUncontrolledName])
	}
}

// Without the write model nobody is named as able to pick the name, and the
// match stays a candidate at the level the request was recognized at.
func TestGrantOnUncontrolledNameWithoutAWriteModel(t *testing.T) {
	a := fixtureAnalysis(t)
	a.Model = nil

	findings, err := GrantsOnUncontrolledNames(a)
	if err != nil {
		t.Fatalf("GrantsOnUncontrolledNames() error = %v", err)
	}
	if len(findings) != 1 || findings[0].Verdict != VerdictCandidate || findings[0].Confidence != a.Shape.Confidence.String() {
		t.Errorf("findings = %v, want one candidate at level %s", findings, a.Shape.Confidence)
	}
}

// uncontrolledNameDeclaration speaks about the elements of the groups rather
// than about the list, which is how a declaration of a product usually reads,
// and about every other kind of part a check can meet.
const uncontrolledNameDeclaration = `schema_version: 1
id: directory
engine: opa
decisions:
  - rule: allow
    side: grants
fields:
  - path: input.groups[_]
    set_by: issuer
    issuer: the directory
    identifier: name
    evidence: [the test]
  - path: input.group
    set_by: issuer
    issuer: the directory
    identifier: name
    evidence: [the test]
  - path: input.group_ids[_]
    set_by: issuer
    issuer: the directory
    identifier: id
    evidence: [the test]
  - path: input.email
    set_by: issuer
    issuer: the directory
    evidence: [the test]
  - path: input.action
    set_by: caller
    evidence: [the test]
`

// uncontrolledNameModel lets anybody create a group, and says nothing about the
// group a request names on its own.
const uncontrolledNameModel = `schema_version: 1
model: write-paths
entries:
  - path: input.groups[_]
    writable_by:
      - principal: role:member
        via: POST /groups
`

// Only a check that grants, on a part an issuer sets and declares a name, is
// reported, and the write model decides between a finding and a candidate.
func TestGrantOnUncontrolledNameReadsTheDeclaration(t *testing.T) {
	tests := []struct {
		name     string
		policy   string
		denying  []string
		expected []string
	}{
		{
			name:     "a name compared whole",
			policy:   `allow if input.groups[_] == "security"`,
			expected: []string{"finding input.groups[_] 1"},
		},
		{
			name:     "a name searched for in the list, declared by its elements",
			policy:   `allow if "security" in input.groups`,
			expected: []string{"finding input.groups[_] 1"},
		},
		{
			name: "the same name checked twice in one decision",
			policy: `allow if "security" in input.groups

allow if input.groups[_] == "audit"`,
			expected: []string{"finding input.groups[_] 2"},
		},
		{
			name:     "a name nobody declared a creator for",
			policy:   `allow if input.group == "security"`,
			expected: []string{"candidate input.group 1"},
		},
		{
			name:   "an id the issuer assigns",
			policy: `allow if "grp-5821" in input.group_ids`,
		},
		{
			name:   "a part the caller sets",
			policy: `allow if input.action == "read"`,
		},
		{
			name:   "a part the issuer sets without saying what kind",
			policy: `allow if input.email == "alice@example.com"`,
		},
		{
			name:   "a part nobody declared",
			policy: `allow if input.team == "security"`,
		},
		{
			name:   "a name asked to be there",
			policy: `allow if input.group`,
		},
		{
			name:    "a refusal on a name",
			policy:  `deny if "contractors" in input.groups`,
			denying: []string{"t/deny"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var entrypoints []string
			if tt.denying == nil {
				entrypoints = []string{"t/allow"}
			}
			a := declaredAnalysis(t, "package t\n\n"+tt.policy+"\n", "", uncontrolledNameModel, entrypoints, tt.denying)
			file := filepath.Join(t.TempDir(), "directory.yaml")
			writeCaseFile(t, file, uncontrolledNameDeclaration)
			point, err := pep.Load(file)
			if err != nil {
				t.Fatalf("pep.Load() error = %v", err)
			}
			a.EnforcementPoint = point

			findings, err := GrantsOnUncontrolledNames(a)
			if err != nil {
				t.Fatalf("GrantsOnUncontrolledNames() error = %v", err)
			}
			var got []string
			for _, finding := range findings {
				got = append(got, fmt.Sprintf("%s %s %d", finding.Verdict, finding.Path, len(finding.Reads)))
			}
			if !slices.Equal(got, tt.expected) {
				t.Errorf("findings = %v, want %v", got, tt.expected)
			}
		})
	}
}
