package taxonomy

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/saluc28/petard/internal/opaengine"
	"github.com/saluc28/petard/internal/pep"
)

// siblingPolicyBundle is the shape the sibling form needs: a list of team
// members, each with the user it names and the role it grants, and one decision
// that reads the role of the member whose user is the requester. Removing the
// team needs owner (role >= 3); assigning a member's role needs editor
// (role >= 2), so the writer's threshold is below the one the same decision
// reads to grant.
const siblingPolicyBundle = `package roster

import rego.v1

roles := {"viewer": 1, "editor": 2, "owner": 3}

# METADATA
# scope: document
# title: The decision the API asks about every request
# entrypoint: true
default authz := false

authz if { allow }

allow if {
	input.action == "remove"
	some i
	data.team.members[i].user == input.user
	roles[data.team.members[i].role] >= 3
}

allow if {
	input.action == "assign"
	some i
	data.team.members[i].user == input.user
	roles[data.team.members[i].role] >= 2
}
`

// siblingData holds an owner, an editor, and a viewer, so the write is
// authorized for one and not another.
const siblingData = `{
  "team": {
    "members": [
      {"user": "alice", "role": "editor"},
      {"user": "bob", "role": "owner"},
      {"user": "carol", "role": "viewer"}
    ]
  }
}`

const siblingModel = `schema_version: 1
model: write-paths
entries:
  - path: data.team.members[_].role
    writable_by:
      - principal: role:editor
        via: "PUT /api/v1/teams/{team}/members/{user}"
        authorized_by:
          decision: data.roster.authz
          request:
            input.action: "assign"
`

// The escalation the sibling form carries: an editor may assign any member's
// role, their own included, and the same decision rewards owner. alice, an
// editor, sets her own role to owner and reaches where bob stands.
func TestSiblingGrantFindsTheAttributeEscalation(t *testing.T) {
	a := analysisOf(t, &FalsePositiveCase{Policy: siblingPolicyBundle, Data: siblingData, WriteModel: siblingModel})

	findings, err := SiblingGrant(t.Context(), a)
	if err != nil {
		t.Fatalf("SiblingGrant() error = %v", err)
	}

	var aliceToBob *Finding
	for i, f := range findings {
		if f.Principal == "carol" {
			t.Errorf("carol was reported, and a viewer cannot assign a role: %s", f)
		}
		if f.Principal == "alice" && f.Target == "bob" {
			aliceToBob = &findings[i]
		}
	}
	if aliceToBob == nil {
		t.Fatalf("the escalation from alice to bob is missing:\n%v", findings)
	}

	f := *aliceToBob
	if f.Verdict != VerdictFinding || f.PatternID != WriteAllowedByAnotherDecision {
		t.Errorf("finding = %s under %s, want a finding of %s", f.Verdict, f.PatternID, WriteAllowedByAnotherDecision)
	}
	if f.Value != "owner" {
		t.Errorf("value = %q, want owner: the role that grants and that bob holds", f.Value)
	}
	if f.Decision != "data.roster.authz" || f.AuthorizedBy != "data.roster.authz" {
		t.Errorf("decision = %q authorized by %q, want the same decision on both sides", f.Decision, f.AuthorizedBy)
	}
	if f.ViaWritePath != "data.team.members[_].role" {
		t.Errorf("via write path = %q, want the role entry of the write model", f.ViaWritePath)
	}
	if f.Via != "PUT /api/v1/teams/{team}/members/{user}" {
		t.Errorf("via = %q, want how the write happens", f.Via)
	}
	if len(f.Reads) == 0 {
		t.Error("the finding points at no line of policy to check it against")
	}
	witnessHolds(t, a, f.Witness)
	if f.Witness.AuthorizedBy != "data.roster.authz" {
		t.Errorf("the write is authorized by %q, want the decision that allows assigning a role", f.Witness.AuthorizedBy)
	}
}

// siblingPathPolicy is the sibling form behind an API that addresses a member by
// the path of the call, sent split into segments: assigning a role is
// PUT /teams/{team}/members/{user}, allowed to an editor of that team, removing
// the team takes an owner, and the health check is open to anybody.
const siblingPathPolicy = `package roster

import rego.v1

roles := {"viewer": 1, "editor": 2, "owner": 3}

# METADATA
# scope: document
# entrypoint: true
default authz := false

authz if input.path == ["health"]

authz if {
	input.method == "DELETE"
	some i
	data.team.members[i].user == input.user
	roles[data.team.members[i].role] >= 3
}

authz if {
	input.method == "PUT"
	input.path = ["teams", team, "members", _]
	some i
	data.team.members[i].team == team
	data.team.members[i].user == input.user
	roles[data.team.members[i].role] >= 2
}
`

const siblingPathData = `{
  "team": {
    "members": [
      {"team": "t-1", "user": "alice", "role": "editor"},
      {"team": "t-1", "user": "bob", "role": "owner"}
    ]
  }
}`

// siblingPathModel declares the path the endpoint sends, with the team and the
// user of the member written, which are fields of the element.
const siblingPathModel = `schema_version: 1
model: write-paths
entries:
  - path: data.team.members[_].role
    writable_by:
      - principal: role:editor
        via: "PUT /teams/{team}/members/{user}"
        authorized_by:
          decision: data.roster.authz
          request:
            input.method: PUT
            input.path: [teams, "{team}", members, "{user}"]
`

// With the path declared, the decision is asked about the write the endpoint
// makes, on alice's own member. Declared by its method alone, the request would
// settle for the health check, which the same decision allows to anybody.
func TestSiblingGrantAsksAboutThePathTheEndpointSends(t *testing.T) {
	a := analysisOf(t, &FalsePositiveCase{Policy: siblingPathPolicy, Data: siblingPathData, WriteModel: siblingPathModel})

	findings, err := SiblingGrant(t.Context(), a)
	if err != nil {
		t.Fatalf("SiblingGrant() error = %v", err)
	}
	var aliceToBob *Finding
	for i, f := range findings {
		if f.Principal == "alice" && f.Target == "bob" {
			aliceToBob = &findings[i]
		}
	}
	if aliceToBob == nil {
		t.Fatalf("the escalation from alice to bob is missing:\n%v", findings)
	}

	witnessHolds(t, a, aliceToBob.Witness)
	path := aliceToBob.Witness.WriteRequest["path"]
	if want := []any{"teams", "t-1", "members", "alice"}; !reflect.DeepEqual(path, want) {
		t.Errorf("the write is asked about %v, want the path of alice's member %v", path, want)
	}
}

// siblingClaimPolicy lets a member assign roles only as an administrator, a
// role the identity provider puts next to the subject, and removing the team
// takes an owner. Nothing in the data says alice is an administrator.
const siblingClaimPolicy = `package roster

import rego.v1

roles := {"viewer": 1, "editor": 2, "owner": 3}

# METADATA
# scope: document
# entrypoint: true
default authz := false

authz if {
	input.action == "remove"
	some i
	data.team.members[i].user == input.subject.id
	roles[data.team.members[i].role] >= 3
}

authz if {
	input.action == "assign"
	input.subject.role == "admin"
}
`

// siblingClaimEditors adds the ordinary way in: an editor of the team assigns
// roles, whatever the provider says about them.
const siblingClaimEditors = `
authz if {
	input.action == "assign"
	some i
	data.team.members[i].user == input.subject.id
	roles[data.team.members[i].role] >= 2
}
`

// siblingOf finds the escalation from one principal to another.
func siblingOf(t *testing.T, a Analysis, principal, target string) Finding {
	t.Helper()

	findings, err := SiblingGrant(t.Context(), a)
	if err != nil {
		t.Fatalf("SiblingGrant() error = %v", err)
	}
	for _, f := range findings {
		if f.Principal == principal && f.Target == target {
			return f
		}
	}
	t.Fatalf("the escalation from %s to %s is missing:\n%v", principal, target, findings)
	return Finding{}
}

// A write the decision allows only to a requester who claims a role, which
// sits next to the subject in the request, is allowed to a principal only if
// the provider says so, which the data cannot tell. The escalation stays a
// candidate and says why; with a way in that asks for no claim it is a finding.
func TestSiblingGrantLeavesAWriteThatNeedsAClaimACandidate(t *testing.T) {
	tests := []struct {
		name    string
		policy  string
		verdict Verdict
	}{
		{name: "the write needs the claim", policy: siblingClaimPolicy, verdict: VerdictCandidate},
		{name: "an editor writes without it", policy: siblingClaimPolicy + siblingClaimEditors, verdict: VerdictFinding},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := analysisOf(t, &FalsePositiveCase{Policy: tt.policy, Data: siblingData, WriteModel: siblingModel})
			shape, err := opaengine.ShapeOf(a.Reads, "input.subject.id")
			if err != nil {
				t.Fatalf("ShapeOf() error = %v", err)
			}
			a.Shape = shape

			f := siblingOf(t, a, "alice", "bob")
			if f.Verdict != tt.verdict {
				t.Errorf("verdict = %s, want %s", f.Verdict, tt.verdict)
			}
			if tt.verdict == VerdictCandidate && f.Note == "" {
				t.Error("the candidate does not say it rests on a claim")
			}
		})
	}
}

// With the subject at the top of the request, nothing sits next to it, and
// only the enforcement point can say that a part is a claim: here the groups,
// which the single sign-on sets.
func TestSiblingGrantReadsTheClaimsTheEnforcementPointDeclares(t *testing.T) {
	policy := strings.NewReplacer("input.subject.id", "input.user", `input.subject.role == "admin"`, `"admins" in input.groups`).
		Replace(siblingClaimPolicy)
	gateway := `schema_version: 1
id: roster-gateway
title: The gateway in front of the roster
engine: opa
source:
  kind: documentation
  note: Written for this test.
decisions:
  - rule: authz
    side: grants
fields:
  - path: input.groups
    set_by: issuer
    issuer: the single sign-on of the roster
    evidence:
      - this test
`
	file := filepath.Join(t.TempDir(), "pep.yaml")
	if err := os.WriteFile(file, []byte(gateway), 0o600); err != nil {
		t.Fatalf("writing the declaration: %v", err)
	}
	point, err := pep.Load(file)
	if err != nil {
		t.Fatalf("pep.Load() error = %v", err)
	}

	for _, tt := range []struct {
		name    string
		point   *pep.EnforcementPoint
		verdict Verdict
	}{
		{name: "declared", point: point, verdict: VerdictCandidate},
		{name: "not declared", point: nil, verdict: VerdictFinding},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a := analysisOf(t, &FalsePositiveCase{Policy: policy, Data: siblingData, WriteModel: siblingModel})
			a.EnforcementPoint = tt.point
			if f := siblingOf(t, a, "alice", "bob"); f.Verdict != tt.verdict {
				t.Errorf("verdict = %s, want %s", f.Verdict, tt.verdict)
			}
		})
	}
}

// The one who already holds the granting value has nothing to gain by writing a
// lower one, so no edge comes out of the downgrade.
func TestSiblingGrantLeavesTheDowngradeAlone(t *testing.T) {
	a := analysisOf(t, &FalsePositiveCase{Policy: siblingPolicyBundle, Data: siblingData, WriteModel: siblingModel})

	findings, err := SiblingGrant(t.Context(), a)
	if err != nil {
		t.Fatalf("SiblingGrant() error = %v", err)
	}
	for _, f := range findings {
		if f.Principal == "bob" && f.Verdict == VerdictFinding {
			t.Errorf("bob, who already holds owner, was reported gaining by writing %s: %s", f.Value, f)
		}
	}
}

// The write model is what says who may set the role and which decision bounds it.
// Without one the reads are still there, but nobody is named as the writer, so
// there is nothing to claim.
func TestSiblingGrantNeedsTheWriteModel(t *testing.T) {
	a := analysisOf(t, &FalsePositiveCase{Policy: siblingPolicyBundle, Data: siblingData, WriteModel: siblingModel})
	a.Model = nil

	findings, err := SiblingGrant(t.Context(), a)
	if err != nil {
		t.Fatalf("SiblingGrant() error = %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("findings = %v, want none without a write model", findings)
	}
}

func TestSiblingGrantNeedsData(t *testing.T) {
	a := analysisOf(t, &FalsePositiveCase{Policy: siblingPolicyBundle, Data: siblingData, WriteModel: siblingModel})
	a.Data = nil

	if _, err := SiblingGrant(t.Context(), a); !errors.Is(err, ErrNeedsData) {
		t.Errorf("SiblingGrant() error = %v, want ErrNeedsData", err)
	}
}
