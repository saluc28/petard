package taxonomy

import (
	"errors"
	"testing"
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
