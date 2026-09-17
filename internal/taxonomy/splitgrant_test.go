package taxonomy

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
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

// joinPolicyBundle is the shape of Chef Automate cut down to what the pattern
// needs: the request carries a list of subjects, a policy applies to whoever it
// holds among its members, and the same decision is what the API asks before it
// adds a member.
const joinPolicyBundle = `package authz

# METADATA
# scope: document
# title: Projects the subjects of the request are authorized on
# entrypoint: true
authorized_project contains project if {
	has_member[policy]
	statement := data.policies[policy].statements[_]
	action_matches(input.action, statement.actions[_])
	resource_matches(input.resource, statement.resources[_])
	project := statement.projects[_]
	project == input.projects[_]
}

has_member contains policy if {
	member := data.policies[policy].members[_]
	subject := input.subjects[_]
	subject_matches(subject, member)
}

subject_matches(value, stored) if value == stored

action_matches(asked, stored) if asked == stored

action_matches(asked, stored) if {
	endswith(stored, "*")
	startswith(asked, trim_right(stored, "*"))
}

resource_matches(asked, stored) if asked == stored

resource_matches(asked, stored) if {
	endswith(stored, "*")
	startswith(asked, trim_right(stored, "*"))
}
`

// joinData holds three policies: one that grants everything, one that grants
// managing the members of any policy, and one that grants reading.
const joinData = `{
  "policies": {
    "administrator-access": {
      "members": ["team:admins"],
      "statements": {"s": {"actions": ["*"], "resources": ["*"], "projects": ["project-a", "project-b"]}}
    },
    "member-editors": {
      "members": ["user:bob"],
      "statements": {"s": {"actions": ["iam:policyMembers:*"], "resources": ["iam:policies:*"], "projects": ["project-a"]}}
    },
    "viewers": {
      "members": ["user:alice"],
      "statements": {"s": {"actions": ["infra:nodes:get"], "resources": ["*"], "projects": ["project-a"]}}
    }
  }
}`

const joinModel = `schema_version: 1
model: write-paths
entries:
  - path: data.policies.{policy}.members.{member}
    writable_by:
      - principal: role:policy-member-editor
        via: "POST /apis/iam/v2/policies/{policy}/members:add"
        authorized_by:
          decision: data.authz.authorized_project
          request:
            input.action: "iam:policyMembers:create"
            input.resource: "iam:policies:{policy}:members"
`

// The escalation an IAM API of this shape carries: whoever may manage the
// members of a policy may add themselves to it, and the policy that grants
// everything is one of them.
func TestSplitGrantFindsAJoin(t *testing.T) {
	a := analysisOf(t, &FalsePositiveCase{Policy: joinPolicyBundle, Data: joinData, WriteModel: joinModel})

	findings, err := SplitGrant(t.Context(), a)
	if err != nil {
		t.Fatalf("SplitGrant() error = %v", err)
	}

	var bobToAdmins *Finding
	for i, f := range findings {
		if f.Principal == "user:bob" && f.Target == "team:admins" {
			bobToAdmins = &findings[i]
		}
		if f.Principal == "user:alice" {
			t.Errorf("alice was reported, and no policy of hers allows managing members: %s", f)
		}
	}
	if bobToAdmins == nil {
		t.Fatalf("the join from bob to the administrators is missing:\n%v", findings)
	}

	f := *bobToAdmins
	if f.Verdict != VerdictFinding || f.PatternID != WriteAllowedByAnotherDecision {
		t.Errorf("finding = %s under %s, want a finding of %s", f.Verdict, f.PatternID, WriteAllowedByAnotherDecision)
	}
	if f.Decision != "data.authz.authorized_project" || f.AuthorizedBy != "data.authz.authorized_project" {
		t.Errorf("decision = %q authorized by %q, want the same decision on both sides", f.Decision, f.AuthorizedBy)
	}
	if f.Value != "user:bob" {
		t.Errorf("value = %q, want the principal added, which is the subject", f.Value)
	}
	if f.ViaWritePath != "data.policies.{policy}.members.{member}" || f.Via != "POST /apis/iam/v2/policies/{policy}/members:add" {
		t.Errorf("written at %q via %q", f.ViaWritePath, f.Via)
	}
	if f.Subject != "input.subjects[_]" {
		t.Errorf("subject = %q, want the element of the list", f.Subject)
	}
	if len(f.Reads) == 0 {
		t.Error("the finding points at no line of policy to check it against")
	}
}

// A principal already in the collection has no join to make, and the pattern
// does not report one.
func TestSplitGrantLeavesAMemberAlone(t *testing.T) {
	a := analysisOf(t, &FalsePositiveCase{Policy: joinPolicyBundle, Data: joinData, WriteModel: joinModel})

	findings, err := SplitGrant(t.Context(), a)
	if err != nil {
		t.Fatalf("SplitGrant() error = %v", err)
	}
	for _, f := range findings {
		if f.Principal == "team:admins" && f.Target == "team:admins" {
			t.Errorf("a principal was reported joining what they are already in: %s", f)
		}
	}
}

// What the endpoint fills in itself is what keeps the question about a write.
// Without it the pattern asks whether the principal can make some request about
// that resource, and a reader answers yes: alice, who may only read, comes out
// as somebody who can add members.
func TestSplitGrantNarrowsTheJoinToTheRequestTheEndpointSends(t *testing.T) {
	model := strings.ReplaceAll(joinModel, `          request:
            input.action: "iam:policyMembers:create"
            input.resource: "iam:policies:{policy}:members"
`, "")
	a := analysisOf(t, &FalsePositiveCase{Policy: joinPolicyBundle, Data: joinData, WriteModel: model})

	findings, err := SplitGrant(t.Context(), a)
	if err != nil {
		t.Fatalf("SplitGrant() error = %v", err)
	}

	widened := slices.ContainsFunc(findings, func(f Finding) bool { return f.Principal == "user:alice" })
	if !widened {
		t.Error("alice is not reported even with the request left open, so this test proves nothing about why it is fixed")
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
