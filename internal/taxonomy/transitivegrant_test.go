package taxonomy

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"github.com/saluc28/petard/internal/opaengine"
)

// The case and the counter cases of PTD-OPA-003 on the real fixture.
//
// dave is a member of one project that holds no document at all, and reaches
// the whole dataset through it. Everybody else is a counter case, and bob is
// the one worth naming: he reaches plenty, and none of it comes from the
// hierarchy, so a pattern that measured reach instead of amplification would
// report him.
func TestTransitiveGrantOnFixture(t *testing.T) {
	reads, shape, _ := analyzeFixture(t)
	bundle := fixtureBundle(t)

	findings, err := TransitiveGrant(t.Context(), bundle, reads, shape, fixtureData(t), opaengine.Limits{})
	if err != nil {
		t.Fatalf("TransitiveGrant() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want the one position that lives off the hierarchy:\n%v", len(findings), findings)
	}

	finding := findings[0]
	if finding.Principal != "dave" {
		t.Errorf("principal = %q, want dave", finding.Principal)
	}
	if finding.Verdict != VerdictCandidate {
		t.Errorf("verdict = %s, want a candidate: a hierarchy that propagates access is doing its job", finding.Verdict)
	}
	if finding.Decision != "data.quill.authz.allow" {
		t.Errorf("decision = %q", finding.Decision)
	}
	if finding.ReachTransitive != 18 || finding.ReachDirect != 0 {
		t.Errorf("reach = %d with the relation and %d without it, want 18 and 0",
			finding.ReachTransitive, finding.ReachDirect)
	}
	if expected := []string{"data.projects[_].parent"}; !slices.Equal(finding.Relation, expected) {
		t.Errorf("relation = %v, want %v", finding.Relation, expected)
	}
	if finding.Confidence != "D" {
		t.Errorf("confidence = %q, want the level the subject was recognized at", finding.Confidence)
	}
	if len(finding.Reads) != 1 || finding.Reads[0].Ref != "graph.reachable" {
		t.Errorf("places to look = %v, want the call that follows the relation", finding.Reads)
	}
}

// The trap of section 5 of the fixture, seen from the pattern that would fall
// into it.
//
// graph.reachable includes a node only if that node is a key of the graph
// object, so an adjacency list written the natural way leaves the root out and
// the policy grants a member of the root nothing at all. A pattern that walked
// the relation itself, with gonum or anything else, would answer the
// mathematical question and report the same position as worth every document in
// both columns of this table. Here the two columns differ, and they differ
// because OPA evaluated the construct the policy really uses.
func TestTransitiveGrantFollowsTheConstructThePolicyUses(t *testing.T) {
	const adjacency = `parent_of[child] := parents if {
	some child, project in data.projects
	parents := [%s]
}`

	tests := []struct {
		name     string
		parents  string
		findings int
	}{
		{name: "every project is a key of the graph", parents: "p | p := project.parent", findings: 1},
		{name: "the root has no entry of its own", parents: "project.parent", findings: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bundle, reads, data := analyze(t, hierarchyPolicy(fmt.Sprintf(adjacency, tt.parents)), hierarchyData)

			findings, err := TransitiveGrant(t.Context(), bundle, reads,
				opaengine.RecognizeShape(reads), data, opaengine.Limits{})
			if err != nil {
				t.Fatalf("TransitiveGrant() error = %v", err)
			}
			if len(findings) != tt.findings {
				t.Errorf("findings = %d, want %d:\n%v", len(findings), tt.findings, findings)
			}
		})
	}
}

// A policy with no transitive construct has nothing for this pattern to
// measure, and the answer is silence rather than a measurement of zero.
func TestTransitiveGrantWithoutAHierarchy(t *testing.T) {
	bundle, reads, data := analyze(t, `package t

# METADATA
# scope: document
# entrypoint: true
default allow := false

allow if data.users[input.user].active
`, `{"users": {"dave": {"active": true}}}`)

	findings, err := TransitiveGrant(t.Context(), bundle, reads,
		opaengine.RecognizeShape(reads), data, opaengine.Limits{})
	if err != nil {
		t.Fatalf("TransitiveGrant() error = %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("findings = %v, want none: nothing here follows a relation", findings)
	}
}

func TestTransitiveGrantNeedsTheData(t *testing.T) {
	reads, shape, _ := analyzeFixture(t)

	_, err := TransitiveGrant(t.Context(), fixtureBundle(t), reads, shape, nil, opaengine.Limits{})
	if !errors.Is(err, ErrNeedsData) {
		t.Errorf("TransitiveGrant() error = %v, want ErrNeedsData", err)
	}
}

// A policy written allow and not deny carries its deny into every residual
// condition. When partial evaluation cannot inline the negation, the deny comes
// back as a rule of its own that the comparison cannot read, and whether a
// write that makes alice an owner opens the delete it seems to open is settled
// by asking the decision about that delete, before the write and after it.
func TestReachOverAsksAboutTheRequestPastADeny(t *testing.T) {
	const policy = `package t

# METADATA
# scope: document
# entrypoint: true
default authz := false

authz if {
	allow
	not deny
}

allow if input.action == "read"

allow if {
	input.action == "delete"
	data.roles[input.user] == "owner"
}

`
	tests := []struct {
		name    string
		deny    string
		beyond  bool
		certain bool
	}{
		{
			// Inlined, the deny is read like any other condition.
			name:    "a deny partial evaluation inlines",
			deny:    `deny if input.blocked == true`,
			beyond:  true,
			certain: true,
		},
		{
			// The deny refuses other requests, so the delete gets through.
			name:    "a deny on other requests",
			deny:    `deny if { lower(input.action) == "create"; input.level != "admin" }`,
			beyond:  true,
			certain: true,
		},
		{
			name:    "a deny on the resources it names",
			deny:    `deny if { some tag in input.tags; tag == "frozen" }`,
			beyond:  true,
			certain: true,
		},
		{
			// Deletes are switched off for everybody, so the owner gains
			// nothing and no request proves otherwise.
			name:    "a deny on every delete",
			deny:    `deny if lower(input.action) == "delete"`,
			beyond:  false,
			certain: false,
		},
	}

	request := map[string]any{"user": "alice"}
	unknowns := []string{"input.action", "input.blocked", "input.level", "input.tags"}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bundle, _, before := analyze(t, policy+tt.deny+"\n", `{"roles": {"alice": "viewer"}}`)
			_, _, after := analyze(t, policy+tt.deny+"\n", `{"roles": {"alice": "owner"}}`)

			now, err := reachOf(t.Context(), bundle, before, "data.t.authz", request, unknowns, opaengine.Limits{})
			if err != nil {
				t.Fatalf("reachOf(before) error = %v", err)
			}
			then, err := reachOf(t.Context(), bundle, after, "data.t.authz", request, unknowns, opaengine.Limits{})
			if err != nil {
				t.Fatalf("reachOf(after) error = %v", err)
			}

			found, err := then.over(t.Context(), now, nil)
			if err != nil {
				t.Fatalf("over() error = %v", err)
			}
			if found.beyond != tt.beyond || found.certain != tt.certain {
				t.Errorf("over() = (%t, %t), want (%t, %t)", found.beyond, found.certain, tt.beyond, tt.certain)
			}
			if tt.beyond && found.request == nil {
				t.Error("over() found no request that shows the gain")
			}
		})
	}
}

// A decision that lets an administrator do anything, and an editor put, grants
// alice's put either way. The example is alice's put as an editor. The other
// request also claims alice is an administrator, which the question never said.
func TestReachExampleClaimsTheFewestParts(t *testing.T) {
	const policy = `package t

# METADATA
# scope: document
# entrypoint: true
default authz := false

authz if {
	input.role == "admin"
	input.scope == "all"
}

authz if {
	input.method == "PUT"
	data.roles[input.user] == "editor"
}
`
	bundle, _, data := analyze(t, policy, `{"roles": {"alice": "editor"}}`)

	// The conditions come in the order that puts the administrator first, which
	// is the order partial evaluation is free to return them in.
	residuals := &opaengine.ResidualSet{Conditions: []opaengine.Condition{
		{Query: `input.role = "admin"; input.scope = "all"`, Value: "true"},
		{Query: `input.method = "PUT"`, Value: "true"},
	}}
	allowed := reach{
		ways:     2,
		content:  opaengine.GrantContentOf(residuals),
		bundle:   bundle,
		data:     data,
		decision: "data.t.authz",
		request:  map[string]any{"user": "alice"},
	}

	request, err := allowed.example(t.Context())
	if err != nil {
		t.Fatalf("example() error = %v", err)
	}
	if want := map[string]any{"user": "alice", "method": "PUT"}; !reflect.DeepEqual(request, want) {
		t.Errorf("example() = %v, want %v", request, want)
	}
}

// hierarchyPolicy is the shape of a policy that grants through a hierarchy,
// with the adjacency rule left to the caller: it is the line the trap lives on.
func hierarchyPolicy(adjacency string) string {
	return `package t

# METADATA
# scope: document
# entrypoint: true
default allow := false

allow if {
	data.users[input.user].active
	doc := data.documents[input.doc]
	some anc in ancestors_of(doc.project)
	input.user in data.projects[anc].members
}

ancestors_of(proj) := graph.reachable(parent_of, {proj})

` + adjacency + "\n"
}

// hierarchyData holds one member of the root and one member of nothing, plus a
// document that hangs off a leaf.
const hierarchyData = `{
	"users": {"dave": {"active": true}, "mallory": {"active": true}},
	"projects": {
		"root": {"members": ["dave"]},
		"leaf": {"parent": "root", "members": []}
	},
	"documents": {"d1": {"project": "leaf"}}
}`
