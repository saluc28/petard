package taxonomy

import (
	"errors"
	"fmt"
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
