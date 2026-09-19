package taxonomy

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/saluc28/petard/internal/graph"
	"github.com/saluc28/petard/internal/opaengine"
	"github.com/saluc28/petard/internal/writemodel"
)

// declaredAnalysis loads a policy that annotates nothing, with its decisions
// declared from outside the way a caller declares them: to grant, or to deny.
func declaredAnalysis(t *testing.T, policy, data, model string, entrypoints, denying []string) Analysis {
	t.Helper()

	dir := t.TempDir()
	writeCaseFile(t, filepath.Join(dir, "policy", "policy.rego"), policy)
	bundle, err := opaengine.Load([]string{filepath.Join(dir, "policy")}, opaengine.ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	bundle.Entrypoints = entrypoints
	bundle.DenyEntrypoints = denying
	reads, err := opaengine.Reads(bundle, opaengine.Limits{})
	if err != nil {
		t.Fatalf("Reads() error = %v", err)
	}
	a := Analysis{Bundle: bundle, Reads: reads, Shape: opaengine.RecognizeShape(reads)}

	if data != "" {
		writeCaseFile(t, filepath.Join(dir, "data", "data.json"), data)
		if a.Data, err = opaengine.LoadData([]string{filepath.Join(dir, "data")}); err != nil {
			t.Fatalf("LoadData() error = %v", err)
		}
	}
	if model != "" {
		file := filepath.Join(dir, "write-model.yaml")
		writeCaseFile(t, file, model)
		if a.Model, err = writemodel.Load(file); err != nil {
			t.Fatalf("writemodel.Load() error = %v", err)
		}
	}
	return a
}

// The three fail-open patterns ask which side a check applies on, and a check
// written as a violation applies on the side that denies with no negation in
// front of it. Declared to deny, each of them finds its hole in a violation;
// declared to grant, the same rule reads as granting what it collects, and the
// hole is not where the pattern looks.
func TestTheFailOpenPatternsReadADecisionThatDenies(t *testing.T) {
	tests := []struct {
		name   string
		policy string
		data   string
		run    func(Analysis) ([]Finding, error)
	}{
		{
			name: DenyUndefinedOnMissingData,
			policy: `package t

violation contains "multi-factor authentication is required" if {
	data.tenants[input.tenant].policy.require_mfa == true
	not input.mfa
}
`,
			data: `{"tenants": {"berq": {"policy": {"require_mfa": true}}, "dolm": {}}}`,
			run: func(a Analysis) ([]Finding, error) {
				return FailOpenOnMissingData(t.Context(), a.Reads, a.Data)
			},
		},
		{
			name: FailOpenOnSourceUnavailable,
			policy: `package t

violation contains "the risk is too high" if {
	response := http.send({"method": "GET", "url": "https://risk.invalid/score", "raise_error": false})
	response.body.score > 80
}
`,
			run: func(a Analysis) ([]Finding, error) { return GrantsWhenSourceFails(a.Reads), nil },
		},
		{
			name: EveryOverEmptyDomain,
			policy: `package t

violation contains "an image is not signed" if not all_signed

all_signed if every image in input.images { data.signatures[image] }
`,
			run: func(a Analysis) ([]Finding, error) { return FailOpenOnEmptyEvery(a.Reads), nil },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			denying := declaredAnalysis(t, tt.policy, tt.data, "", nil, []string{"t/violation"})
			findings, err := tt.run(denying)
			if err != nil {
				t.Fatalf("run error = %v", err)
			}
			if len(findings) != 1 || findings[0].Decision != "data.t.violation" {
				t.Fatalf("findings = %v, want one on data.t.violation", findings)
			}
			if tt.name == DenyUndefinedOnMissingData && findings[0].EnforcingSide != enforcingSideDeclaredToDeny {
				t.Errorf("enforcing side = %q, want %q", findings[0].EnforcingSide, enforcingSideDeclaredToDeny)
			}
			if tt.name == EveryOverEmptyDomain && strings.Contains(findings[0].Summary, "grants") {
				t.Errorf("summary = %q, and a violation grants nothing", findings[0].Summary)
			}

			granting := declaredAnalysis(t, tt.policy, tt.data, "", []string{"t/violation"}, nil)
			if findings, err := tt.run(granting); err != nil || len(findings) != 0 {
				t.Errorf("declared to grant: findings = %v, error = %v, want none", findings, err)
			}
		})
	}
}

// lockedPolicy refuses to open a locked document to anybody but an
// administrator.
const lockedPolicy = `package t

deny if {
	data.documents[input.doc].locked
	not data.users[input.user].admin
}
`

const lockedData = `{"users": {"alice": {"admin": true}, "bob": {}}, "documents": {"d1": {"locked": true}, "d2": {}}}`

// What is left of a decision that denies is who gets refused where. bob is
// refused on d1, and an edge from bob to d1 would tell BloodHound that bob can
// open it. Declared to grant, the same rule draws that edge, which is what
// keeps this test from passing on a graph that draws nothing at all.
func TestADecisionThatDeniesDrawsNoCapability(t *testing.T) {
	capabilities := func(a Analysis) []graph.Edge {
		t.Helper()
		g, err := opaengine.BuildGraph(a.Reads)
		if err != nil {
			t.Fatalf("BuildGraph() error = %v", err)
		}
		if _, err := AddCapabilities(t.Context(), g, a); err != nil {
			t.Fatalf("AddCapabilities() error = %v", err)
		}
		return edgesOfKind(g, graph.EdgeKindCanPerform)
	}

	if edges := capabilities(declaredAnalysis(t, lockedPolicy, lockedData, "", []string{"t/deny"}, nil)); len(edges) == 0 {
		t.Fatal("declared to grant, the rule draws no capability, and this test would prove nothing")
	}
	if edges := capabilities(declaredAnalysis(t, lockedPolicy, lockedData, "", nil, []string{"t/deny"})); len(edges) != 0 {
		t.Errorf("declared to deny, the rule draws %d capabilities: %v", len(edges), edges)
	}
}

// A relation a decision that denies follows on the side that grants lifts a
// refusal, and measuring it would count the ways to be refused. The same
// closure on a decision that grants is measured as before.
func TestADecisionThatDeniesIsNotMeasuredForAHierarchy(t *testing.T) {
	reads := &opaengine.ReadSet{
		Closures: []opaengine.Closure{{
			Builtin:  "graph.reachable",
			Rule:     "data.t.within",
			Relation: []string{"data.teams[_].parent"},
			Decisions: []opaengine.ReachedDecision{
				{Name: "data.t.allow"},
				{Name: "data.t.violation"},
			},
		}},
		Denying: []string{"data.t.violation"},
	}

	relations := relationsPerDecision(reads)
	if len(relations) != 1 || relations["data.t.allow"] == nil {
		t.Errorf("relations = %v, want the decision that grants alone", relations)
	}
	sites := closureSites(reads)
	if len(sites) != 1 || sites["data.t.allow"] == nil {
		t.Errorf("sites = %v, want the decision that grants alone", sites)
	}
}

// A field a decision that denies reads under not is on the side that grants,
// and a writer another decision authorizes could lift the refusal: a value
// written into a field, or the subject added to a list. What the pattern would
// measure is what the violation compares with, the values that refuse, so it
// starts from neither.
func TestADecisionThatDeniesStartsNoSplitGrant(t *testing.T) {
	const policy = `package t

violation contains "the tier is too low" if not premium

premium if data.users[input.user].tier == "gold"

violation contains "not a member of the team" if not member

member if data.teams[input.team].members[_] == input.user
`
	const model = `schema_version: 1
model: write-paths
entries:
  - path: data.users.{user}.tier
    writable_by:
      - principal: role:support
        via: "PUT /users/{user}/tier"
        authorized_by:
          decision: data.t.assign
          value: input.tier
  - path: data.teams.{team}.members.{member}
    writable_by:
      - principal: role:team-manager
        via: "POST /teams/{team}/members"
        authorized_by:
          decision: data.t.manage
`
	a := declaredAnalysis(t, policy, "", model, nil, []string{"t/violation"})
	for _, read := range a.Reads.Reads {
		for _, decision := range read.Decisions {
			if decision.UnderNegation {
				t.Fatalf("%s reaches %s on the side that denies, and this test would prove nothing", read.Path, decision.Name)
			}
		}
	}

	if grants := authorizedGrants(a.Reads, a.Shape, a.Model); len(grants) != 0 {
		t.Errorf("starts on a field = %v, want none on a decision that denies", grants)
	}
	if joins := authorizedJoins(a.Reads, a.Shape, a.Model); len(joins) != 0 {
		t.Errorf("starts on a list = %v, want none on a decision that denies", joins)
	}
}
