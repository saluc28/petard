package taxonomy

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/saluc28/petard/internal/graph"
	"github.com/saluc28/petard/internal/opaengine"
)

// fixtureAnalysis is everything the chain needs about the fixture.
func fixtureAnalysis(t *testing.T) Analysis {
	t.Helper()

	reads, shape, model := analyzeFixture(t)
	return Analysis{
		Bundle:           fixtureBundle(t),
		Reads:            reads,
		Shape:            shape,
		Model:            model,
		Data:             fixtureData(t),
		EnforcementPoint: fixtureGateway(t),
	}
}

// chainOn runs both patterns and then the chain, which is the only honest way
// to test it: its inputs have to be what the two patterns really produce.
func chainOn(t *testing.T, a Analysis) []Finding {
	t.Helper()

	selfWrite, err := SelfWrite(a.Reads, a.Shape, a.Model)
	if err != nil {
		t.Fatalf("SelfWrite() error = %v", err)
	}
	positions, err := TransitiveGrant(t.Context(), a.Bundle, a.Reads, a.Shape, a.Data, a.Limits)
	if err != nil {
		t.Fatalf("TransitiveGrant() error = %v", err)
	}
	escalations, err := Escalations(t.Context(), a, selfWrite, positions)
	if err != nil {
		t.Fatalf("Escalations() error = %v", err)
	}
	return escalations
}

// The central criterion, and the only claim in the whole
// registry that deserves the words privilege escalation.
//
// mallory holds nothing: no membership, no document, the viewer role. Writing
// one field of her own profile, from the self service form the write model
// declares, puts her where dave stands, and dave's position is the one the
// transitive pattern measured as worth the entire dataset.
//
// The numbers are ways rather than documents, as everywhere the count comes out
// of partial evaluation: nothing today, fifty five ways once the field is left
// open, and thirty six of those go through the hierarchy. It is that last
// number that ties the two patterns together instead of leaving them side by
// side.
func TestEscalationsOnFixture(t *testing.T) {
	findings := chainOn(t, fixtureAnalysis(t))

	if len(findings) != 1 {
		t.Fatalf("escalations = %d, want the one the fixture injects:\n%v", len(findings), findings)
	}

	finding := findings[0]
	if finding.Principal != "mallory" || finding.Target != "dave" {
		t.Errorf("chain = %s to %s, want mallory to dave", finding.Principal, finding.Target)
	}
	if finding.Verdict != VerdictFinding {
		t.Errorf("verdict = %s, want a finding: the position is taken, not just worth taking", finding.Verdict)
	}
	if finding.PatternID != TransitiveGrantViaOwnership {
		t.Errorf("pattern = %s, want the transitive grant, which the registry says becomes a finding here",
			finding.PatternID)
	}
	if finding.ViaWritePath != "data.users.{owner}.profile.department" {
		t.Errorf("via write path = %q, want the entry of the write model", finding.ViaWritePath)
	}
	if finding.Via != "PATCH /api/v1/me/profile" {
		t.Errorf("via = %q, want how the write happens: a finding without the how is not actionable", finding.Via)
	}
	if finding.ReachTransitive != 55 || finding.ReachDirect != 19 {
		t.Errorf("reach = %d with the hierarchy and %d without it, want 55 and 19",
			finding.ReachTransitive, finding.ReachDirect)
	}
	if len(finding.Reads) != 3 {
		t.Errorf("places to look = %d, want the two reads and the call that follows the relation", len(finding.Reads))
	}

	// The same request and the same value the fixture's measuring instrument
	// writes by hand (verify/measure.rego, chain_decision_after): with platform
	// written, mallory reads a document of a team below the division, which she
	// reaches only through the hierarchy.
	want := &Witness{
		Decision: "data.quill.authz.allow",
		Request:  map[string]any{"user": "mallory", "action": "read", "doc": "d-t11-1"},
		Document: "data.users.mallory.profile.department",
		Value:    "platform",
	}
	if !reflect.DeepEqual(finding.Witness, want) {
		t.Errorf("witness = %+v, want %+v", finding.Witness, want)
	}
	witnessHolds(t, fixtureAnalysis(t), finding.Witness)
}

// witnessHolds checks a witness the way anybody could without Petard: the
// decision that authorizes the write allows it, when the policy authorizes it,
// and the granting decision refuses the request with the data as it stands and
// grants it with the one document replaced.
func witnessHolds(t *testing.T, a Analysis, w *Witness) {
	t.Helper()

	if w == nil {
		t.Fatal("the escalation comes with no request that shows it")
	}
	if w.AuthorizedBy != "" {
		allowed, err := opaengine.Holds(t.Context(), a.Bundle, a.Data, w.AuthorizedBy, w.WriteRequest)
		if err != nil {
			t.Fatalf("Holds() on the write error = %v", err)
		}
		if !allowed {
			t.Errorf("%s refuses the write %v", w.AuthorizedBy, w.WriteRequest)
		}
	}
	before, err := opaengine.Holds(t.Context(), a.Bundle, a.Data, w.Decision, w.Request)
	if err != nil {
		t.Fatalf("Holds() before the write error = %v", err)
	}
	if before {
		t.Errorf("%s grants %v before the write, so the request shows nothing", w.Decision, w.Request)
	}

	written, err := a.Data.With(t.Context(), w.Document, w.Value)
	if err != nil {
		t.Fatalf("With(%s) error = %v", w.Document, err)
	}
	after, err := opaengine.Holds(t.Context(), a.Bundle, written, w.Decision, w.Request)
	if err != nil {
		t.Fatalf("Holds() after the write error = %v", err)
	}
	if !after {
		t.Errorf("%s refuses %v with %s as %v", w.Decision, w.Request, w.Document, w.Value)
	}
}

// chainClaimPolicy is the chain of the fixture in a few lines: a document hangs
// off a leaf, dave is a member of the root, and membership also follows the
// department, which each user writes. Reading through the hierarchy asks for a
// clearance the provider puts next to the subject.
const chainClaimPolicy = `package chain

import rego.v1

# METADATA
# scope: document
# entrypoint: true
default allow := false

allow if {
	input.action == "read"
	doc := data.documents[input.doc]
	some anc in ancestors_of(doc.project)
	is_member(input.subject.id, anc)
	input.subject.clearance == "high"
}

is_member(user, proj) if user in data.projects[proj].members

is_member(user, proj) if data.users[user].department == data.projects[proj].department

parent_of[child] := parents if {
	some child, project in data.projects
	parents := [p | p := project.parent]
}

ancestors_of(proj) := graph.reachable(parent_of, {proj})
`

const chainClaimData = `{
  "users": {"dave": {"department": "ops"}, "mallory": {"department": "sales"}},
  "projects": {
    "root": {"members": ["dave"], "department": "platform"},
    "leaf": {"parent": "root", "members": []}
  },
  "documents": {"d1": {"project": "leaf"}}
}`

const chainClaimModel = `schema_version: 1
model: write-paths
entries:
  - path: data.users.{owner}.department
    writable_by:
      - principal: "{owner}"
        via: "PATCH /me"
`

// mallory can write platform into their department and reach what dave's
// position reaches, but reading through the hierarchy asks for a clearance
// nothing says mallory holds. The chain is then a candidate that says so, and
// without the clearance in the policy it is a finding.
func TestEscalationsLeaveAChainThatNeedsAClaimACandidate(t *testing.T) {
	for _, tt := range []struct {
		name    string
		policy  string
		verdict Verdict
	}{
		{name: "reading asks for a clearance", policy: chainClaimPolicy, verdict: VerdictCandidate},
		{
			name:    "reading asks for none",
			policy:  strings.Replace(chainClaimPolicy, "\tinput.subject.clearance == \"high\"\n", "", 1),
			verdict: VerdictFinding,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a := analysisOf(t, &FalsePositiveCase{Policy: tt.policy, Data: chainClaimData, WriteModel: chainClaimModel})
			shape, err := opaengine.ShapeOf(a.Reads, "input.subject.id")
			if err != nil {
				t.Fatalf("ShapeOf() error = %v", err)
			}
			a.Shape = shape

			findings := chainOn(t, a)
			if len(findings) != 1 || findings[0].Principal != "mallory" || findings[0].Target != "dave" {
				t.Fatalf("chain = %v, want mallory reaching dave", findings)
			}
			f := findings[0]
			if f.Verdict != tt.verdict {
				t.Errorf("verdict = %s, want %s", f.Verdict, tt.verdict)
			}
			if tt.verdict == VerdictCandidate && f.Note == "" {
				t.Error("the candidate does not say it rests on a claim")
			}
		})
	}
}

// Everybody else in the fixture already gets something out of that decision, so
// what a write would buy them is more of it rather than a way in. Saying how
// much more needs a threshold, and the threshold is the open question the
// transitive pattern declares: until it is measured, this reports the case that
// needs no threshold at all.
func TestEscalationsLeaveAloneWhoeverAlreadyHolds(t *testing.T) {
	for _, finding := range chainOn(t, fixtureAnalysis(t)) {
		switch finding.Principal {
		case "alice", "bob", "carol", "dave":
			t.Errorf("a principal who already gets something was reported: %s", finding)
		}
	}
}

// Without the declaration of who writes what, the self write pattern only
// produces candidates, and a chain built on a candidate would rest the whole
// claim on something nobody declared.
func TestEscalationsNeedTheWriteModel(t *testing.T) {
	a := fixtureAnalysis(t)
	a.Model = nil

	if findings := chainOn(t, a); len(findings) != 0 {
		t.Errorf("escalations = %v, want none: nobody declared that the field is writable", findings)
	}
}

func TestEscalationsNeedTheData(t *testing.T) {
	a := fixtureAnalysis(t)
	a.Data = nil

	_, err := Escalations(t.Context(), a, nil, nil)
	if !errors.Is(err, ErrNeedsData) {
		t.Errorf("Escalations() error = %v, want ErrNeedsData", err)
	}
}

// The chain is the one thing in the analysis that becomes an edge between two
// people, and it is the edge BloodHound is allowed to walk. The principals are
// nodes the policy never mentions: they come from the data and from a
// declaration about who writes it, which is the crossing the project is about.
func TestAddEscalationsPutsThePathInTheGraph(t *testing.T) {
	a := fixtureAnalysis(t)

	g, err := opaengine.BuildGraph(a.Reads)
	if err != nil {
		t.Fatalf("BuildGraph() error = %v", err)
	}
	if err := AddEscalations(g, chainOn(t, a)); err != nil {
		t.Fatalf("AddEscalations() error = %v", err)
	}

	var escalations int
	for _, edge := range g.Edges() {
		if edge.Kind != graph.EdgeKindCanEscalateTo {
			continue
		}
		escalations++
		if edge.From != "mallory" || edge.To != "dave" {
			t.Errorf("edge = %s to %s, want mallory to dave", edge.From, edge.To)
		}
		if !edge.Kind.IsTraversable() {
			t.Error("the one edge that represents escalation is not traversable, so no path will show in the UI")
		}
		if edge.Source.File == "" || edge.Source.Line == 0 {
			t.Errorf("the edge points at no line of policy: %+v", edge.Source)
		}

		// The proof travels on the edge as JSON, the way a request body
		// carries it, since BloodHound takes no object as a property.
		for property, want := range map[string]any{
			graph.PropWitnessRequest:  `{"action":"read","doc":"d-t11-1","user":"mallory"}`,
			graph.PropWitnessDocument: "data.users.mallory.profile.department",
			graph.PropWitnessValue:    `"platform"`,
		} {
			if got := edge.Properties[property]; got != want {
				t.Errorf("%s = %v, want %v", property, got, want)
			}
		}
	}
	if escalations != 1 {
		t.Errorf("escalation edges = %d, want 1", escalations)
	}

	for _, name := range []string{"mallory", "dave"} {
		node, found := g.Node(name)
		if !found {
			t.Fatalf("%s is not in the graph", name)
		}
		if node.Kind != graph.NodeKindPrincipal {
			t.Errorf("%s is a %s, want a principal", name, node.Kind)
		}
	}
}
