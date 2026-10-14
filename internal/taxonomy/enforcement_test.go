package taxonomy

import (
	"errors"
	"path/filepath"
	"slices"
	"testing"

	"github.com/saluc28/petard/internal/opaengine"
)

// gatewayAsking is a gateway that hands the policy the path of a call under a
// name no recognizer reads, and says so.
const gatewayAsking = `schema_version: 1
id: test-gateway
engine: opa
source:
  kind: documentation
  note: a gateway for the test
decisions:
  - rule: allow
    side: grants
subject: input.principal.agent_id
action: input.request.verb
resource: input.request.remainder_path
`

const policyAsking = `package p

# METADATA
# entrypoint: true
default allow := false

allow if {
	input.principal.agent_id != ""
	input.method == "GET"
	startswith(input.request.remainder_path, "/do/")
}
`

// What is asked for is taken from where it is declared, the command line ahead
// of the enforcement point, and recognized when neither says. A part the
// enforcement point declares and no decision reads is recognized as if nothing
// had been said about it, as its subject is; one named on the command line and
// read nowhere is refused, as a typo.
func TestShapeOfTakesWhatIsAskedForFromWhereItIsDeclared(t *testing.T) {
	declared := analysisWithGateway(t, policyAsking, gatewayAsking)

	// The policy reads the path the gateway declares and not the verb, so the
	// resource is declared and the action is left out: the declaration replaces
	// what the names say for both, and input.method is not the action.
	target := declared.Shape.Target()
	if target.Resource != "input.request.remainder_path" || target.Action != "" ||
		target.Confidence != opaengine.ConfidenceDeclared || target.Recognizer != "declared" {
		t.Errorf("from the enforcement point, asked for = %+v, want the declared path at level A and no action", target)
	}
	if declared.Shape.Subject != "input.principal.agent_id" || declared.Shape.Confidence != opaengine.ConfidenceDeclared {
		t.Errorf("subject = %s at level %s, want the declared one", declared.Shape.Subject, declared.Shape.Confidence)
	}

	tests := []struct {
		name     string
		inputs   Inputs
		action   string
		resource string
		level    opaengine.Confidence
		err      error
	}{
		{
			name:   "the command line ahead of the enforcement point",
			inputs: Inputs{Action: "input.method", Resource: "input.request.remainder_path"},
			action: "input.method", resource: "input.request.remainder_path", level: opaengine.ConfidenceDeclared,
		},
		{
			name:     "a resource alone replaces what is recognized for both",
			inputs:   Inputs{Resource: "input.request"},
			resource: "input.request", level: opaengine.ConfidenceDeclared,
		},
		{name: "a part no decision reads", inputs: Inputs{Resource: "input.request.url"}, err: opaengine.ErrTargetNotRead},
		{name: "a part outside the request", inputs: Inputs{Action: "data.methods"}, err: opaengine.ErrBadTarget},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shape, err := ShapeOf(declared.Reads, tt.inputs, declared.EnforcementPoint)
			if !errors.Is(err, tt.err) {
				t.Fatalf("ShapeOf() error = %v, want %v", err, tt.err)
			}
			if tt.err != nil {
				return
			}
			target := shape.Target()
			if target.Action != tt.action || target.Resource != tt.resource || target.Confidence != tt.level {
				t.Errorf("asked for = %+v, want %q and %q at level %s", target, tt.action, tt.resource, tt.level)
			}
		})
	}

	// With nothing declared the names are read: the method, and no resource,
	// since no field of this request is called like one.
	recognized, err := ShapeOf(declared.Reads, Inputs{}, nil)
	if err != nil {
		t.Fatalf("ShapeOf() error = %v", err)
	}
	if target := recognized.Target(); target.Action != "input.method" || target.Resource != "" ||
		target.Confidence != opaengine.ConfidenceNames {
		t.Errorf("recognized, asked for = %+v, want the method by its name and no resource", target)
	}
}

// A resource somebody declared is the one PTD-OPA-012 reads a loose match on,
// at the level of a declaration. Recognized by name alone, this request has no
// resource and the prefix on the path goes unreported.
func TestLooseMatchOnADeclaredResource(t *testing.T) {
	declared := analysisWithGateway(t, policyAsking, gatewayAsking)

	findings := GrantsOnLooseMatches(declared)
	if len(findings) != 1 {
		t.Fatalf("findings = %v, want one", findings)
	}
	if finding := findings[0]; finding.Path != "input.request.remainder_path" ||
		finding.Verdict != VerdictCandidate || finding.Confidence != "A" {
		t.Errorf("a %s on %s at level %s, want a candidate on the declared path at level A",
			finding.Verdict, finding.Path, finding.Confidence)
	}

	recognized := declared
	shape, err := ShapeOf(declared.Reads, Inputs{}, nil)
	if err != nil {
		t.Fatalf("ShapeOf() error = %v", err)
	}
	recognized.Shape = shape
	if findings := GrantsOnLooseMatches(recognized); len(findings) != 0 {
		t.Errorf("with nothing declared, findings = %v, want none: no name says the path is the resource", findings)
	}
}

// A product that reads one field of what a rule returns, and lets the request
// through on one value of it, says so in its declaration, and the bundle is
// asked for that field on that answer: the refusal the rule also returns is not
// a grant.
func TestDeclareEnforcementPointTakesTheFieldAndTheAnswers(t *testing.T) {
	const policy = `package sts

default result := {"decision": "deny", "why": "no_rule_matched"}

result := {"decision": "allow", "why": "owner"} if input.owner == "alice"

result := {"decision": "deny", "why": "suspended"} if input.suspended
`
	const gateway = `schema_version: 1
id: test-sts
engine: opa
source:
  kind: documentation
  note: a token service for the test
decisions:
  - rule: result
    side: grants
    field: decision
    answers: [allow]
`
	dir := t.TempDir()
	writeCaseFile(t, filepath.Join(dir, "policy", "p.rego"), policy)
	writeCaseFile(t, filepath.Join(dir, "pep.yaml"), gateway)
	bundle, err := opaengine.Load([]string{filepath.Join(dir, "policy")}, opaengine.ParseModeAuto)
	if err != nil {
		t.Fatalf("the policy does not compile: %v", err)
	}

	if _, err := DeclareEnforcementPoint(bundle, filepath.Join(dir, "pep.yaml")); err != nil {
		t.Fatalf("DeclareEnforcementPoint() error = %v", err)
	}
	reads, err := opaengine.Reads(bundle, opaengine.Limits{})
	if err != nil {
		t.Fatalf("Reads() error = %v", err)
	}
	if !slices.Equal(reads.Decisions, []string{"data.sts.result.decision"}) ||
		!slices.Equal(reads.Answers["data.sts.result.decision"], []string{`"allow"`}) {
		t.Fatalf("decisions = %v with answers %v, want the field on the answer allow", reads.Decisions, reads.Answers)
	}

	for request, granted := range map[string]bool{"owner": true, "suspended": false} {
		input := map[string]any{"owner": "alice"}
		if request == "suspended" {
			input = map[string]any{"suspended": true}
		}
		holds, err := opaengine.Holds(t.Context(), bundle, opaengine.NoData(), "data.sts.result.decision", input)
		if err != nil {
			t.Fatalf("Holds() error = %v", err)
		}
		if holds != granted {
			t.Errorf("the request of the %s is granted %t, want %t", request, holds, granted)
		}
	}
}
