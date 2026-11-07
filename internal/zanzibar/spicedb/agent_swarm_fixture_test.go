package spicedb

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/saluc28/petard/internal/zanzibar"
)

// agentSwarmValidation and agentSwarmWrites are the SpiceDB twin of the
// agent-swarm fixture: the same delegation defect as the OpenFGA model beside it,
// plus the expiration SpiceDB can express. TestOracle holds its answers to
// SpiceDB too.
var (
	agentSwarmValidation = filepath.Join("..", "..", "..", "fixtures", "agent-swarm", "spicedb", "validation.yaml")
	agentSwarmWrites     = filepath.Join("..", "..", "..", "fixtures", "agent-swarm", "spicedb", "writes.yaml")
)

// The one defect is a delegation that does not narrow, so the whole escalation is
// PTD-ZAN-006. The named planner, which may only audit the deploy tool, raises
// invoke on it; the witness is a chain of two writes, it spawns a sub-session and
// delegates the tool to it; and because the caller grant carries an expiration the
// writer sets, the raise also defeats a time bound, which the OpenFGA twin cannot
// express.
func TestAgentSwarmFixture(t *testing.T) {
	file := findOne(t, agentSwarmValidation)
	wm, err := zanzibar.LoadWriteModel(agentSwarmWrites)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, m := range zanzibar.Run(file.Sample(time.Now()), wm) {
		if m.Verdict != zanzibar.Finding {
			t.Errorf("%s: %s, want a finding", m.Subject, m.Verdict)
		}
		if m.PatternID != "PTD-ZAN-006" {
			t.Errorf("%s: %s, want PTD-ZAN-006 alone", m.Subject, m.PatternID)
		}
		found = true
	}
	if !found {
		t.Fatal("the fixture reports no finding")
	}

	// With no write model nothing is reported: the schema carries no caveat, so
	// there is not even a self-asserted-exemption candidate.
	if got := zanzibar.Run(file.Sample(time.Now()), nil); len(got) != 0 {
		t.Errorf("with no write model it reports %d matches, want none", len(got))
	}

	planner := zanzibar.Object{Type: "user", ID: "11111111-1111-1111-1111-111111111111"}
	deploy := zanzibar.Object{Type: "tool", ID: "deploy"}
	classified, err := zanzibar.Classify(file.Schema.Model, wm, file.Schema, file.Relationships, []zanzibar.Object{planner}, zanzibar.Options{Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	var invoke *zanzibar.ClassifiedEscalation
	for i := range classified {
		if classified[i].Object == deploy && classified[i].Permission == "invoke" {
			invoke = &classified[i]
		}
	}
	if invoke == nil {
		t.Fatalf("the planner does not raise invoke on %s; got %+v", deploy, classified)
	}
	if invoke.Category != zanzibar.CategoryDelegationNotNarrowed {
		t.Errorf("category = %s, want %s", invoke.Category, zanzibar.CategoryDelegationNotNarrowed)
	}
	if len(invoke.Writes) != 2 {
		t.Errorf("the witness is %d writes, want a chain of 2", len(invoke.Writes))
	}
	if !invoke.DefeatsExpiry {
		t.Error("DefeatsExpiry is not set, but the caller grant carries a writer-set expiration")
	}
}
