package openfga

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"github.com/openfga/openfga/pkg/server"

	"github.com/saluc28/petard/internal/zanzibar"
)

// agentSwarmDir is the agent-swarm OpenFGA fixture: an agent platform whose open
// delegation endpoint lets a session register a sub-session it spawns as a caller
// of a tool the session itself cannot call.
var agentSwarmDir = filepath.Join("..", "..", "..", "fixtures", "agent-swarm", "openfga")

// agentSwarmStore reads the store file of the fixture and the write model beside it.
func agentSwarmStore(t *testing.T) (*File, *zanzibar.WriteModel) {
	t.Helper()
	files, err := Find([]string{filepath.Join(agentSwarmDir, "store.fga.yaml")})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatalf("the store file reads as %d inputs, want 1", len(files))
	}
	wm, err := zanzibar.LoadWriteModel(filepath.Join(agentSwarmDir, "writes.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return files[0], wm
}

// agentSwarmModel is the text of the fixture's model, as a server takes it.
func agentSwarmModel(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(agentSwarmDir, "model.fga"))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// newAgentSwarmStore is a store of s holding the fixture's model and the tuples.
func newAgentSwarmStore(ctx context.Context, t *testing.T, s *server.Server, tuples []zanzibar.Relationship) oracleModel {
	t.Helper()
	store, err := s.CreateStore(ctx, &openfgav1.CreateStoreRequest{Name: "petard-agent-swarm"})
	if err != nil {
		t.Fatal(err)
	}
	model := oracleModel{server: s, store: store.GetId()}
	model.write(ctx, t, agentSwarmModel(t))
	keys := make([]*openfgav1.TupleKey, 0, len(tuples))
	for _, tuple := range tuples {
		keys = append(keys, tupleKeyOf(t, tuple))
	}
	model.writeTuples(ctx, t, keys)
	return model
}

// The one defect of the fixture is a delegation that does not narrow: the whole
// escalation is PTD-ZAN-006. The named planner, which may only audit the deploy
// tool, raises invoke on it, and the witness is a chain of two writes, it spawns a
// sub-session and then delegates the tool to it. OpenFGA carries no expiration, so
// the stale-authority aspect does not apply; the SpiceDB twin is where it does.
func TestAgentSwarmFixture(t *testing.T) {
	store, wm := agentSwarmStore(t)

	found := false
	for _, m := range zanzibar.Run(sampleOf(store), wm) {
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

	// With no write model nothing is reported: the model carries no condition, so
	// there is not even a self-asserted-exemption candidate.
	if got := zanzibar.Run(sampleOf(store), nil); len(got) != 0 {
		t.Errorf("with no write model it reports %d matches, want none", len(got))
	}

	planner := zanzibar.Object{Type: "user", ID: "11111111-1111-1111-1111-111111111111"}
	deploy := zanzibar.Object{Type: "tool", ID: "deploy"}
	classified, err := zanzibar.Classify(store.Schema.Model, wm, store.Schema, store.Relationships, []zanzibar.Object{planner}, zanzibar.Options{Now: time.Now()})
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
	if invoke.DefeatsExpiry {
		t.Error("DefeatsExpiry is set, but OpenFGA carries no expiration")
	}
}

// The checks the store file asserts are the answers OpenFGA gives on the file as
// it stands: the planner may audit the deploy tool and not call it, and the
// releaser may call it.
func TestAgentSwarmFixtureChecksHoldOnCheck(t *testing.T) {
	ctx := t.Context()
	s := newFixtureServer(t)
	store, _ := agentSwarmStore(t)
	model := newAgentSwarmStore(ctx, t, s, store.Relationships)
	if len(store.Assertions) == 0 {
		t.Fatal("the store file asserts no check")
	}
	for _, check := range store.Assertions {
		allowed, err := model.check(ctx, t, check)
		if err != nil {
			t.Errorf("%s: %v", check, err)
			continue
		}
		if allowed != (check.Level == zanzibar.Yes) {
			t.Errorf("%s: OpenFGA says %v, the file says %s", check, allowed, check.Level)
		}
	}
}

// Every escalation the engine finds for the planner is one OpenFGA's own Check
// shows: from the tuples of the store the permission is not allowed, and after the
// writes of the witness, made in order, it is allowed for the planner or for a
// session the witness spawned.
func TestAgentSwarmFixtureWitnessHoldsOnCheck(t *testing.T) {
	ctx := t.Context()
	s := newFixtureServer(t)
	store, wm := agentSwarmStore(t)
	schema := store.Schema
	planner := zanzibar.Object{Type: "user", ID: "11111111-1111-1111-1111-111111111111"}

	classified, err := zanzibar.Classify(schema.Model, wm, schema, store.Relationships, []zanzibar.Object{planner}, zanzibar.Options{Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if len(classified) == 0 {
		t.Fatal("the planner raises nothing to replay")
	}
	for _, esc := range classified {
		replayAgentSwarmWitness(ctx, t, s, store.Relationships, planner, esc)
	}
}

// replayAgentSwarmWitness makes the writes of an escalation on a new store and
// asks Check for the permission before and after.
func replayAgentSwarmWitness(ctx context.Context, t *testing.T, s *server.Server, start []zanzibar.Relationship, attacker zanzibar.Object, esc zanzibar.ClassifiedEscalation) {
	t.Helper()
	model := newAgentSwarmStore(ctx, t, s, start)
	asks := func(o zanzibar.Object) zanzibar.Assertion {
		return zanzibar.Assertion{Resource: esc.Object, Name: esc.Permission, Subject: zanzibar.Subject{Object: o}}
	}

	if allowed, _ := model.check(ctx, t, asks(attacker)); allowed {
		t.Errorf("%s: Check allows it before the writes: %v", asks(attacker), esc.Writes)
		return
	}

	coalition := []zanzibar.Object{attacker}
	for _, step := range esc.Writes {
		if step.Created != (zanzibar.Object{}) {
			coalition = append(coalition, step.Created)
		}
		if step.Relationship.Resource == (zanzibar.Object{}) {
			continue
		}
		key := tupleKeyOf(t, step.Relationship)
		request := &openfgav1.WriteRequest{StoreId: model.store, AuthorizationModelId: model.id}
		if step.Delete {
			request.Deletes = &openfgav1.WriteRequestDeletes{TupleKeys: []*openfgav1.TupleKeyWithoutCondition{
				{User: key.GetUser(), Relation: key.GetRelation(), Object: key.GetObject()},
			}}
		} else {
			request.Writes = &openfgav1.WriteRequestWrites{TupleKeys: []*openfgav1.TupleKey{key}}
		}
		if _, err := s.Write(ctx, request); err != nil {
			t.Errorf("%s: OpenFGA refuses a write of the witness, %s: %v", asks(attacker), step.Relationship, err)
			return
		}
	}

	for _, member := range coalition {
		if allowed, _ := model.check(ctx, t, asks(member)); allowed {
			return
		}
	}
	t.Errorf("%s: Check does not allow it for %v after the writes %v", asks(attacker), coalition, esc.Writes)
}
