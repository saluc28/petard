package openfga

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"slices"
	"testing"
	"time"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"github.com/openfga/language/pkg/go/transformer"
	"github.com/openfga/openfga/pkg/server"
	serverconfig "github.com/openfga/openfga/pkg/server/config"
	"github.com/openfga/openfga/pkg/storage/memory"
	"github.com/openfga/openfga/pkg/typesystem"
	yaml "go.yaml.in/yaml/v3"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/saluc28/petard/internal/zanzibar"
	"github.com/saluc28/petard/internal/zanzibar/zanzibartest"
)

// oracleWriteChunk is how many tuples one write of the oracle carries, below the
// limit a write takes (pkg/server/config/config.go:19 at v1.22.1).
const oracleWriteChunk = 40

// oracleCount is what a run of the oracle found.
type oracleCount struct {
	agreed, undecided, settled, dropped, loops, inline, depth int
}

// The engine against OpenFGA itself. For every stage of every test, those of testdata
// and OpenFGA's own, every check the stage's objects allow is answered by the engine
// and by Check of a real server in this process, over the same model and the same
// tuples. The subjects are the objects and the usersets the model allows, and each
// check is asked with no context and with every context the stage's assertions supply.
//
// The server runs as it ships, with inline conditions let through, which is all that
// flag gates (pkg/server/write.go:58-66, pkg/server/authorization_models.go:75-81).
func TestOracle(t *testing.T) {
	s, err := server.NewServerWithOpts(
		server.WithDatastore(memory.New()),
		server.WithExperimentals(serverconfig.ExperimentalInlineExpressions),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)

	raw, err := os.ReadFile("testdata/oracle.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var own corpusFile
	if err := yaml.Unmarshal(raw, &own); err != nil {
		t.Fatal(err)
	}

	var total oracleCount
	for _, test := range append(own.Tests, corpusTests(t)...) {
		t.Run(test.Name, func(t *testing.T) {
			oracleTest(t, s, test, &total)
		})
	}
	t.Logf("OpenFGA agrees on %d checks. Of those it refuses, %d read as conditional and %d are settled here whatever the condition says. %d more it answers by dropping a tuple it cannot decide, and %d without meeting a loop cut here. Left out: %d on an inline condition, %d past its depth",
		total.agreed, total.undecided, total.settled, total.dropped, total.loops, total.inline, total.depth)
}

func oracleTest(t *testing.T, s *server.Server, test corpusTest, total *oracleCount) {
	ctx := t.Context()
	store, err := s.CreateStore(ctx, &openfgav1.CreateStoreRequest{Name: "petard-oracle"})
	if err != nil {
		t.Fatal(err)
	}

	var written []*openfgav1.TupleKey
	for number, stage := range test.Stages {
		schema, err := Compile(fmt.Sprintf("%s stage %d", test.Name, number), stage.Model)
		if err != nil {
			t.Fatalf("stage %d: %v", number, err)
		}
		model := oracleModel{server: s, store: store.GetId()}
		model.write(ctx, t, stage.Model)

		keys := make([]*openfgav1.TupleKey, 0, len(stage.Tuples))
		for _, tuple := range stage.Tuples {
			keys = append(keys, tuple.key(t))
		}
		model.writeTuples(ctx, t, keys)
		written = append(written, keys...)

		askEveryCheck(ctx, t, model, schema, admitted(schema, written), oracleContexts(t, stage), number, total)
	}
}

// askEveryCheck holds the engine to the server over every check the tuples allow.
func askEveryCheck(ctx context.Context, t *testing.T, model oracleModel, schema *Schema, stored []zanzibar.Relationship, contexts []map[string]any, stage int, total *oracleCount) {
	t.Helper()
	checker := zanzibar.NewChecker(schema.Model, stored, schema, time.Now())
	objects := zanzibartest.Objects(schema.Model, stored)
	subjects := zanzibartest.Subjects(schema.Model, stored)
	for _, values := range contexts {
		for _, resource := range objects {
			for _, name := range zanzibartest.Names(schema.Model.Type(resource.Type)) {
				for _, subject := range subjects {
					check := zanzibar.Assertion{Resource: resource, Name: name, Subject: subject, Context: values}
					got, err := checker.Check(resource, name, subject, values)
					if err != nil {
						t.Fatalf("stage %d: %s: %v", stage, check, err)
					}
					allowed, refusal := model.check(ctx, t, check)
					if why := compareOracle(schema, stored, check, got, allowed, refusal, total); why != "" {
						t.Errorf("stage %d: %s: %s", stage, check, why)
					}
				}
			}
		}
	}
}

// oracleModel is a model written to a store of the server.
type oracleModel struct {
	server *server.Server
	store  string
	id     string
}

func (m *oracleModel) write(ctx context.Context, t *testing.T, text string) {
	t.Helper()
	model, err := transformer.TransformDSLToProto(text)
	if err != nil {
		t.Fatal(err)
	}
	written, err := m.server.WriteAuthorizationModel(ctx, &openfgav1.WriteAuthorizationModelRequest{
		StoreId:         m.store,
		SchemaVersion:   typesystem.SchemaVersion1_1,
		TypeDefinitions: model.GetTypeDefinitions(),
		Conditions:      model.GetConditions(),
	})
	if err != nil {
		t.Fatalf("write model: %v", err)
	}
	m.id = written.GetAuthorizationModelId()
}

func (m oracleModel) writeTuples(ctx context.Context, t *testing.T, keys []*openfgav1.TupleKey) {
	t.Helper()
	for chunk := range slices.Chunk(keys, oracleWriteChunk) {
		if _, err := m.server.Write(ctx, &openfgav1.WriteRequest{
			StoreId:              m.store,
			AuthorizationModelId: m.id,
			Writes:               &openfgav1.WriteRequestWrites{TupleKeys: chunk},
		}); err != nil {
			t.Fatalf("write tuples: %v", err)
		}
	}
}

func (m oracleModel) check(ctx context.Context, t *testing.T, c zanzibar.Assertion) (bool, error) {
	t.Helper()
	var fields *structpb.Struct
	if c.Context != nil {
		var err error
		if fields, err = structpb.NewStruct(c.Context); err != nil {
			t.Fatalf("%s: %v", c, err)
		}
	}
	resp, err := m.server.Check(ctx, &openfgav1.CheckRequest{
		StoreId:              m.store,
		AuthorizationModelId: m.id,
		TupleKey:             &openfgav1.CheckRequestTupleKey{User: c.Subject.String(), Relation: c.Name, Object: c.Resource.String()},
		Context:              fields,
	})
	return resp.GetAllowed(), err
}

// compareOracle says what is wrong with the engine's answer given OpenFGA's, and
// nothing when they fit: yes for allowed, no for not allowed, and conditional for a
// refusal because a condition cannot be decided.
//
// With a condition OpenFGA cannot decide, its answer can be other than that, and the
// engine's still fits it, because OpenFGA's is the one that stops short of what the
// tuples say. It refuses on a condition it reads and did not need, so a refusal
// fits a yes or a no the condition cannot change. And it drops a tuple it cannot decide
// when another in the same read passes, so it answers without it, and a conditional fits
// what it answers.
//
// A no that cut a loop can also meet an allowed from OpenFGA, where OpenFGA never met
// that loop: see readsPastTheLoop.
func compareOracle(schema *Schema, stored []zanzibar.Relationship, c zanzibar.Assertion, got zanzibar.Result, allowed bool, refusal error, total *oracleCount) string {
	code := int(status.Code(refusal))
	switch {
	case code == depthErrorCode:
		total.depth++
	case got.Level == zanzibar.Conditional && restsOnInline(stored):
		total.inline++
	case refusal != nil && code != validationErrorCode:
		return fmt.Sprintf("OpenFGA fails it (%v), this says %s", refusal, got.Level)
	case refusal != nil && got.Level == zanzibar.Conditional:
		total.undecided++
	case refusal != nil && anyCondition(schema, stored, c.Context, zanzibar.Conditional):
		total.settled++
	case refusal != nil:
		return fmt.Sprintf("OpenFGA refuses it (%v) with every condition decided, this says %s", refusal, got.Level)
	case got.Level == zanzibar.Conditional && droppedBesideAnother(schema, stored, c):
		total.dropped++
	case got.Level == zanzibar.No && got.Cycle && allowed && readsPastTheLoop(schema, stored, c):
		total.loops++
	case got.Level == zanzibar.Conditional || (got.Level == zanzibar.Yes) != allowed:
		return fmt.Sprintf("OpenFGA says %v, this says %s (cycle %v)", allowed, got.Level, got.Cycle)
	default:
		total.agreed++
	}
	return ""
}

// droppedBesideAnother says whether a tuple whose condition OpenFGA cannot decide
// shares a read with one that passes.
func droppedBesideAnother(schema *Schema, stored []zanzibar.Relationship, c zanzibar.Assertion) bool {
	for _, undecided := range stored {
		if conditionLevel(schema, undecided, c.Context) != zanzibar.Conditional {
			continue
		}
		for _, passing := range stored {
			if conditionLevel(schema, passing, c.Context) == zanzibar.Yes && shareARead(undecided, passing, c.Subject) {
				return true
			}
		}
	}
	return false
}

// shareARead says whether OpenFGA can read two tuples through one iterator when
// subject is checked. It reads what one relation of one object holds, for a userset
// tuple or a walked one (internal/checkutil/checkutil.go:64-92,
// internal/graph/check.go:898-915), and what a relation of one type holds for the
// subject or its wildcard (internal/checkutil/checkutil.go:97-139).
func shareARead(a, b zanzibar.Relationship, subject zanzibar.Subject) bool {
	switch {
	case a.Relation != b.Relation:
		return false
	case a.Resource == b.Resource:
		return true
	}
	return a.Resource.Type == b.Resource.Type && namesSubject(a.Subject, subject) && namesSubject(b.Subject, subject)
}

func namesSubject(stored, subject zanzibar.Subject) bool {
	return stored == subject || (stored.ID == zanzibar.WildcardID && stored.Type == subject.Type)
}

// readsPastTheLoop says whether OpenFGA can answer a check without meeting a loop the
// engine cut. It does not follow a tuple whose condition does not hold. And for a
// subject that is not a userset, a relation that only reaches itself it can walk with
// a set of what it has seen (internal/graph/check.go:664-723,
// internal/graph/recursive_resolver.go:277-300), where a loop is nothing to report.
func readsPastTheLoop(schema *Schema, stored []zanzibar.Relationship, c zanzibar.Assertion) bool {
	if anyCondition(schema, stored, c.Context, zanzibar.No) {
		return true
	}
	if c.Subject.Relation != "" {
		return false
	}
	for _, typ := range schema.Model.Types {
		for _, name := range zanzibartest.Names(typ) {
			if walkedBreadthFirst(schema.types, typ.Name, name, c.Subject.Type) {
				return true
			}
		}
	}
	return false
}

func walkedBreadthFirst(types *typesystem.TypeSystem, typ, name, subjectType string) bool {
	if types.UsersetUseRecursiveResolver(typ, name, subjectType) {
		return true
	}
	relation, err := types.GetRelation(typ, name)
	if err != nil {
		return false
	}
	found, err := typesystem.WalkUsersetRewrite(relation.GetRewrite(), func(r *openfgav1.Userset) any {
		if ttu := r.GetTupleToUserset(); ttu != nil && types.TTUUseRecursiveResolver(typ, name, subjectType, ttu) {
			return true
		}
		return nil
	})
	return err == nil && found != nil
}

func anyCondition(schema *Schema, stored []zanzibar.Relationship, values map[string]any, level zanzibar.Level) bool {
	return slices.ContainsFunc(stored, func(r zanzibar.Relationship) bool {
		return r.Caveat != nil && conditionLevel(schema, r, values) == level
	})
}

// conditionLevel is what the condition of a tuple says with the context of a check,
// the tuple's own context written over it. A tuple with no condition passes.
func conditionLevel(schema *Schema, r zanzibar.Relationship, values map[string]any) zanzibar.Level {
	if r.Caveat == nil {
		return zanzibar.Yes
	}
	merged := make(map[string]any, len(values)+len(r.Caveat.Context))
	maps.Copy(merged, values)
	maps.Copy(merged, r.Caveat.Context)
	level, err := schema.Evaluate(r.Caveat.Name, merged)
	if err != nil {
		return zanzibar.Conditional
	}
	return level
}

// oracleContexts is no context, then every distinct context the stage's assertions
// supply.
func oracleContexts(t *testing.T, stage corpusStage) []map[string]any {
	t.Helper()
	out := []map[string]any{nil}
	seen := map[string]bool{}
	for _, a := range stage.CheckAssertions {
		if a.Context == nil {
			continue
		}
		key, err := json.Marshal(a.Context)
		if err != nil {
			t.Fatal(err)
		}
		if !seen[string(key)] {
			seen[string(key)] = true
			out = append(out, a.Context)
		}
	}
	return out
}
