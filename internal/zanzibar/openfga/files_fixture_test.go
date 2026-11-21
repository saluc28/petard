package openfga

import (
	"context"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"github.com/openfga/openfga/pkg/server"
	"github.com/openfga/openfga/pkg/storage/memory"
	yaml "go.yaml.in/yaml/v3"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/saluc28/petard/internal/graph"
	"github.com/saluc28/petard/internal/zanzibar"
	registry "github.com/saluc28/petard/taxonomy-registry"
)

// fixtureDir is the vulnerable OpenFGA fixture.
var fixtureDir = filepath.Join("..", "..", "..", "fixtures", "vulnerable-openfga")

// fixtureStore reads the store file of the fixture and the write model beside it.
func fixtureStore(t *testing.T) (*File, *zanzibar.WriteModel) {
	t.Helper()
	files, err := Find([]string{filepath.Join(fixtureDir, "store.fga.yaml")})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatalf("the store file reads as %d inputs, want 1", len(files))
	}
	wm, err := zanzibar.LoadWriteModel(filepath.Join(fixtureDir, "writes.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return files[0], wm
}

func sampleOf(f *File) zanzibar.Sample {
	return zanzibar.Sample{
		Model:         f.Schema.Model,
		Relationships: f.Relationships,
		Assertions:    f.Assertions,
		Caveats:       f.Schema,
		Now:           time.Now(),
	}
}

// fixtureModel is the text of the model of the fixture, as a server takes it.
func fixtureModel(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(fixtureDir, "model.fga"))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// fixtureOracleTest is the fixture in the form TestOracle reads: its model, its tuples,
// and the contexts its checks supply.
func fixtureOracleTest(t *testing.T) corpusTest {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(fixtureDir, "store.fga.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var store struct {
		Tuples []corpusTuple `yaml:"tuples"`
		Tests  []struct {
			Check []struct {
				Context map[string]any `yaml:"context"`
			} `yaml:"check"`
		} `yaml:"tests"`
	}
	if err := yaml.Unmarshal(raw, &store); err != nil {
		t.Fatal(err)
	}
	stage := corpusStage{Model: fixtureModel(t), Tuples: store.Tuples}
	for _, test := range store.Tests {
		for _, check := range test.Check {
			stage.CheckAssertions = append(stage.CheckAssertions, corpusAssertion{Context: check.Context})
		}
	}
	return corpusTest{Name: "the vulnerable fixture", Stages: []corpusStage{stage}}
}

// newFixtureServer is a real server, as it ships, in this process.
func newFixtureServer(t *testing.T) *server.Server {
	t.Helper()
	s, err := server.NewServerWithOpts(server.WithDatastore(memory.New()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

// newFixtureStore is a store of s that holds the model of the fixture and tuples.
func newFixtureStore(ctx context.Context, t *testing.T, s *server.Server, tuples []zanzibar.Relationship) oracleModel {
	t.Helper()
	store, err := s.CreateStore(ctx, &openfgav1.CreateStoreRequest{Name: "petard-fixture"})
	if err != nil {
		t.Fatal(err)
	}
	model := oracleModel{server: s, store: store.GetId()}
	model.write(ctx, t, fixtureModel(t))
	keys := make([]*openfgav1.TupleKey, 0, len(tuples))
	for _, tuple := range tuples {
		keys = append(keys, tupleKeyOf(t, tuple))
	}
	model.writeTuples(ctx, t, keys)
	return model
}

// tupleKeyOf is a relationship of the engine as OpenFGA writes it.
func tupleKeyOf(t *testing.T, r zanzibar.Relationship) *openfgav1.TupleKey {
	t.Helper()
	key := &openfgav1.TupleKey{User: r.Subject.String(), Relation: r.Relation, Object: r.Resource.String()}
	if r.Caveat != nil {
		context, err := structpb.NewStruct(r.Caveat.Context)
		if err != nil {
			t.Fatalf("context of %s: %v", r, err)
		}
		key.Condition = &openfgav1.RelationshipCondition{Name: r.Caveat.Name, Context: context}
	}
	return key
}

// EXPECTED.md says the same: the two parameters the checks supply, one finding for each
// kind of decisive write, and nothing on the network, the date or the owner. With no
// write model the two parameters are candidates and the escalations are not reported.
func TestFixture(t *testing.T) {
	store, wm := fixtureStore(t)
	want := map[string][]string{
		"PTD-ZAN-001": {
			"document#editor, now of condition not_expired",
			"document#viewer, user_ip of condition ip_allowlist",
		},
		"PTD-ZAN-002": {"document#access, a deny lifted by a delete"},
		"PTD-ZAN-003": {
			"document#access, a grant to every subject at once",
			"document#view, a grant to every subject at once",
			"document#viewer, a grant to every subject at once",
		},
		"PTD-ZAN-004": {
			"document#access, linked to an object the coalition holds a permission on",
			"document#view, linked to an object the coalition holds a permission on",
		},
		"PTD-ZAN-005": {
			"document#access, a group the coalition can join",
			"document#view, a group the coalition can join",
			"document#viewer, a group the coalition can join",
		},
		"PTD-ZAN-006": {
			"document#access, a grant written for another the writer lacks",
			"document#edit, a grant written for another the writer lacks",
			"document#editor, a grant written for another the writer lacks",
			"document#view, a grant written for another the writer lacks",
			"document#viewer, a grant written for another the writer lacks",
			"team#member, a grant written for another the writer lacks",
		},
		"PTD-ZAN-007": {
			"document#access, written in behind a permission the coalition held",
			"document#edit, written in behind a permission the coalition held",
			"document#editor, written in behind a permission the coalition held",
			"document#view, written in behind a permission the coalition held",
		},
		"PTD-ZAN-008": {
			"document#access, written in behind a gate that needs no permission",
			"document#view, written in behind a gate that needs no permission",
			"document#viewer, written in behind a gate that needs no permission",
			"team#member, written in behind a gate that needs no permission",
		},
	}

	got := map[string][]string{}
	for _, m := range zanzibar.Run(sampleOf(store), wm) {
		if m.Verdict != zanzibar.Finding {
			t.Errorf("%s: %s, want a finding", m.Subject, m.Verdict)
		}
		got[m.PatternID] = append(got[m.PatternID], m.Subject)
	}
	for _, subjects := range got {
		slices.Sort(subjects)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("with the write model it reports\n%v\nwant\n%v", got, want)
	}

	var candidates []string
	for _, m := range zanzibar.Run(sampleOf(store), nil) {
		if m.Verdict != zanzibar.Candidate || m.PatternID != zanzibar.SelfAssertedExemptionID {
			t.Errorf("%s: %s %s, want a candidate of %s", m.Subject, m.PatternID, m.Verdict, zanzibar.SelfAssertedExemptionID)
		}
		candidates = append(candidates, m.Subject)
	}
	slices.Sort(candidates)
	if !slices.Equal(candidates, want["PTD-ZAN-001"]) {
		t.Errorf("with no write model it reports %v, want %v", candidates, want["PTD-ZAN-001"])
	}
}

// reports says whether the pattern of id matches anything in a store file, with a write
// model beside it when one is there, as an analysis reads it.
func reports(t *testing.T, path, id string) bool {
	t.Helper()
	files, err := Find([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatalf("%s reads as %d inputs, want 1", path, len(files))
	}
	var wm *zanzibar.WriteModel
	writes := filepath.Join(filepath.Dir(path), "writes.yaml")
	if _, err := os.Stat(writes); err == nil {
		if wm, err = zanzibar.LoadWriteModel(writes); err != nil {
			t.Fatal(err)
		}
	}
	return slices.ContainsFunc(zanzibar.Run(sampleOf(files[0]), wm), func(m zanzibar.Match) bool {
		return m.PatternID == id
	})
}

// Every Zanzibar pattern says it applies to OpenFGA and finds its case in the store file
// it names, and every declared false positive written as a case does on a store file what
// the registry says it does.
func TestRegistryCases(t *testing.T) {
	files, err := fs.Glob(registry.Zanzibar, "*.yaml")
	if err != nil || len(files) == 0 {
		t.Fatalf("no Zanzibar pattern in the registry: %v", err)
	}
	for _, file := range files {
		t.Run(file, func(t *testing.T) {
			raw, err := fs.ReadFile(registry.Zanzibar, file)
			if err != nil {
				t.Fatal(err)
			}
			var entry struct {
				ID        string   `yaml:"id"`
				FrontEnds []string `yaml:"front_ends"`
				Fixture   struct {
					Store string `yaml:"store"`
				} `yaml:"fixture"`
				FalsePositives []struct {
					Condition string `yaml:"condition"`
					Case      *struct {
						Store   string `yaml:"store"`
						Reports bool   `yaml:"reports"`
					} `yaml:"case"`
				} `yaml:"false_positives"`
			}
			if err := yaml.Unmarshal(raw, &entry); err != nil {
				t.Fatal(err)
			}

			if !slices.Contains(entry.FrontEnds, "openfga") {
				t.Errorf("%s does not name openfga among its front ends: %v", entry.ID, entry.FrontEnds)
			}
			if !reports(t, filepath.Join("..", "..", "..", filepath.FromSlash(entry.Fixture.Store)), entry.ID) {
				t.Errorf("%s is not found in its store file, %q", entry.ID, entry.Fixture.Store)
			}
			for _, fp := range entry.FalsePositives {
				if fp.Case == nil {
					continue
				}
				path := filepath.Join(t.TempDir(), "case.fga.yaml")
				if err := os.WriteFile(path, []byte(fp.Case.Store), 0o600); err != nil {
					t.Fatal(err)
				}
				if got := reports(t, path, entry.ID); got != fp.Case.Reports {
					t.Errorf("case of %q: reported %t, the registry says %t", fp.Condition, got, fp.Case.Reports)
				}
			}
		})
	}
}

// The fixture leaves document#owner without a write rule, so petard proposes a gate for
// it. Every relation of OpenFGA can be asked, so a holder of edit who makes itself owner
// raises owner, and only owner is a safe gate. The anyone rule for viewer raises what it
// raises whichever gate is weighed, and does not count against any of them.
func TestFixtureSafeGates(t *testing.T) {
	store, wm := fixtureStore(t)
	proposals, _, err := zanzibar.SafeGates(store.Schema.Model, wm, store.Schema, zanzibar.Options{Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range proposals {
		if p.Type != "document" || p.Relation != "owner" {
			continue
		}
		if !slices.Equal(p.Safe, []string{"owner"}) {
			t.Errorf("safe gates for document#owner = %v, want owner alone", p.Safe)
		}
		return
	}
	t.Errorf("no proposal for document#owner; got %+v", proposals)
}

// A gate proposed as safe adds no raise. From every position that puts an attacker on the
// gate, what a coalition can raise with a rule for the gate is what it can raise without
// one, under the rules the write model already declares.
func TestFixtureSafeGatesAddNoRaise(t *testing.T) {
	store, wm := fixtureStore(t)
	model := store.Schema.Model
	opts := zanzibar.Options{Now: time.Now()}
	proposals, _, err := zanzibar.SafeGates(model, wm, store.Schema, opts)
	if err != nil {
		t.Fatal(err)
	}

	raised := func(rules *zanzibar.WriteModel, p zanzibar.StartingPosition) map[string]bool {
		t.Helper()
		escalations, err := zanzibar.Escalations(model, rules, store.Schema, p.Tuples, []zanzibar.Object{p.Attacker}, opts)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]bool{}
		for _, esc := range escalations {
			out[esc.Object.String()+"#"+esc.Permission] = true
		}
		return out
	}

	weighed := 0
	for _, proposal := range proposals {
		for _, gate := range proposal.Safe {
			proposed := *wm
			proposed.Writes = append(slices.Clone(wm.Writes), &zanzibar.WriteRule{
				Resource:   proposal.Type,
				Relation:   proposal.Relation,
				Operations: []zanzibar.Operation{zanzibar.Create},
				Gate:       zanzibar.Gate{Holds: gate},
				Subject:    zanzibar.SubjectSpec{Any: true},
			})
			for _, typ := range model.Types {
				for _, p := range zanzibar.StartingPositions(model, zanzibar.Object{Type: typ.Name, ID: "attacker"}, zanzibar.Options{}) {
					if p.Type != proposal.Type || p.Target != gate {
						continue
					}
					weighed++
					without := raised(wm, p)
					for target := range raised(&proposed, p) {
						if !without[target] {
							t.Errorf("%s#%s gated on %s, from %s: it raises %s, and the declared rules alone do not", proposal.Type, proposal.Relation, gate, p, target)
						}
					}
				}
			}
		}
	}
	if weighed == 0 {
		t.Fatal("no safe gate was weighed")
	}
}

// The checks the store file asserts are the answers OpenFGA gives, on the file as it
// stands: what fga model test reads the file for.
func TestFixtureChecksHoldOnCheck(t *testing.T) {
	ctx := t.Context()
	s := newFixtureServer(t)
	store, _ := fixtureStore(t)
	model := newFixtureStore(ctx, t, s, store.Relationships)
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

// What PTD-ZAN-001 says, on OpenFGA itself. As the file stands the network holds and the
// date holds; with the parameter the check brings written on the tuple, as the write
// model lets its writer, the check from outside is allowed, and so is one that brings
// nothing.
func TestFixtureExemptionsHoldOnCheck(t *testing.T) {
	ctx := t.Context()
	s := newFixtureServer(t)
	store, _ := fixtureStore(t)
	roadmap := zanzibar.Object{Type: "document", ID: "roadmap"}

	tests := []struct {
		name       string
		user       string
		relation   string
		permission string
		written    map[string]any // what the write sets on the tuple, beside what it holds
		outside    map[string]any // a context the condition refuses
	}{
		{
			name:       "the address on a viewer",
			user:       "vic",
			relation:   "viewer",
			permission: "view",
			written:    map[string]any{"user_ip": "10.1.2.3"},
			outside:    map[string]any{"user_ip": "192.168.0.1"},
		},
		{
			name:       "the time on an editor",
			user:       "erin",
			relation:   "editor",
			permission: "edit",
			written:    map[string]any{"now": "2026-10-20T00:00:00Z"},
			outside:    map[string]any{"now": "2026-12-01T00:00:00Z"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subject := zanzibar.Subject{Object: zanzibar.Object{Type: "user", ID: tt.user}}
			check := zanzibar.Assertion{Resource: roadmap, Name: tt.permission, Subject: subject, Context: tt.outside}

			model := newFixtureStore(ctx, t, s, store.Relationships)
			if allowed, err := model.check(ctx, t, check); allowed || err != nil {
				t.Fatalf("as the file stands, %s: allowed %v, error %v, want refused", check, allowed, err)
			}

			rewritten := slices.Clone(store.Relationships)
			at := slices.IndexFunc(rewritten, func(r zanzibar.Relationship) bool {
				return r.Subject == subject && r.Relation == tt.relation
			})
			if at < 0 {
				t.Fatalf("the fixture has no %s tuple for %s", tt.relation, tt.user)
			}
			caveat := *rewritten[at].Caveat
			caveat.Context = maps.Clone(caveat.Context)
			maps.Copy(caveat.Context, tt.written)
			rewritten[at].Caveat = &caveat

			model = newFixtureStore(ctx, t, s, rewritten)
			for _, values := range []map[string]any{tt.outside, nil} {
				asked := check
				asked.Context = values
				if allowed, err := model.check(ctx, t, asked); !allowed || err != nil {
					t.Errorf("with %v on the tuple, %s: allowed %v, error %v, want allowed", tt.written, asked, allowed, err)
				}
			}
		})
	}
}

// Every escalation the engine finds on the fixture is one OpenFGA's own Check shows. In a
// real store, from the state the engine started in, the permission is not allowed for
// the attacker; after the writes of the witness, made in order through Write, it is
// allowed for the attacker or for an object the witness made. The states are the ones
// the findings come from: the tuples of the store file, and the positions the model
// generates.
func TestFixtureWitnessesHoldOnCheck(t *testing.T) {
	ctx := t.Context()
	s := newFixtureServer(t)
	store, wm := fixtureStore(t)
	schema := store.Schema
	attacker := zanzibar.Object{Type: "user", ID: "attacker"}

	states := [][]zanzibar.Relationship{store.Relationships}
	for _, p := range zanzibar.StartingPositions(schema.Model, attacker, zanzibar.Options{}) {
		states = append(states, p.Tuples)
	}

	replayed := map[zanzibar.Category]int{}
	replay := func(state []zanzibar.Relationship, who zanzibar.Object) {
		t.Helper()
		classified, err := zanzibar.Classify(schema.Model, wm, schema, state, []zanzibar.Object{who}, zanzibar.Options{Now: time.Now()})
		if err != nil {
			t.Fatal(err)
		}
		for _, esc := range classified {
			replayWitness(ctx, t, s, state, who, esc)
			replayed[esc.Category]++
		}
	}
	for _, state := range states {
		replay(state, attacker)
	}
	subjects := 0
	for _, who := range namedUsers(store) {
		subjects++
		replay(store.Relationships, who)
	}
	if subjects == 0 {
		t.Fatal("the store file names no subject")
	}
	for _, category := range []zanzibar.Category{
		zanzibar.CategoryFailOpenOnAbsence,
		zanzibar.CategoryGlobalSwitch,
		zanzibar.CategoryTransitiveGrant,
		zanzibar.CategoryAssumableIdentity,
		zanzibar.CategoryDelegationNotNarrowed,
		zanzibar.CategorySplitGrant,
		zanzibar.CategoryAttrSelfWrite,
	} {
		if replayed[category] == 0 {
			t.Errorf("no witness of %s was held to Check", category)
		}
	}
	t.Logf("%d states, witnesses by category: %v", len(states), replayed)
}

// namedUsers are the users the tuples of a store file name as their subject.
func namedUsers(store *File) []zanzibar.Object {
	var out []zanzibar.Object
	for _, r := range store.Relationships {
		if r.Subject.Relation == "" && r.Subject.Type == "user" && !slices.Contains(out, r.Subject.Object) {
			out = append(out, r.Subject.Object)
		}
	}
	return out
}

// What the graph says a subject holds is what OpenFGA's Check says. For every user the
// tuples name, on every object and relation, there is a permission on a PTD_CanPerform
// edge exactly where Check allows it. A check it refuses over a condition it cannot
// decide is not a holding.
func TestFixtureHoldingsHoldOnCheck(t *testing.T) {
	ctx := t.Context()
	s := newFixtureServer(t)
	store, wm := fixtureStore(t)
	model := newFixtureStore(ctx, t, s, store.Relationships)

	g, err := zanzibar.EscalationGraph(sampleOf(store), wm)
	if err != nil {
		t.Fatal(err)
	}
	drawn := map[string]bool{}
	for _, e := range g.Edges() {
		if e.Kind != graph.EdgeKindCanPerform {
			continue
		}
		permissions, _ := e.Properties[graph.PropPermissions].([]string)
		for _, permission := range permissions {
			drawn[e.From+" "+permission+" "+e.To] = true
		}
	}
	if len(drawn) == 0 {
		t.Fatal("the graph draws no holding")
	}

	objects := map[zanzibar.Object]bool{}
	for _, r := range store.Relationships {
		objects[r.Resource] = true
	}
	allowed := 0
	for _, who := range namedUsers(store) {
		for object := range objects {
			for _, p := range store.Schema.Model.Type(object.Type).Permissions {
				check := zanzibar.Assertion{Resource: object, Name: p.Name, Subject: zanzibar.Subject{Object: who}}
				got, err := model.check(ctx, t, check)
				key := who.String() + " " + p.Name + " " + object.String()
				if err == nil && got {
					allowed++
				}
				if want := err == nil && got; drawn[key] != want {
					t.Errorf("%s: the graph says %v, Check says %v (%v)", key, drawn[key], got, err)
				}
			}
		}
	}
	if allowed == 0 {
		t.Fatal("Check allows nothing, so nothing was held to it")
	}
}

// replayWitness makes the writes of an escalation on a new store and asks Check for the
// permission before and after.
func replayWitness(ctx context.Context, t *testing.T, s *server.Server, start []zanzibar.Relationship, attacker zanzibar.Object, esc zanzibar.ClassifiedEscalation) {
	t.Helper()
	model := newFixtureStore(ctx, t, s, start)
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
