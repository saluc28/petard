package zanzibarsetup

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"github.com/openfga/language/pkg/go/transformer"
	"github.com/openfga/openfga/pkg/server"
	"github.com/openfga/openfga/pkg/storage/memory"
	"github.com/openfga/openfga/pkg/typesystem"
	"google.golang.org/grpc"

	"github.com/saluc28/petard/internal/zanzibar/spicedb"
)

// rel names a path under the repository root, three levels up from this package.
func rel(parts ...string) string {
	return filepath.Join(append([]string{"..", "..", ".."}, parts...)...)
}

func TestPartitionEndpoints(t *testing.T) {
	disk, endpoints, fga := partitionEndpoints([]string{
		"spicedb://localhost:50051",
		"schema.zed",
		"http://localhost:8181",
		"spicedb+insecure://127.0.0.1:50051",
		"openfga://fga:8081/store",
		"./policies",
	})

	if len(fga) != 1 || fga[0].Store != "store" {
		t.Errorf("OpenFGA endpoints = %+v, want the one store", fga)
	}

	wantDisk := []string{"schema.zed", "http://localhost:8181", "./policies"}
	if len(disk) != len(wantDisk) {
		t.Fatalf("disk paths = %v, want %v", disk, wantDisk)
	}
	for i, p := range wantDisk {
		if disk[i] != p {
			t.Errorf("disk[%d] = %q, want %q", i, disk[i], p)
		}
	}

	// The OPA URL stays on the disk side, for the policy loader, and never
	// becomes a SpiceDB endpoint.
	for _, p := range disk {
		if _, ok := spicedb.ParseEndpoint(p); ok {
			t.Errorf("disk path %q was taken for a SpiceDB endpoint", p)
		}
	}

	want := []spicedb.Endpoint{
		{Address: "localhost:50051", Raw: "spicedb://localhost:50051"},
		{Address: "127.0.0.1:50051", Insecure: true, Raw: "spicedb+insecure://127.0.0.1:50051"},
	}
	if len(endpoints) != len(want) {
		t.Fatalf("endpoints = %+v, want %+v", endpoints, want)
	}
	for i, ep := range want {
		if endpoints[i] != ep {
			t.Errorf("endpoints[%d] = %+v, want %+v", i, endpoints[i], ep)
		}
	}
}

// writeFile writes a SpiceDB input into a test directory.
func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Load reads the schema and its write model from the same directory, and leaves
// the directory for the policy loader while taking the schema and validation
// files out.
func TestLoadDiscoversTheWriteModelBesideTheSchema(t *testing.T) {
	dir := rel("fixtures", "vulnerable-spicedb")

	found, err := Load(context.Background(), []string{dir}, "")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(found.Files) == 0 {
		t.Fatal("found no SpiceDB files under the fixture")
	}
	if len(found.WriteModels) != 1 {
		t.Fatalf("write models = %d, want 1 beside the schema", len(found.WriteModels))
	}
	for d, wm := range found.WriteModels {
		if wm == nil {
			t.Errorf("write model for %s is nil", d)
		}
	}
	if found.PolicyWriteModel != "" {
		t.Errorf("policy write model = %q, want empty with no flag", found.PolicyWriteModel)
	}
	if len(found.PolicyPaths) != 1 || filepath.Clean(found.PolicyPaths[0]) != filepath.Clean(dir) {
		t.Errorf("policy paths = %v, want just the directory for the policy loader", found.PolicyPaths)
	}
}

// Analyses decides what each schema is run with: a validation file brings its
// own relationships; a schema no validation file reads is run from its bare
// schema when a write model stands beside it; a schema with neither is left
// without evidence for the caller to report rather than read as clean.
func TestAnalysesChoosesWhatEachSchemaIsRunWith(t *testing.T) {
	schema := "definition user {}\n\n" +
		"definition document {\n" +
		"\trelation viewer: user\n" +
		"\tpermission view = viewer\n" +
		"}\n"
	writeModel := "schema_version: 1\n" +
		"model: relationship-writes\n" +
		"writes:\n" +
		"  - resource: document\n" +
		"    relation: viewer\n" +
		"    operations: [create, touch]\n" +
		"    gate: anyone\n" +
		"    subject: [user]\n"

	t.Run("a validation file brings its own relationships", func(t *testing.T) {
		found, err := Load(context.Background(), []string{rel("fixtures", "vulnerable-spicedb")}, "")
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		run, noEvidence := found.Analyses(time.Now())
		if len(run) != 1 {
			t.Fatalf("analyses = %d, want 1 for the validation file", len(run))
		}
		if run[0].WriteModel == nil {
			t.Error("the analysis has no write model, but one stands beside the schema")
		}
		if len(run[0].Sample.Relationships) == 0 {
			t.Error("the validation file's relationships are not in the sample")
		}
		if len(noEvidence) != 0 {
			t.Errorf("no-evidence = %v, want none", noEvidence)
		}
	})

	t.Run("a schema with a write model is run from its bare schema", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "schema.zed", schema)
		writeFile(t, dir, "writes.yaml", writeModel)

		found, err := Load(context.Background(), []string{dir}, "")
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		run, noEvidence := found.Analyses(time.Now())
		if len(run) != 1 {
			t.Fatalf("analyses = %d, want 1 from the bare schema", len(run))
		}
		if run[0].WriteModel == nil {
			t.Error("the analysis has no write model, but one stands beside the schema")
		}
		if len(run[0].Sample.Relationships) != 0 {
			t.Errorf("the bare schema's sample carries %d relationships, want none", len(run[0].Sample.Relationships))
		}
		if len(noEvidence) != 0 {
			t.Errorf("no-evidence = %v, want none", noEvidence)
		}
	})

	t.Run("a schema with neither is left without evidence", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "schema.zed", schema)

		found, err := Load(context.Background(), []string{dir}, "")
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		run, noEvidence := found.Analyses(time.Now())
		if len(run) != 0 {
			t.Errorf("analyses = %d, want none without a write model", len(run))
		}
		if len(noEvidence) != 1 {
			t.Fatalf("no-evidence = %v, want the one schema", noEvidence)
		}
	})
}

// The write-model flag feeds both engines, told apart by the kind the file
// declares: a relationship-writes model is the Zanzibar engine's and is kept
// from the policy loader, a write-paths model is the policy engine's.
func TestLoadRoutesTheWriteModelFlagByKind(t *testing.T) {
	spiceDir := rel("fixtures", "vulnerable-spicedb")
	rebacModel := filepath.Join(spiceDir, "writes.yaml")
	policyModel := rel("fixtures", "vulnerable-bundle", "write-model.yaml")

	tests := []struct {
		name            string
		flag            string
		wantPolicyModel string
	}{
		{"no flag", "", ""},
		{"a relationship-writes model is the zanzibar engine's", rebacModel, ""},
		{"a write-paths model is the policy engine's", policyModel, policyModel},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			found, err := Load(context.Background(), []string{spiceDir}, tt.flag)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if found.PolicyWriteModel != tt.wantPolicyModel {
				t.Errorf("policy write model = %q, want %q", found.PolicyWriteModel, tt.wantPolicyModel)
			}
		})
	}
}

// A directory is read for both products, each file kept to its own, and the write
// model beside the schemas reaches both. A store file whose test brings tuples is
// analyzed once for each state, under the one schema it reads.
func TestLoadReadsBothProducts(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "schema.zed", "definition user {}\ndefinition doc {\n  relation viewer: user\n  permission view = viewer\n}\n")
	writeFile(t, dir, "model.fga", "model\n  schema 1.1\ntype user\ntype doc\n  relations\n    define viewer: [user]\n")
	writeFile(t, dir, "store.fga.yaml", "model_file: model.fga\n"+
		"tuples:\n  - {user: user:anne, relation: viewer, object: doc:1}\n"+
		"tests:\n  - name: own\n    tuples:\n      - {user: user:bob, relation: viewer, object: doc:1}\n")
	writeFile(t, dir, "writes.yaml", "schema_version: 1\nmodel: relationship-writes\nwrites: []\n")

	found, err := Load(t.Context(), []string{dir}, "")
	if err != nil {
		t.Fatal(err)
	}
	products := map[Product]int{}
	for _, f := range found.Files {
		products[f.Product]++
	}
	if products[SpiceDB] != 1 || products[OpenFGA] != 3 {
		t.Errorf("files by product = %v, want 1 of SpiceDB and 3 of OpenFGA", products)
	}
	if len(found.WriteModels) != 1 {
		t.Errorf("write models = %v, want the one beside the schemas", found.WriteModels)
	}
	if got := len(found.PolicyPaths); got != 1 {
		t.Errorf("policy paths = %v, want the directory, for the loader to take the Rego of", found.PolicyPaths)
	}

	run, noEvidence := found.Analyses(time.Now())
	if len(noEvidence) != 0 {
		t.Errorf("no-evidence = %v, want none", noEvidence)
	}
	byState := map[int]int{}
	for _, a := range run {
		if a.Sample.Model.Type("doc").Permission("view") == nil {
			byState[len(a.Sample.Relationships)]++
		}
	}
	if byState[1] != 1 || byState[2] != 1 || len(run) != 3 {
		t.Errorf("analyses = %d, OpenFGA by tuples = %v, want the shared state and the test's", len(run), byState)
	}
}

// A file named one by one is not left for the policy loader, whichever product it
// belongs to, and a running store is read over its API with a write model from the
// flag.
func TestLoadReadsARunningOpenFGA(t *testing.T) {
	ctx := t.Context()
	s, err := server.NewServerWithOpts(server.WithDatastore(memory.New()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	openfgav1.RegisterOpenFGAServiceServer(srv, s)
	go func() { _ = srv.Serve(listener) }()
	t.Cleanup(srv.Stop)

	store, err := s.CreateStore(ctx, &openfgav1.CreateStoreRequest{Name: "live"})
	if err != nil {
		t.Fatal(err)
	}
	model, err := transformer.TransformDSLToProto("model\n  schema 1.1\ntype user\ntype doc\n  relations\n    define viewer: [user]\n")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.WriteAuthorizationModel(ctx, &openfgav1.WriteAuthorizationModelRequest{
		StoreId: store.GetId(), SchemaVersion: typesystem.SchemaVersion1_1, TypeDefinitions: model.GetTypeDefinitions(),
	}); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	writeFile(t, dir, "writes.yaml", "schema_version: 1\nmodel: relationship-writes\nwrites: []\n")
	endpoint := "openfga+insecure://" + listener.Addr().String() + "/" + store.GetId()
	found, err := Load(ctx, []string{endpoint}, filepath.Join(dir, "writes.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(found.Files) != 1 || found.Files[0].Product != OpenFGA || found.Files[0].Path != endpoint {
		t.Fatalf("files = %+v, want the running store", found.Files)
	}
	if len(found.PolicyPaths) != 0 {
		t.Errorf("policy paths = %v, want none", found.PolicyPaths)
	}
	run, _ := found.Analyses(time.Now())
	if len(run) != 1 || run[0].WriteModel == nil {
		t.Errorf("analyses = %+v, want the store under the write model of the flag", run)
	}
}
