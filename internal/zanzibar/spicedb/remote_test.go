package spicedb

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/authzed/spicedb/pkg/tuple"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
)

func TestParseEndpoint(t *testing.T) {
	tests := []struct {
		name   string
		arg    string
		want   Endpoint
		wantOK bool
	}{
		{
			name:   "tls scheme",
			arg:    "spicedb://localhost:50051",
			want:   Endpoint{Address: "localhost:50051", Raw: "spicedb://localhost:50051"},
			wantOK: true,
		},
		{
			name:   "insecure scheme",
			arg:    "spicedb+insecure://localhost:50051",
			want:   Endpoint{Address: "localhost:50051", Insecure: true, Raw: "spicedb+insecure://localhost:50051"},
			wantOK: true,
		},
		{name: "opa url is not a spicedb endpoint", arg: "http://localhost:8181", wantOK: false},
		{name: "https opa url is not one either", arg: "https://opa.example", wantOK: false},
		{name: "a schema file is not one", arg: "schema.zed", wantOK: false},
		{name: "a directory is not one", arg: "./policies", wantOK: false},
		{name: "a bare host without a scheme is not one", arg: "localhost:50051", wantOK: false},
		{name: "empty is not one", arg: "", wantOK: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ParseEndpoint(tt.arg)
			if ok != tt.wantOK {
				t.Fatalf("ParseEndpoint(%q) ok = %v, want %v", tt.arg, ok, tt.wantOK)
			}
			if ok && got != tt.want {
				t.Fatalf("ParseEndpoint(%q) = %+v, want %+v", tt.arg, got, tt.want)
			}
		})
	}
}

// fakeSpiceDB is a fake SpiceDB answering ReadSchema with a fixed schema and
// ReadRelationships with a fixed set, and recording the bearer token the calls
// carried, so a test can prove ReadLive reads both over the API and sends the
// token with them.
type fakeSpiceDB struct {
	v1.UnimplementedSchemaServiceServer
	v1.UnimplementedPermissionsServiceServer
	schema   string
	rels     []string
	readErr  error
	relsErr  error
	gotToken string
}

func (s *fakeSpiceDB) ReadSchema(ctx context.Context, _ *v1.ReadSchemaRequest) (*v1.ReadSchemaResponse, error) {
	s.recordToken(ctx)
	if s.readErr != nil {
		return nil, s.readErr
	}
	return &v1.ReadSchemaResponse{SchemaText: s.schema}, nil
}

func (s *fakeSpiceDB) ReadRelationships(_ *v1.ReadRelationshipsRequest, stream grpc.ServerStreamingServer[v1.ReadRelationshipsResponse]) error {
	s.recordToken(stream.Context())
	if s.relsErr != nil {
		return s.relsErr
	}
	for _, r := range s.rels {
		if err := stream.Send(&v1.ReadRelationshipsResponse{Relationship: tuple.MustParseV1Rel(r)}); err != nil {
			return err
		}
	}
	return nil
}

func (s *fakeSpiceDB) recordToken(ctx context.Context) {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if vals := md.Get("authorization"); len(vals) > 0 {
			s.gotToken = vals[0]
		}
	}
}

// serveFake starts the fake over an in-memory bufconn listener and returns a
// dial option that reaches it, so ReadLive exercises the whole gRPC stack
// (metadata, serialization) without a network.
func serveFake(t *testing.T, srv *fakeSpiceDB) grpc.DialOption {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	grpcSrv := grpc.NewServer()
	v1.RegisterSchemaServiceServer(grpcSrv, srv)
	v1.RegisterPermissionsServiceServer(grpcSrv, srv)
	go func() { _ = grpcSrv.Serve(lis) }()
	t.Cleanup(grpcSrv.Stop)
	return grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
		return lis.DialContext(ctx)
	})
}

func TestReadLiveReadsAndCompilesTheSchema(t *testing.T) {
	const schema = "definition user {}\n" +
		"definition doc {\n" +
		"\trelation viewer: user\n" +
		"\tpermission view = viewer\n" +
		"}\n"
	srv := &fakeSpiceDB{schema: schema, rels: []string{
		"doc:readme#viewer@user:alice",
		"doc:design#viewer@user:bob",
	}}
	dial := serveFake(t, srv)

	ep := Endpoint{Address: "passthrough:///bufnet", Insecure: true, Raw: "spicedb+insecure://bufnet"}
	f, err := readLive(context.Background(), ep, "sekret", dial)
	if err != nil {
		t.Fatalf("ReadLive: %v", err)
	}

	if f.Path != ep.Raw || f.SchemaPath != ep.Raw {
		t.Errorf("File named %q/%q, want %q", f.Path, f.SchemaPath, ep.Raw)
	}
	if f.Validation {
		t.Errorf("a live read is not a validation file")
	}
	// The schema the server returned compiled into the model: two definitions,
	// one relation, one permission.
	relations, permissions := 0, 0
	for _, typ := range f.Schema.Model.Types {
		relations += len(typ.Relations)
		permissions += len(typ.Permissions)
	}
	if n := len(f.Schema.Model.Types); n != 2 {
		t.Errorf("compiled %d definitions, want 2", n)
	}
	if relations != 1 || permissions != 1 {
		t.Errorf("compiled %d relations and %d permissions, want 1 and 1", relations, permissions)
	}
	if srv.gotToken != "Bearer sekret" {
		t.Errorf("server saw authorization %q, want %q", srv.gotToken, "Bearer sekret")
	}

	// The relationships the server streamed were read and lowered the way a
	// validation file's are, so the patterns take them as a starting state.
	if n := len(f.Relationships); n != 2 {
		t.Fatalf("read %d relationships, want 2", n)
	}
	first := f.Relationships[0]
	if first.Resource.Type != "doc" || first.Relation != "viewer" || first.Subject.Type != "user" || first.Subject.ID != "alice" {
		t.Errorf("first relationship = %+v, want doc#viewer@user:alice", first)
	}
}

func TestReadLiveWrapsAReadError(t *testing.T) {
	srv := &fakeSpiceDB{readErr: errors.New("boom")}
	dial := serveFake(t, srv)

	ep := Endpoint{Address: "passthrough:///bufnet", Insecure: true, Raw: "spicedb+insecure://bufnet"}
	_, err := readLive(context.Background(), ep, "", dial)
	if err == nil {
		t.Fatal("ReadLive returned no error for a failing ReadSchema")
	}
}

func TestReadLiveWrapsARelationshipReadError(t *testing.T) {
	srv := &fakeSpiceDB{schema: "definition user {}\n", relsErr: errors.New("boom")}
	dial := serveFake(t, srv)

	ep := Endpoint{Address: "passthrough:///bufnet", Insecure: true, Raw: "spicedb+insecure://bufnet"}
	_, err := readLive(context.Background(), ep, "", dial)
	if err == nil {
		t.Fatal("readLive returned no error for a failing ReadRelationships")
	}
}

func TestReadLiveRejectsEmptyAddress(t *testing.T) {
	// The exported entry, no server: an endpoint with no host:port fails with a
	// clear reason rather than a bare dial error.
	_, err := ReadLive(context.Background(), Endpoint{Raw: "spicedb://"}, "")
	if err == nil {
		t.Fatal("ReadLive accepted an endpoint with no address")
	}
	if !strings.Contains(err.Error(), "spicedb://") {
		t.Errorf("error %q does not name the endpoint", err)
	}
}

func TestReadLiveWrapsACompileError(t *testing.T) {
	srv := &fakeSpiceDB{schema: "definition user {\n  this is not a schema\n}"}
	dial := serveFake(t, srv)

	ep := Endpoint{Address: "passthrough:///bufnet", Insecure: true, Raw: "spicedb+insecure://bufnet"}
	_, err := readLive(context.Background(), ep, "", dial)
	if !errors.Is(err, ErrSchema) {
		t.Fatalf("ReadLive error = %v, want it to wrap ErrSchema", err)
	}
}
