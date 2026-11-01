package openfga

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"github.com/openfga/language/pkg/go/transformer"
	"github.com/openfga/openfga/pkg/server"
	"github.com/openfga/openfga/pkg/storage/memory"
	"github.com/openfga/openfga/pkg/typesystem"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func TestParseEndpoint(t *testing.T) {
	tests := []struct {
		arg  string
		want Endpoint
		ok   bool
	}{
		{arg: "openfga://fga:8081/01STORE", want: Endpoint{Address: "fga:8081", Store: "01STORE", Raw: "openfga://fga:8081/01STORE"}, ok: true},
		{arg: "openfga+insecure://localhost:8081/01STORE/01MODEL", want: Endpoint{Address: "localhost:8081", Store: "01STORE", Model: "01MODEL", Insecure: true, Raw: "openfga+insecure://localhost:8081/01STORE/01MODEL"}, ok: true},
		{arg: "openfga://fga:8081", want: Endpoint{Address: "fga:8081", Raw: "openfga://fga:8081"}, ok: true},
		{arg: "spicedb://fga:8081/01STORE"},
		{arg: "http://localhost:8181"},
		{arg: "model.fga"},
	}
	for _, tt := range tests {
		t.Run(tt.arg, func(t *testing.T) {
			got, ok := ParseEndpoint(tt.arg)
			if ok != tt.ok || !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseEndpoint = %+v, %v, want %+v, %v", got, ok, tt.want, tt.ok)
			}
		})
	}
}

// liveServer is an OpenFGA on the loopback interface, and the address to reach it.
func liveServer(t *testing.T, opts ...grpc.ServerOption) (openfgav1.OpenFGAServiceServer, string) {
	t.Helper()
	s, err := server.NewServerWithOpts(server.WithDatastore(memory.New()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer(opts...)
	openfgav1.RegisterOpenFGAServiceServer(srv, s)
	go func() { _ = srv.Serve(listener) }()
	t.Cleanup(srv.Stop)
	return s, listener.Addr().String()
}

func liveStore(ctx context.Context, t *testing.T, s openfgav1.OpenFGAServiceServer) string {
	t.Helper()
	store, err := s.CreateStore(ctx, &openfgav1.CreateStoreRequest{Name: "live"})
	if err != nil {
		t.Fatal(err)
	}
	return store.GetId()
}

func liveModel(ctx context.Context, t *testing.T, s openfgav1.OpenFGAServiceServer, store, text string) string {
	t.Helper()
	model, err := transformer.TransformDSLToProto(text)
	if err != nil {
		t.Fatal(err)
	}
	written, err := s.WriteAuthorizationModel(ctx, &openfgav1.WriteAuthorizationModelRequest{
		StoreId:         store,
		SchemaVersion:   typesystem.SchemaVersion1_1,
		TypeDefinitions: model.GetTypeDefinitions(),
		Conditions:      model.GetConditions(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return written.GetAuthorizationModelId()
}

const (
	liveOlder = `model
  schema 1.1
type user
type document
  relations
    define owner: [user]
    define viewer: [user]
`
	liveLatest = `model
  schema 1.1
type user
type document
  relations
    define viewer: [user]
`
)

// The live read takes the latest model, or the one named, and the tuples of the store,
// over more than one page, leaving out what the model it read does not admit: a tuple
// written under an older model counts for nothing, as a check of OpenFGA reads it.
func TestReadLive(t *testing.T) {
	ctx := t.Context()
	s, address := liveServer(t)
	store := liveStore(ctx, t, s)
	older := liveModel(ctx, t, s, store, liveOlder)

	const viewers = 120
	keys := make([]*openfgav1.TupleKey, 0, viewers)
	for i := range viewers {
		keys = append(keys, &openfgav1.TupleKey{User: fmt.Sprintf("user:u%d", i), Relation: "viewer", Object: "document:1"})
	}
	for start := 0; start < viewers; start += 50 {
		if _, err := s.Write(ctx, &openfgav1.WriteRequest{
			StoreId: store, AuthorizationModelId: older,
			Writes: &openfgav1.WriteRequestWrites{TupleKeys: keys[start:min(start+50, viewers)]},
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Write(ctx, &openfgav1.WriteRequest{
		StoreId: store, AuthorizationModelId: older,
		Writes: &openfgav1.WriteRequestWrites{TupleKeys: []*openfgav1.TupleKey{{User: "user:anne", Relation: "owner", Object: "document:1"}}},
	}); err != nil {
		t.Fatal(err)
	}
	liveModel(ctx, t, s, store, liveLatest)

	t.Run("the latest model", func(t *testing.T) {
		ep := Endpoint{Address: address, Store: store, Insecure: true, Raw: "openfga+insecure://" + address + "/" + store}
		f, err := ReadLive(ctx, ep, "")
		if err != nil {
			t.Fatal(err)
		}
		if f.Schema.Model.Type("document").Declares("owner") {
			t.Error("read the older model, want the latest")
		}
		if got := len(f.Relationships); got != viewers {
			t.Errorf("read %d tuples, want %d, the ones the latest model admits", got, viewers)
		}
		if f.Path != ep.Raw || f.SchemaPath != ep.Raw || f.Store {
			t.Errorf("File = %q, %q, store %v, want it named by the endpoint", f.Path, f.SchemaPath, f.Store)
		}
	})
	t.Run("a model by its id", func(t *testing.T) {
		f, err := ReadLive(ctx, Endpoint{Address: address, Store: store, Model: older, Insecure: true, Raw: "x"}, "")
		if err != nil {
			t.Fatal(err)
		}
		if !f.Schema.Model.Type("document").Declares("owner") {
			t.Error("did not read the model named")
		}
		if got := len(f.Relationships); got != viewers+1 {
			t.Errorf("read %d tuples, want %d", got, viewers+1)
		}
	})
}

// The sample stops at its limit, however much the store holds.
func TestReadLiveStopsAtTheSampleLimit(t *testing.T) {
	ctx := t.Context()
	s, address := liveServer(t)
	store := liveStore(ctx, t, s)
	model := liveModel(ctx, t, s, store, liveLatest)
	for batch := range (sampleLimit + 200) / 100 {
		keys := make([]*openfgav1.TupleKey, 0, 100)
		for i := range 100 {
			keys = append(keys, &openfgav1.TupleKey{User: fmt.Sprintf("user:u%d", batch*100+i), Relation: "viewer", Object: "document:1"})
		}
		if _, err := s.Write(ctx, &openfgav1.WriteRequest{StoreId: store, AuthorizationModelId: model, Writes: &openfgav1.WriteRequestWrites{TupleKeys: keys}}); err != nil {
			t.Fatal(err)
		}
	}
	f, err := ReadLive(ctx, Endpoint{Address: address, Store: store, Insecure: true, Raw: "x"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if got := len(f.Relationships); got != sampleLimit {
		t.Errorf("read %d tuples, want %d", got, sampleLimit)
	}
}

// The token goes as a bearer on every call, and is not sent when there is none.
func TestReadLiveSendsTheToken(t *testing.T) {
	ctx := t.Context()
	var seen, calls atomic.Int32
	s, address := liveServer(t, grpc.UnaryInterceptor(func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
		calls.Add(1)
		md, _ := metadata.FromIncomingContext(ctx)
		if got := md.Get("authorization"); len(got) == 1 && got[0] == "Bearer secret" {
			seen.Add(1)
		}
		return next(ctx, req)
	}))
	store := liveStore(ctx, t, s)
	liveModel(ctx, t, s, store, liveLatest)

	ep := Endpoint{Address: address, Store: store, Insecure: true, Raw: "x"}
	if _, err := ReadLive(ctx, ep, "secret"); err != nil {
		t.Fatal(err)
	}
	if calls.Load() == 0 || seen.Load() != calls.Load() {
		t.Errorf("the token came with %d of %d calls", seen.Load(), calls.Load())
	}
	seen.Store(0)
	if _, err := ReadLive(ctx, ep, ""); err != nil {
		t.Fatal(err)
	}
	if seen.Load() != 0 {
		t.Errorf("a token came with %d calls, and none was given", seen.Load())
	}
}

// What cannot be read says what is missing.
func TestReadLiveRefuses(t *testing.T) {
	ctx := t.Context()
	s, address := liveServer(t)
	empty := liveStore(ctx, t, s)
	tests := []struct {
		name string
		ep   Endpoint
		want string
	}{
		{name: "no address", ep: Endpoint{Store: "s", Raw: "openfga:///s"}, want: "no host:port"},
		{name: "no store", ep: Endpoint{Address: address, Insecure: true, Raw: "openfga+insecure://x"}, want: "no store"},
		{name: "a store with no model", ep: Endpoint{Address: address, Store: empty, Insecure: true, Raw: "x"}, want: "holds no model"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ReadLive(ctx, tt.ep, "")
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("ReadLive error = %v, want one saying %q", err, tt.want)
			}
		})
	}
}
