package openfga

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"
	"time"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/saluc28/petard/internal/zanzibar"
)

// TokenEnv is the environment variable a running OpenFGA's bearer token is read from,
// named once in the environment rather than on the command line where a shell would
// record it.
const TokenEnv = "PETARD_OPENFGA_TOKEN" // #nosec G101 -- the name of an environment variable, not a credential

// The schemes a running OpenFGA is named with, in place of a path. What follows is
// the gRPC host:port the server listens on, the store, and optionally a model of it.
const (
	// tlsScheme reaches an OpenFGA over TLS, the shape a deployed one has.
	tlsScheme = "openfga://"
	// insecureScheme reaches an OpenFGA over plaintext, for a local development one.
	// It is a separate scheme, not a flag, so that turning off transport security is
	// a visible choice in the argument itself.
	insecureScheme = "openfga+insecure://"
)

// Endpoint is a running OpenFGA named on the command line in place of a path.
type Endpoint struct {
	// Address is the gRPC host:port, Store the store to read, and Model the model
	// of it, empty for the latest one.
	Address, Store, Model string
	// Insecure is true when the scheme asked for plaintext transport.
	Insecure bool
	// Raw is the argument as given, so a report names the endpoint the way the user
	// wrote it.
	Raw string
}

// ParseEndpoint recognizes a running OpenFGA named in place of a path:
// openfga://host:port/store, or openfga+insecure://host:port/store over plaintext for
// a local development server, with /model after the store to read a model other than
// the latest. ok is false for everything else, which is for the loaders that read it.
func ParseEndpoint(arg string) (Endpoint, bool) {
	var rest string
	insecureTransport := false
	switch {
	case strings.HasPrefix(arg, insecureScheme):
		rest, insecureTransport = strings.TrimPrefix(arg, insecureScheme), true
	case strings.HasPrefix(arg, tlsScheme):
		rest = strings.TrimPrefix(arg, tlsScheme)
	default:
		return Endpoint{}, false
	}
	parts := strings.SplitN(rest, "/", 3)
	ep := Endpoint{Address: parts[0], Insecure: insecureTransport, Raw: arg}
	if len(parts) > 1 {
		ep.Store = parts[1]
	}
	if len(parts) > 2 {
		ep.Model = parts[2]
	}
	return ep, true
}

// readTimeout bounds each read, so a server that accepts the connection and then
// never answers fails the command rather than hanging it.
const readTimeout = 30 * time.Second

// ReadLive reads a model and a bounded sample of the tuples of a store from a running
// OpenFGA over its gRPC API, read only. It is how a model that lives only inside a
// running OpenFGA is analyzed. The API returns the compiled form, which holds no
// positions, so what it reports names the endpoint alone.
//
// A tuple the model does not admit is left out, as a check of OpenFGA leaves it out
// (internal/validation/validation.go:379-384 at v1.23.0): one written under an older
// model counts for nothing rather than for what it used to mean.
//
// token is the bearer the server needs, empty when it needs none; the caller reads it
// from TokenEnv.
func ReadLive(ctx context.Context, ep Endpoint, token string) (*File, error) {
	if ep.Address == "" {
		return nil, fmt.Errorf("openfga: %s names no host:port to connect to", ep.Raw)
	}
	if ep.Store == "" {
		return nil, fmt.Errorf("openfga: %s names no store to read: write it after the address, as openfga://host:port/store", ep.Raw)
	}
	transport := credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})
	if ep.Insecure {
		transport = insecure.NewCredentials()
	}
	opts := []grpc.DialOption{grpc.WithTransportCredentials(transport)}
	if token != "" {
		opts = append(opts, grpc.WithPerRPCCredentials(bearer{token: token}))
	}
	conn, err := grpc.NewClient(ep.Address, opts...)
	if err != nil {
		return nil, fmt.Errorf("openfga: connecting to %s: %w", ep.Raw, err)
	}
	defer func() { _ = conn.Close() }()
	client := openfgav1.NewOpenFGAServiceClient(conn)

	model, err := readModel(ctx, client, ep)
	if err != nil {
		return nil, err
	}
	schema, err := guarded(ep.Raw, func() (*Schema, error) { return lower(ep.Raw, model, nil) })
	if err != nil {
		return nil, err
	}
	tuples, err := readTuples(ctx, client, schema, ep)
	if err != nil {
		return nil, err
	}
	return &File{Path: ep.Raw, SchemaPath: ep.Raw, Schema: schema, Relationships: tuples}, nil
}

// readModel reads the model the endpoint names, or the latest one of the store, which
// is the one a check with no model named is answered with.
func readModel(ctx context.Context, client openfgav1.OpenFGAServiceClient, ep Endpoint) (*openfgav1.AuthorizationModel, error) {
	callCtx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	if ep.Model != "" {
		resp, err := client.ReadAuthorizationModel(callCtx, &openfgav1.ReadAuthorizationModelRequest{StoreId: ep.Store, Id: ep.Model})
		if err != nil {
			return nil, fmt.Errorf("openfga: reading the model from %s: %w", ep.Raw, err)
		}
		return resp.GetAuthorizationModel(), nil
	}
	resp, err := client.ReadAuthorizationModels(callCtx, &openfgav1.ReadAuthorizationModelsRequest{
		StoreId:  ep.Store,
		PageSize: wrapperspb.Int32(1),
	})
	if err != nil {
		return nil, fmt.Errorf("openfga: reading the model from %s: %w", ep.Raw, err)
	}
	if len(resp.GetAuthorizationModels()) == 0 {
		return nil, fmt.Errorf("openfga: store %s of %s holds no model", ep.Store, ep.Raw)
	}
	return resp.GetAuthorizationModels()[0], nil
}

const (
	// sampleLimit caps how many tuples the live read pulls for the patterns' starting
	// state, a whole number of pages. It is a sample, not the whole store: a production
	// store can hold far more than an analysis needs or could hold in memory.
	sampleLimit = 1000

	// readPageSize is the page a read asks for, the largest a read takes.
	readPageSize = 100
)

// readTuples reads a bounded sample of the store's tuples, and lowers the ones the
// model admits.
func readTuples(ctx context.Context, client openfgav1.OpenFGAServiceClient, schema *Schema, ep Endpoint) ([]zanzibar.Relationship, error) {
	var out []zanzibar.Relationship
	token, read := "", 0
	for read < sampleLimit {
		callCtx, cancel := context.WithTimeout(ctx, readTimeout)
		resp, err := client.Read(callCtx, &openfgav1.ReadRequest{
			StoreId:           ep.Store,
			PageSize:          wrapperspb.Int32(readPageSize),
			ContinuationToken: token,
		})
		cancel()
		if err != nil {
			return nil, fmt.Errorf("openfga: reading tuples from %s: %w", ep.Raw, err)
		}
		for _, tuple := range resp.GetTuples() {
			read++
			lowered := LowerTuple(zanzibar.Position{File: ep.Raw}, tuple.GetKey())
			if schema.Admit(lowered) == nil {
				out = append(out, lowered)
			}
		}
		token = resp.GetContinuationToken()
		if token == "" {
			break
		}
	}
	return out, nil
}

// bearer sends a static bearer token as the authorization metadata of every RPC.
//
// RequireTransportSecurity is false so the token still reaches an OpenFGA named with
// the insecure scheme: a local development server has no certificate, and gRPC would
// otherwise refuse to send a per-RPC credential over plaintext. Sending a secret over
// a plaintext connection is the user's own choice when they write openfga+insecure://.
type bearer struct{ token string }

func (b bearer) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{"authorization": "Bearer " + b.token}, nil
}

func (bearer) RequireTransportSecurity() bool { return false }
