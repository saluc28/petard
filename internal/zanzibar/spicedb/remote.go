package spicedb

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	v1 "github.com/authzed/authzed-go/proto/authzed/api/v1"
	authzed "github.com/authzed/authzed-go/v1"
	"github.com/authzed/spicedb/pkg/tuple"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/saluc28/petard/internal/zanzibar"
)

// TokenEnv is the environment variable a running SpiceDB's bearer token is read
// from. It is the SpiceDB counterpart to the running OPA's token env, so the two
// live sources are reached the same way: a token the server needs, named once in
// the environment rather than on the command line where a shell would record it.
const TokenEnv = "PETARD_SPICEDB_TOKEN"

// The schemes a running SpiceDB is named with, in place of a path. The address
// after the scheme is the gRPC host:port the server listens on.
const (
	// tlsScheme reaches a SpiceDB over TLS, the shape a deployed one has.
	tlsScheme = "spicedb://"
	// insecureScheme reaches a SpiceDB over plaintext, for a local development
	// one started without a certificate. It is a separate scheme, not a flag, so
	// that turning off transport security is a visible choice in the argument
	// itself rather than a default a reader has to know to look for.
	insecureScheme = "spicedb+insecure://"
)

// Endpoint is a running SpiceDB named on the command line in place of a path.
type Endpoint struct {
	// Address is the gRPC host:port, the scheme taken off.
	Address string
	// Insecure is true when the scheme asked for plaintext transport.
	Insecure bool
	// Raw is the argument as given, so a report names the endpoint the way the
	// user wrote it rather than the bare address.
	Raw string
}

// ParseEndpoint recognizes a running SpiceDB named in place of a path:
// spicedb://host:port over TLS, or spicedb+insecure://host:port over plaintext
// for a local development server. ok is false for everything else, which is a
// file, a directory, a bundle archive, or a running OPA's http(s) URL, so the
// caller leaves those to the loaders that read them.
func ParseEndpoint(arg string) (Endpoint, bool) {
	switch {
	case strings.HasPrefix(arg, insecureScheme):
		return Endpoint{Address: strings.TrimPrefix(arg, insecureScheme), Insecure: true, Raw: arg}, true
	case strings.HasPrefix(arg, tlsScheme):
		return Endpoint{Address: strings.TrimPrefix(arg, tlsScheme), Raw: arg}, true
	}
	return Endpoint{}, false
}

// readTimeout bounds the one schema read, so a server that accepts the
// connection and then never answers fails the command rather than hanging it.
const readTimeout = 30 * time.Second

// ReadLive reads the schema from a running SpiceDB over its API and compiles it
// the way a .zed file on disk is compiled. It is how a schema that lives only
// inside a running SpiceDB, written from code in any language or assembled at
// runtime, is analyzed: the server returns the canonical .zed whatever the
// schema was written as, so petard reads that text and never parses the host
// language.
//
// It also reads a bounded sample of the relationships, so a finding can rest on
// what the store actually holds and not only on the positions the schema
// generates. The sample is capped: a production store can hold far more than an
// analysis needs or should load.
//
// Read only: ReadSchema and ReadRelationships are reads, and nothing here
// writes. token is the bearer the server needs, empty when it needs none; the
// caller reads it from TokenEnv.
func ReadLive(ctx context.Context, ep Endpoint, token string) (*File, error) {
	return readLive(ctx, ep, token)
}

// readLive is ReadLive, plus the dial options a test adds to reach an in-memory
// server. A real call goes through ReadLive and adds none, so the transport
// comes from the endpoint's scheme alone; keeping the seam here keeps it off the
// exported signature.
func readLive(ctx context.Context, ep Endpoint, token string, extra ...grpc.DialOption) (*File, error) {
	if ep.Address == "" {
		return nil, fmt.Errorf("spicedb: %s names no host:port to connect to", ep.Raw)
	}
	transport := credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})
	if ep.Insecure {
		transport = insecure.NewCredentials()
	}
	opts := []grpc.DialOption{grpc.WithTransportCredentials(transport)}
	if token != "" {
		opts = append(opts, grpc.WithPerRPCCredentials(bearer{token: token}))
	}
	opts = append(opts, extra...)

	client, err := authzed.NewClient(ep.Address, opts...)
	if err != nil {
		return nil, fmt.Errorf("spicedb: connecting to %s: %w", ep.Raw, err)
	}
	defer func() { _ = client.Close() }()

	callCtx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	resp, err := client.ReadSchema(callCtx, &v1.ReadSchemaRequest{})
	if err != nil {
		return nil, fmt.Errorf("spicedb: reading schema from %s: %w", ep.Raw, err)
	}

	schema, err := Compile(ep.Raw, nil, 1, resp.GetSchemaText())
	if err != nil {
		return nil, err
	}

	rels, err := readRelationships(ctx, client, ep, resp.GetReadAt())
	if err != nil {
		return nil, err
	}
	return &File{Path: ep.Raw, SchemaPath: ep.Raw, Schema: schema, Relationships: rels}, nil
}

// sampleLimit caps how many relationships the live read pulls for the patterns'
// starting state. It is a sample, not the whole store: the closure takes the
// relationships as one pre-existing state to write on top of, and a production
// store can hold far more than an analysis needs or could hold in memory.
const sampleLimit = 1000

// readRelationships reads a bounded sample of the store's relationships on the
// same connection the schema was read on, and lowers each the way a validation
// file's relationships are lowered, so the patterns read them as the same kind
// of evidence. The empty filter reads across every resource type; schemaReadAt
// pins the read to at least the schema's snapshot, so the sample cannot name a
// type the schema read did not have.
func readRelationships(ctx context.Context, client *authzed.Client, ep Endpoint, schemaReadAt *v1.ZedToken) ([]zanzibar.Relationship, error) {
	req := &v1.ReadRelationshipsRequest{
		RelationshipFilter: &v1.RelationshipFilter{},
		OptionalLimit:      sampleLimit,
	}
	if schemaReadAt != nil {
		req.Consistency = &v1.Consistency{Requirement: &v1.Consistency_AtLeastAsFresh{AtLeastAsFresh: schemaReadAt}}
	}

	callCtx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	stream, err := client.ReadRelationships(callCtx, req)
	if err != nil {
		return nil, fmt.Errorf("spicedb: reading relationships from %s: %w", ep.Raw, err)
	}

	var out []zanzibar.Relationship
	for {
		msg, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("spicedb: reading relationships from %s: %w", ep.Raw, err)
		}
		rel := tuple.FromV1Relationship(msg.GetRelationship())
		out = append(out, lowerRelationship(rel, zanzibar.Position{File: ep.Raw}))
	}
	return out, nil
}

// bearer sends a static bearer token as the authorization metadata of every
// RPC, the way zed does with --token.
//
// RequireTransportSecurity is false so the token still reaches a SpiceDB named
// with the insecure scheme: a local development server has no certificate, and
// gRPC would otherwise refuse to send a per-RPC credential over plaintext.
// Sending a secret over a plaintext connection is the user's own choice when
// they write spicedb+insecure://, not a default this hides.
type bearer struct{ token string }

func (b bearer) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{"authorization": "Bearer " + b.token}, nil
}

func (bearer) RequireTransportSecurity() bool { return false }
