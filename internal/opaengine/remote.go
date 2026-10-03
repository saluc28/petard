package opaengine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Petard reads a running OPA the way a collector reads a directory service: over
// its REST API, read only. It fetches the policies the server holds, and asks
// the server to decide nothing, so pointing it at a live PDP observes the
// deployment without exercising it.

const (
	// remoteTimeout bounds one request to a running OPA, so a server that
	// accepts the connection and then stalls does not hang the analysis.
	remoteTimeout = 30 * time.Second

	// maxResponseBytes caps one response body held in memory. The data of a
	// real deployment can be large, but a body past this is a server that is
	// wedged or hostile rather than one worth reading in whole.
	maxResponseBytes = 256 << 20
)

// ErrUnauthorized is returned when a running OPA rejects the request, which is
// what a missing or wrong token looks like. It is its own error so the caller
// can name the token environment variable, which this package does not know.
var ErrUnauthorized = errors.New("opaengine: the OPA server rejected the request")

// IsRemote reports whether a path names a running OPA rather than a file or a
// directory: an http or https URL.
func IsRemote(path string) bool {
	return strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://")
}

// opaClient reads one running OPA, read only.
type opaClient struct {
	base  string
	token string
	http  *http.Client
}

func newClient(base, token string) *opaClient {
	return &opaClient{
		base:  strings.TrimRight(base, "/"),
		token: token,
		http:  &http.Client{Timeout: remoteTimeout},
	}
}

// get reads one endpoint and decodes its JSON body into v.
//
// The token, when there is one, travels in the Authorization header and nowhere
// else, so it never lands in a URL, a log line or an error message.
func (c *opaClient) get(ctx context.Context, path string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return fmt.Errorf("opaengine: building the request for %s: %w", path, err)
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("opaengine: reading %s from %s: %w", path, c.base, err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return fmt.Errorf("%w: %s for %s%s", ErrUnauthorized, resp.Status, c.base, path)
	case resp.StatusCode != http.StatusOK:
		return fmt.Errorf("opaengine: %s%s returned %s", c.base, path, resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("opaengine: reading %s from %s: %w", path, c.base, err)
	}
	if int64(len(body)) > maxResponseBytes {
		return fmt.Errorf("opaengine: %s%s returned more than %d bytes", c.base, path, maxResponseBytes)
	}
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("opaengine: parsing %s from %s: %w", path, c.base, err)
	}
	return nil
}

// LoadRemote reads the policies of a running OPA and compiles them into a
// bundle, the same as Load does for files.
//
// GET /v1/policies returns the source of every module the server holds, under
// the id it was loaded with (v1/server/server.go:2179 at v1.20.2). Petard
// compiles that source, so it analyzes the policy the server is actually
// running, not a checkout that may have moved on.
func LoadRemote(ctx context.Context, base, token string, mode ParseMode) (*Bundle, error) {
	var response struct {
		Result []struct {
			ID  string `json:"id"`
			Raw string `json:"raw"`
		} `json:"result"`
	}
	if err := newClient(base, token).get(ctx, "/v1/policies", &response); err != nil {
		return nil, err
	}

	sources := make([]source, 0, len(response.Result))
	for _, policy := range response.Result {
		if policy.Raw == "" {
			continue
		}
		sources = append(sources, source{name: policy.ID, text: policy.Raw})
	}
	if len(sources) == 0 {
		return nil, fmt.Errorf("%w at %s", ErrNoModules, base)
	}
	return bundleFrom(sources, mode)
}
