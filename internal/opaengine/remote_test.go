package opaengine

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
)

// policiesHandler serves GET /v1/policies the way OPA does, and refuses a
// request without the expected token when one is set.
func policiesHandler(t *testing.T, token string, policies map[string]string) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/policies" {
			t.Errorf("request to %s, want /v1/policies", r.URL.Path)
		}
		if token != "" && r.Header.Get("Authorization") != "Bearer "+token {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		type policy struct {
			ID  string `json:"id"`
			Raw string `json:"raw"`
		}
		var result []policy
		for id, raw := range policies {
			result = append(result, policy{ID: id, Raw: raw})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"result": result})
	})
}

const remotePolicy = `package authz

import rego.v1

# METADATA
# entrypoint: true
allow if "admin" in data.users[input.user].roles
`

// A running OPA is read over GET /v1/policies: its modules compile into a
// bundle named by the ids the server gave them, the same as files do.
func TestLoadRemoteReadsPolicies(t *testing.T) {
	server := httptest.NewServer(policiesHandler(t, "", map[string]string{"authz/policy.rego": remotePolicy}))
	defer server.Close()

	bundle, err := LoadRemote(t.Context(), server.URL, "", ParseModeAuto)
	if err != nil {
		t.Fatalf("LoadRemote() error = %v", err)
	}
	if !slices.Equal(bundle.Files, []string{"authz/policy.rego"}) {
		t.Errorf("Files = %v, want the policy id the server gave", bundle.Files)
	}

	reads, err := Reads(bundle, Limits{})
	if err != nil {
		t.Fatalf("Reads() error = %v", err)
	}
	if !slices.Contains(reads.Paths(), "data.users[_].roles") {
		t.Errorf("Paths() = %v, want the read of the compiled policy", reads.Paths())
	}
}

// The token travels in the Authorization header. Without it the server refuses,
// and the error says so in a way the caller can turn into a hint.
func TestLoadRemoteSendsTheToken(t *testing.T) {
	server := httptest.NewServer(policiesHandler(t, "s3cret", map[string]string{"policy.rego": remotePolicy}))
	defer server.Close()

	if _, err := LoadRemote(t.Context(), server.URL, "", ParseModeAuto); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("LoadRemote() without the token error = %v, want ErrUnauthorized", err)
	}
	if _, err := LoadRemote(t.Context(), server.URL, "s3cret", ParseModeAuto); err != nil {
		t.Errorf("LoadRemote() with the token error = %v", err)
	}
}

// A server that holds no modules is not a bundle, and says so rather than
// coming back as an empty analysis.
func TestLoadRemoteWithNoPolicies(t *testing.T) {
	server := httptest.NewServer(policiesHandler(t, "", map[string]string{}))
	defer server.Close()

	if _, err := LoadRemote(t.Context(), server.URL, "", ParseModeAuto); !errors.Is(err, ErrNoModules) {
		t.Errorf("LoadRemote() error = %v, want ErrNoModules", err)
	}
}

func TestLoadRemoteOnABadStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	_, err := LoadRemote(t.Context(), server.URL, "", ParseModeAuto)
	if err == nil || errors.Is(err, ErrUnauthorized) {
		t.Errorf("LoadRemote() error = %v, want a plain failure naming the status", err)
	}
}

// The data of a running OPA is read one root at a time, over GET /v1/data/<root>.
// A root the server has nothing under comes back with no result and is skipped,
// not stored as an empty document.
func TestFetchData(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/data/users":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"result": map[string]any{"alice": map[string]any{"roles": []string{"admin"}}},
			})
		case "/v1/data/missing":
			_ = json.NewEncoder(w).Encode(map[string]any{}) // undefined: no result
		default:
			t.Errorf("unexpected request to %s", r.URL.Path)
		}
	}))
	defer server.Close()

	data, err := FetchData(t.Context(), server.URL, "", []string{"missing", "users"})
	if err != nil {
		t.Fatalf("FetchData() error = %v", err)
	}
	if !slices.Equal(data.Files, []string{server.URL + "/v1/data/users"}) {
		t.Errorf("Files = %v, want only the root that resolved", data.Files)
	}
	value, found, err := data.Value(t.Context(), "data.users.alice.roles")
	if err != nil || !found {
		t.Fatalf("data.users.alice.roles not read (found %v, error %v)", found, err)
	}
	if roles, ok := value.([]any); !ok || len(roles) != 1 || roles[0] != "admin" {
		t.Errorf("roles = %v, want [admin] mounted under the root", value)
	}
}

// A server with nothing under any root the decisions read is an analysis without
// data, which says so rather than coming back empty.
func TestFetchDataNoneResolved(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{})
	}))
	defer server.Close()

	if _, err := FetchData(t.Context(), server.URL, "", []string{"users"}); !errors.Is(err, ErrNoData) {
		t.Errorf("FetchData() error = %v, want ErrNoData", err)
	}
}

func TestIsRemote(t *testing.T) {
	for path, want := range map[string]bool{
		"http://localhost:8181": true,
		"https://opa.internal":  true,
		"./policy":              false,
		"bundle.tar.gz":         false,
		"/etc/opa/policy.rego":  false,
	} {
		if got := IsRemote(path); got != want {
			t.Errorf("IsRemote(%q) = %v, want %v", path, got, want)
		}
	}
}
