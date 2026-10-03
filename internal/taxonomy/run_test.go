package taxonomy

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/saluc28/petard/internal/opaengine"
)

// inferredPolicy annotates nothing, the way most policies are written: a
// decision built from two others, and in another package a rule conftest and
// Gatekeeper read as a refusal.
var inferredPolicy = map[string]string{
	"authz.rego": `package authz

import rego.v1

default authz := false

authz if {
	allow
	not deny
}

allow if "admin" in data.users[input.user].roles

deny if input.user in data.blocked
`,
	"images.rego": `package images

import rego.v1

violation contains msg if {
	not startswith(input.image, data.settings.registry)
	msg := "image from an unknown registry"
}
`,
}

// Nothing names a decision here, so the rules nothing else uses become the
// decisions, the one called violation on the side that refuses, and the
// analysis says it inferred them. A decision named by an annotation, by a flag
// or by an enforcement point is taken as named, and nothing is inferred.
func TestLoadInfersDecisions(t *testing.T) {
	dir := t.TempDir()
	for name, content := range inferredPolicy {
		writeCaseFile(t, filepath.Join(dir, name), content)
	}

	tests := []struct {
		name      string
		inputs    Inputs
		decisions []string
		inferred  bool
	}{
		{
			name:      "nothing names them",
			inputs:    Inputs{Paths: []string{dir}},
			decisions: []string{"data.authz.authz", "data.images.violation"},
			inferred:  true,
		},
		{
			name:      "a flag names one",
			inputs:    Inputs{Paths: []string{dir}, Entrypoints: []string{"authz/allow"}},
			decisions: []string{"data.authz.allow"},
		},
		{
			name:      "the policy annotates them",
			inputs:    Inputs{Paths: []string{fixturePath("policy-v1")}},
			decisions: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := Load(t.Context(), tt.inputs)
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if a.DecisionsInferred != tt.inferred {
				t.Errorf("DecisionsInferred = %v, want %v", a.DecisionsInferred, tt.inferred)
			}
			if tt.decisions != nil && !slices.Equal(a.Reads.Decisions, tt.decisions) {
				t.Errorf("Decisions = %v, want %v", a.Reads.Decisions, tt.decisions)
			}
			if tt.inferred && !a.Reads.Denies("data.images.violation") {
				t.Error("violation was inferred on the side that grants")
			}
		})
	}
}

// A library of functions has no rule a query could ask for, so there is nothing
// to infer, and the run stops rather than analyzing nothing.
func TestLoadWithNothingToInfer(t *testing.T) {
	dir := t.TempDir()
	writeCaseFile(t, filepath.Join(dir, "lib.rego"), `package lib

import rego.v1

is_admin(user) if "admin" in data.users[user].roles
`)
	if _, err := Load(t.Context(), Inputs{Paths: []string{dir}}); !errors.Is(err, opaengine.ErrNoDecisions) {
		t.Errorf("Load() error = %v, want opaengine.ErrNoDecisions", err)
	}
}

// Without -data the run reads the data the bundle carries, and says so; -data
// replaces it, as the documents somebody chose over the ones the bundle ships.
func TestLoadTakesTheDataOfTheBundle(t *testing.T) {
	dir := t.TempDir()
	for name, content := range inferredPolicy {
		writeCaseFile(t, filepath.Join(dir, name), content)
	}
	writeCaseFile(t, filepath.Join(dir, "users", "data.json"), `{"alice": {"roles": ["admin"]}}`)
	other := t.TempDir()
	writeCaseFile(t, filepath.Join(other, "users.json"), `{"users": {"bob": {"roles": []}}}`)

	tests := []struct {
		name     string
		dataPath string
		user     string
		bundled  bool
	}{
		{name: "nothing given", user: "alice", bundled: true},
		{name: "data given", dataPath: other, user: "bob"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := Load(t.Context(), Inputs{Paths: []string{dir}, DataPath: tt.dataPath})
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if a.Data == nil {
				t.Fatal("the analysis has no data")
			}
			if a.DataFromBundle != tt.bundled {
				t.Errorf("DataFromBundle = %v, want %v", a.DataFromBundle, tt.bundled)
			}
			if _, found, err := a.Data.Value(t.Context(), "data.users."+tt.user); err != nil || !found {
				t.Errorf("data.users.%s is not in the data (error %v)", tt.user, err)
			}
		})
	}
}

// A bundle without data is an analysis without it, as before.
func TestLoadWithoutDataInTheBundle(t *testing.T) {
	dir := t.TempDir()
	for name, content := range inferredPolicy {
		writeCaseFile(t, filepath.Join(dir, name), content)
	}
	a, err := Load(t.Context(), Inputs{Paths: []string{dir}})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if a.Data != nil || a.DataFromBundle {
		t.Errorf("data = %v from the bundle %v, want none", a.Data, a.DataFromBundle)
	}
}

// A URL is analyzed by reading the running OPA's policies and the data under the
// roots they read, with the bearer token taken from the environment so it never
// sits on the command line.
func TestLoadFromARunningOPA(t *testing.T) {
	const policy = `package authz

import rego.v1

# METADATA
# entrypoint: true
allow if "admin" in data.users[input.user].roles
`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/v1/policies":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"result": []map[string]string{{"id": "authz/policy.rego", "raw": policy}},
			})
		case "/v1/data/users":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"result": map[string]any{"alice": map[string]any{"roles": []string{"admin"}}},
			})
		default:
			t.Errorf("unexpected request to %s", r.URL.Path)
		}
	}))
	defer server.Close()

	t.Setenv(TokenEnv, "tok")
	a, err := Load(t.Context(), Inputs{Paths: []string{server.URL}})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !slices.Equal(a.Reads.Decisions, []string{"data.authz.allow"}) {
		t.Errorf("Decisions = %v, want the policy the server runs", a.Reads.Decisions)
	}
	if !a.DataFromLive || a.Data == nil {
		t.Fatalf("DataFromLive = %v with data %v, want the data read over the API", a.DataFromLive, a.Data)
	}
	if _, found, err := a.Data.Value(t.Context(), "data.users.alice.roles"); err != nil || !found {
		t.Errorf("data.users.alice.roles was not read from the running OPA (found %v, error %v)", found, err)
	}
}

// A missing token is the ordinary first run, and the error names the variable
// to set rather than the raw rejection.
func TestLoadFromARunningOPAWithoutTheToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	_, err := Load(t.Context(), Inputs{Paths: []string{server.URL}})
	if !errors.Is(err, opaengine.ErrUnauthorized) || !strings.Contains(err.Error(), TokenEnv) {
		t.Errorf("Load() error = %v, want ErrUnauthorized naming %s", err, TokenEnv)
	}
}

// A URL is analyzed on its own. Mixed with a file, there is no single bundle to
// compile, and the run says so instead of guessing which to use.
func TestLoadRefusesAURLWithFiles(t *testing.T) {
	_, err := Load(t.Context(), Inputs{Paths: []string{"http://localhost:8181", "policy.rego"}})
	if err == nil || !strings.Contains(err.Error(), "on its own") {
		t.Errorf("Load() error = %v, want a refusal to mix a URL with files", err)
	}
}
