package opaengine

import (
	"slices"
	"testing"
)

// The write surface is the branches that grant on a write method: the POST and
// the DELETE here, each with the path it fixes, and not the GET, which guards a
// read. Two allow blocks share the rule path data.authz.allow, so the endpoints
// are told apart by the physical block, not the path.
func TestWriteEndpoints(t *testing.T) {
	policy := `package authz

import rego.v1

default allow := false

allow if {
	input.method == "POST"
	input.path == ["users"]
}

allow if {
	input.method == "GET"
	input.path == ["users"]
}

allow if {
	input.method == "DELETE"
	input.path == ["sessions", "current"]
}
`
	dir := writeSources(t, map[string]string{"policy.rego": policy})
	bundle, err := Load([]string{dir}, ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	bundle.Entrypoints = []string{"authz/allow"}

	reads, err := Reads(bundle, Limits{})
	if err != nil {
		t.Fatalf("Reads() error = %v", err)
	}

	endpoints := WriteEndpoints(reads)
	got := make(map[string]string, len(endpoints))
	for _, endpoint := range endpoints {
		if endpoint.Decision != "data.authz.allow" {
			t.Errorf("endpoint %s grants %s, want data.authz.allow", endpoint.Method, endpoint.Decision)
		}
		got[endpoint.Method] = endpoint.Path
	}

	want := map[string]string{
		"POST":   `["users"]`,
		"DELETE": `["sessions", "current"]`,
	}
	for method, path := range want {
		if got[method] != path {
			t.Errorf("%s path = %q, want %q", method, got[method], path)
		}
	}
	if _, ok := got["GET"]; ok {
		t.Error("GET is a read, not a write the surface should list")
	}
}

// A path that holds variables is no constant, so it is no check, but it is still
// the shape of the endpoint: the literals are the fixed segments, the variables
// the ones the request fills, as {name} placeholders.
func TestWriteEndpointsShapesAVariablePath(t *testing.T) {
	policy := `package authz

import rego.v1

default allow := false

allow if {
	input.method = "PUT"
	input.path = ["teams", team, "members", member]
}
`
	dir := writeSources(t, map[string]string{"policy.rego": policy})
	bundle, err := Load([]string{dir}, ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	bundle.Entrypoints = []string{"authz/allow"}

	reads, err := Reads(bundle, Limits{})
	if err != nil {
		t.Fatalf("Reads() error = %v", err)
	}

	endpoints := WriteEndpoints(reads)
	if len(endpoints) != 1 {
		t.Fatalf("endpoints = %v, want one", endpoints)
	}
	want := `["teams", "{team}", "members", "{member}"]`
	if endpoints[0].Path != want {
		t.Errorf("path = %q, want %q", endpoints[0].Path, want)
	}
}

// A branch that refuses on the method, under a negation, is no write surface: it
// is the method being ruled out, not granted.
func TestWriteEndpointsSkipsANegatedMethod(t *testing.T) {
	policy := `package authz

import rego.v1

default allow := false

allow if {
	not input.method == "DELETE"
	input.path == ["safe"]
}
`
	dir := writeSources(t, map[string]string{"policy.rego": policy})
	bundle, err := Load([]string{dir}, ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	bundle.Entrypoints = []string{"authz/allow"}

	reads, err := Reads(bundle, Limits{})
	if err != nil {
		t.Fatalf("Reads() error = %v", err)
	}
	if endpoints := WriteEndpoints(reads); len(endpoints) != 0 {
		if slices.ContainsFunc(endpoints, func(e WriteEndpoint) bool { return e.Method == "DELETE" }) {
			t.Errorf("a negated method was taken as a write the policy authorizes: %v", endpoints)
		}
	}
}
