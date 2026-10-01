package taxonomy

import (
	"errors"
	"path/filepath"
	"slices"
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
			a, err := Load(tt.inputs)
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
	if _, err := Load(Inputs{Paths: []string{dir}}); !errors.Is(err, opaengine.ErrNoDecisions) {
		t.Errorf("Load() error = %v, want opaengine.ErrNoDecisions", err)
	}
}
