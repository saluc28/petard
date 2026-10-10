package pep

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	pepregistry "github.com/saluc28/petard/pep-registry"
)

// Every declaration the binary carries has to load, since a -pep that names one
// of them and fails would fail on somebody else's machine and not in a test.
func TestTheRegistryLoads(t *testing.T) {
	points, err := List(pepregistry.Files)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	var ids []string
	for _, point := range points {
		ids = append(ids, point.ID)
		if point.File != pepregistry.Dir+"/"+point.ID+".yaml" {
			t.Errorf("%s is filed as %s, and -pep finds a declaration by its id", point.ID, point.File)
		}
	}
	if expected := []string{"kuadrant-mcp-gateway", "spacelift-login"}; !slices.Equal(ids, expected) {
		t.Errorf("ids = %v, want %v", ids, expected)
	}
}

// The first entry that covers a part of the request answers for it, which is
// what lets a declaration say the teams are names an issuer hands over and the
// rest of the session is the product's own.
func TestFieldForTakesTheFirstEntryThatCovers(t *testing.T) {
	spacelift, err := Find(pepregistry.Files, "spacelift-login")
	if err != nil {
		t.Fatalf("Find() error = %v", err)
	}
	gateway, err := Find(pepregistry.Files, "kuadrant-mcp-gateway")
	if err != nil {
		t.Fatalf("Find() error = %v", err)
	}

	tests := []struct {
		point      *EnforcementPoint
		path       string
		setBy      SetBy
		identifier Identifier
	}{
		{spacelift, "input.session.teams[_]", SetByIssuer, IdentifierName},
		{spacelift, "input.session.idp_subject", SetByIssuer, IdentifierID},
		{spacelift, "input.session.machine", SetByEnforcementPoint, ""},
		{gateway, `input.request.headers["x-mcp-toolname"]`, SetByCaller, ""},
		{gateway, `input.request.headers["x-mcp-servername"]`, SetByEnforcementPoint, ""},
		{gateway, `input.request.headers["x-forwarded-for"]`, SetByCaller, ""},
		{gateway, "input.auth.identity.preferred_username", SetByIssuer, ""},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			field, found := tt.point.FieldFor(tt.path)
			if !found {
				t.Fatalf("FieldFor(%s) found nothing", tt.path)
			}
			if field.SetBy != tt.setBy || field.Identifier != tt.identifier {
				t.Errorf("FieldFor(%s) = %s, %q, want %s, %q", tt.path, field.SetBy, field.Identifier, tt.setBy, tt.identifier)
			}
		})
	}

	if field, found := spacelift.FieldFor("input.spaces[_].id"); found {
		t.Errorf("FieldFor(input.spaces[_].id) = %+v, want nothing: no entry speaks about it", field)
	}
}

// The decisions are named, and a bundle says which of its rules have that name.
func TestEntrypointsSplitsTheDecisionsBySide(t *testing.T) {
	spacelift, err := Find(pepregistry.Files, "spacelift-login")
	if err != nil {
		t.Fatalf("Find() error = %v", err)
	}
	rules := map[string][]string{
		"allow": {"data.spacelift.allow"},
		"admin": {"data.spacelift.admin"},
		"deny":  {"data.spacelift.deny"},
	}
	grants, denies := spacelift.Entrypoints(func(name string) []string { return rules[name] })

	if expected := []string{"data.spacelift.allow", "data.spacelift.admin"}; !slices.Equal(grants, expected) {
		t.Errorf("grants = %v, want %v", grants, expected)
	}
	if expected := []string{"data.spacelift.deny"}; !slices.Equal(denies, expected) {
		t.Errorf("denies = %v, want %v", denies, expected)
	}
}

// A key the format does not have is refused with its name. Read as nothing,
// bounded-by would leave the requested authority with no ceiling, and
// PTD-OPA-013 would report a candidate where the declaration meant a finding.
func TestLoadRefusesAKeyTheFormatDoesNotHave(t *testing.T) {
	const content = "schema_version: 1\nid: x\ndecisions:\n  - rule: allow\n    side: grants\n" +
		"fields:\n  - path: input.scope\n    set_by: caller\n    authority: requested\n" +
		"    bounded-by: [input.edge]\n    evidence: [x]\n"
	path := filepath.Join(t.TempDir(), "x.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing the file: %v", err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() error = nil, want the misspelled key refused")
	}
	if !strings.Contains(err.Error(), "bounded-by") {
		t.Errorf("Load() error = %v, want it to name the key", err)
	}
}

func TestLoadRejects(t *testing.T) {
	const header = "schema_version: 1\nid: x\nengine: opa\ndecisions:\n  - rule: allow\n    side: grants\n"
	tests := []struct {
		name    string
		content string
	}{
		{"an empty file", ""},
		{"another version", "schema_version: 2\nid: x\ndecisions:\n  - rule: allow\n    side: grants\n"},
		{"no id", "schema_version: 1\ndecisions:\n  - rule: allow\n    side: grants\n"},
		{"no decision", "schema_version: 1\nid: x\n"},
		{"a decision that is a path", "schema_version: 1\nid: x\ndecisions:\n  - rule: authz/allow\n    side: grants\n"},
		{"a side that is neither", "schema_version: 1\nid: x\ndecisions:\n  - rule: allow\n    side: maybe\n"},
		{"a subject outside the request", header + "subject: data.user\n"},
		{"a field outside the request", header + "fields:\n  - path: data.users\n    set_by: caller\n    evidence: [x]\n"},
		{"a field that is not a path", header + "fields:\n  - path: input.team[\n    set_by: caller\n    evidence: [x]\n"},
		{"a setter that is none of the three", header + "fields:\n  - path: input.team\n    set_by: somebody\n    evidence: [x]\n"},
		{"an issuer nobody names", header + "fields:\n  - path: input.token.sub\n    set_by: issuer\n    evidence: [x]\n"},
		{"an identifier that is neither", header + "fields:\n  - path: input.token.sub\n    set_by: issuer\n    issuer: idp\n    identifier: email\n    evidence: [x]\n"},
		{"an identifier on a part the caller sets", header + "fields:\n  - path: input.team\n    set_by: caller\n    identifier: name\n    evidence: [x]\n"},
		{"a field with no evidence", header + "fields:\n  - path: input.team\n    set_by: caller\n"},
		{"an authority that is neither", header + "fields:\n  - path: input.scope\n    set_by: caller\n    authority: both\n    evidence: [x]\n"},
		{"an identity that is also an authority", header + "fields:\n  - path: input.id\n    set_by: issuer\n    issuer: idp\n    identity: true\n    authority: requested\n    evidence: [x]\n"},
		{"bounded_by on a part that is not requested", header + "fields:\n  - path: input.ceiling\n    set_by: issuer\n    issuer: idp\n    authority: ceiling\n    bounded_by: [input.other]\n    evidence: [x]\n"},
		{"a ceiling that is neither request nor data", header + "fields:\n  - path: input.scope\n    set_by: caller\n    authority: requested\n    bounded_by: [scope.other]\n    evidence: [x]\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "x.yaml")
			if err := os.WriteFile(path, []byte(tt.content), 0o600); err != nil {
				t.Fatalf("writing the file: %v", err)
			}
			if _, err := Load(path); !errors.Is(err, ErrInvalid) {
				t.Errorf("Load() error = %v, want ErrInvalid", err)
			}
		})
	}
}
