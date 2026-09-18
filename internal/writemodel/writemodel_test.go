package writemodel

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func fixtureModel(t *testing.T) *Model {
	t.Helper()

	model, err := Load(filepath.Join("..", "..", "fixtures", "vulnerable-bundle", "write-model.yaml"))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	return model
}

// The fixture declares six paths, and the two that matter are the case and
// the counter case of the self write pattern: the same record, one field the
// subject writes and one only an administrator writes.
func TestLoadFixture(t *testing.T) {
	model := fixtureModel(t)

	if model.SchemaVersion != SchemaVersion {
		t.Errorf("schema version = %d, want %d", model.SchemaVersion, SchemaVersion)
	}
	if len(model.Entries) != 6 {
		t.Fatalf("entries = %d, want 6", len(model.Entries))
	}

	department := model.Entries[0]
	if department.RawPath != "data.users.{owner}.profile.department" {
		t.Fatalf("first entry = %q", department.RawPath)
	}
	if got := department.Path.String(); got != department.RawPath {
		t.Errorf("parsed back as %q, want %q", got, department.RawPath)
	}
	name, isCapture := department.WritableBy[0].IsCapture()
	if !isCapture || name != "owner" {
		t.Errorf("first writer = %q, want the capture {owner}", department.WritableBy[0].Principal)
	}
	if position, ok := department.Path.CapturePosition("owner"); !ok || position != 2 {
		t.Errorf("capture {owner} at %d (found %t), want position 2", position, ok)
	}

	// The roles entry carries the split-grant declaration: support may write
	// it, and what support may write is decided by another rule of the bundle.
	roles := model.Entries[2]
	if roles.RawPath != "data.users.{owner}.roles" {
		t.Fatalf("third entry = %q, want the roles path", roles.RawPath)
	}
	support := roles.WritableBy[1]
	if support.Principal != "role:support" {
		t.Fatalf("second writer of roles = %q, want role:support", support.Principal)
	}
	if support.AuthorizedBy == nil {
		t.Fatal("role:support has no authorized_by, so PTD-OPA-006 cannot ask which value it may write")
	}
	if support.AuthorizedBy.Decision != "data.quill.admin.allow" {
		t.Errorf("authorized_by decision = %q, want data.quill.admin.allow", support.AuthorizedBy.Decision)
	}
	if support.AuthorizedBy.Value != "input.role" {
		t.Errorf("authorized_by value = %q, want input.role", support.AuthorizedBy.Value)
	}
	if roles.WritableBy[0].AuthorizedBy != nil {
		t.Error("role:admin carries an authorized_by it should not: only the constrained writer needs one")
	}
}

func TestModelCovering(t *testing.T) {
	model := fixtureModel(t)

	tests := []struct {
		name     string
		read     string
		expected []string
	}{
		{
			name: "a field and the subtree it sits in",
			read: "data.users[_].profile.department",
			expected: []string{
				"data.users.{owner}.profile.department",
				"data.users.{owner}.profile.*",
			},
		},
		{
			name:     "a field of the same record nobody but an admin writes",
			read:     "data.users[_].roles",
			expected: []string{"data.users.{owner}.roles"},
		},
		{
			// Deliberately undeclared: closed world means this is not writable,
			// which is a known false negative rather than a silent one.
			name:     "a path the model does not speak about",
			read:     "data.projects[_].parent",
			expected: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			read, err := ParsePath(tt.read)
			if err != nil {
				t.Fatalf("ParsePath() error = %v", err)
			}

			var covering []string
			for _, entry := range model.Covering(read) {
				covering = append(covering, entry.RawPath)
			}
			if len(covering) != len(tt.expected) {
				t.Fatalf("covering = %v, want %v", covering, tt.expected)
			}
			for i, expected := range tt.expected {
				if covering[i] != expected {
					t.Errorf("covering[%d] = %q, want %q", i, covering[i], expected)
				}
			}
		})
	}
}

func TestPathMatching(t *testing.T) {
	tests := []struct {
		name     string
		entry    string
		read     string
		expected bool
	}{
		{name: "identical literals", entry: "data.tenants.status", read: "data.tenants.status", expected: true},
		{name: "a capture takes any segment", entry: "data.users.{owner}.roles", read: "data.users[_].roles", expected: true},
		{name: "a different field", entry: "data.users.{owner}.roles", read: "data.users[_].profile", expected: false},
		{name: "a shorter read", entry: "data.users.{owner}.profile.department", read: "data.users[_].profile", expected: false},
		{name: "a longer read", entry: "data.users.{owner}.profile", read: "data.users[_].profile.department", expected: false},
		{name: "a subtree covers what is below", entry: "data.users.{owner}.profile.*", read: "data.users[_].profile.department", expected: true},
		{name: "a subtree covers deeply", entry: "data.users.*", read: "data.users[_].profile.department.name", expected: true},
		{name: "a subtree does not cross the collection", entry: "data.users.*", read: "data.projects[_].members", expected: false},
		// The engine writes one [_] for each level of a nested collection.
		{name: "a capture for each level of a nested collection", entry: "data.git.{file}.{line}.Author", read: "data.git[_][_].Author", expected: true},
		{name: "a nested collection is not the level above it", entry: "data.git.{file}.Author", read: "data.git[_][_].Author", expected: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry, err := ParsePath(tt.entry)
			if err != nil {
				t.Fatalf("ParsePath(%q) error = %v", tt.entry, err)
			}
			read, err := ParsePath(tt.read)
			if err != nil {
				t.Fatalf("ParsePath(%q) error = %v", tt.read, err)
			}

			if got := entry.Matches(read); got != tt.expected {
				t.Errorf("%q matches %q = %t, want %t", tt.entry, tt.read, got, tt.expected)
			}
		})
	}
}

// A concrete index names one document wherever it sits, the second level of a
// nested collection included.
func TestParsePathRefusesAConcreteIndex(t *testing.T) {
	for _, path := range []string{"data.users[alice].roles", "data.git[_][3].Author", "data.git[3][_].Author"} {
		if _, err := ParsePath(path); err == nil {
			t.Errorf("ParsePath(%q) error = nil, want a refusal", path)
		}
	}
}

// An endpoint that adds a member sends the collection it writes and not the
// member, so the decision behind it reads no value, and the parts the endpoint
// fills in itself carry the captures of the path.
func TestLoadReadsAnAuthorizationWithNoValue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "write-model.yaml")
	content := `schema_version: 1
model: write-paths
entries:
  - path: data.policies.{policy}.members.{member}
    writable_by:
      - principal: role:policy-member-editor
        via: "POST /apis/iam/v2/policies/{policy}/members:add"
        authorized_by:
          decision: data.authz.authorized_project
          request:
            input.action: "iam:policyMembers:create"
            input.resource: "iam:policies:{policy}:members"
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing the file: %v", err)
	}

	model, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	entry := model.Entries[0]
	auth := entry.WritableBy[0].AuthorizedBy
	if auth == nil || auth.Value != "" {
		t.Fatalf("authorized_by = %+v, want one that reads no value", auth)
	}

	filled, err := entry.Path.Fill(auth.Request["input.resource"], []string{"data", "policies", "administrator-access", "members"})
	if err != nil {
		t.Fatalf("Fill() error = %v", err)
	}
	if filled != "iam:policies:administrator-access:members" {
		t.Errorf("Fill() = %q, want the resource of that one policy", filled)
	}
}

func TestLoadRejects(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		expectedErr error
	}{
		{
			name:        "another kind of file",
			content:     "schema_version: 1\nmodel: taxonomy\nentries: []\n",
			expectedErr: ErrNotAWriteModel,
		},
		{
			name:        "a version this cannot read",
			content:     "schema_version: 2\nmodel: write-paths\nentries: []\n",
			expectedErr: ErrSchemaVersion,
		},
		{
			name: "a writer with no via",
			// The how is what makes a finding actionable, so the format calls
			// it mandatory and so does this.
			content:     "schema_version: 1\nmodel: write-paths\nentries:\n  - path: data.users.{owner}.roles\n    writable_by:\n      - principal: role:admin\n",
			expectedErr: ErrInvalid,
		},
		{
			name:        "a writer naming a capture the path has not got",
			content:     "schema_version: 1\nmodel: write-paths\nentries:\n  - path: data.users.{owner}.roles\n    writable_by:\n      - principal: \"{tenant}\"\n        via: PATCH /whatever\n",
			expectedErr: ErrInvalid,
		},
		{
			name:        "a subtree in the middle",
			content:     "schema_version: 1\nmodel: write-paths\nentries:\n  - path: data.users.*.roles\n    writable_by:\n      - principal: role:admin\n        via: console\n",
			expectedErr: nil, // parse error, not one of the sentinels
		},
		{
			name: "an authorized_by whose value is not a path into input",
			// The decision reads what is written from its request, so naming a
			// data path there could never be asked of it.
			content:     "schema_version: 1\nmodel: write-paths\nentries:\n  - path: data.users.{owner}.roles\n    writable_by:\n      - principal: role:support\n        via: PUT /roles\n        authorized_by:\n          decision: data.quill.admin.allow\n          value: data.roles\n",
			expectedErr: ErrInvalid,
		},
		{
			name:        "a request filled in somewhere other than input",
			content:     "schema_version: 1\nmodel: write-paths\nentries:\n  - path: data.policies.{policy}.members.{member}\n    writable_by:\n      - principal: role:editor\n        via: POST /members\n        authorized_by:\n          decision: data.authz.authorized_project\n          request:\n            action: write\n",
			expectedErr: ErrInvalid,
		},
		{
			name:        "a request naming a capture the path has not got",
			content:     "schema_version: 1\nmodel: write-paths\nentries:\n  - path: data.policies.{policy}.members.{member}\n    writable_by:\n      - principal: role:editor\n        via: POST /members\n        authorized_by:\n          decision: data.authz.authorized_project\n          request:\n            input.resource: \"iam:policies:{id}:members\"\n",
			expectedErr: ErrInvalid,
		},
		{
			name:        "an authorized_by whose decision is not a data path",
			content:     "schema_version: 1\nmodel: write-paths\nentries:\n  - path: data.users.{owner}.roles\n    writable_by:\n      - principal: role:support\n        via: PUT /roles\n        authorized_by:\n          decision: admin/allow\n          value: input.role\n",
			expectedErr: ErrInvalid,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "write-model.yaml")
			if err := os.WriteFile(path, []byte(tt.content), 0o600); err != nil {
				t.Fatalf("writing the file: %v", err)
			}

			_, err := Load(path)
			if err == nil {
				t.Fatal("Load() error = nil, want a refusal")
			}
			if tt.expectedErr != nil && !errors.Is(err, tt.expectedErr) {
				t.Errorf("Load() error = %v, want %v", err, tt.expectedErr)
			}
		})
	}
}
