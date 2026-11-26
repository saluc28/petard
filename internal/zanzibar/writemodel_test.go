package zanzibar

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/saluc28/petard/internal/evidence"
	"github.com/saluc28/petard/internal/writemodel"
)

func TestParseWriteModel(t *testing.T) {
	content := []byte(`
schema_version: 1
model: relationship-writes
writes:
  - resource: document
    relation: viewer
    operations: [create, touch]
    gate: { holds: edit }
    subject: [user, "team#member"]
    wildcard: true
    caveat:
      - name: ip_allowlist
        parameters:
          user_ip: application
    expiration: writer
  - resource: document
    relation: editor
    operations: [create]
    gate: anyone
    subject: self
creates:
  - creates: user
    gate: anyone
  - creates: team
    gate: anyone
    writes:
      - resource: "{created}"
        relation: member
        subject: "{creator}"
`)
	m, err := ParseWriteModel(content)
	if err != nil {
		t.Fatalf("ParseWriteModel: %v", err)
	}
	if len(m.Writes) != 2 || len(m.Creates) != 2 {
		t.Fatalf("got %d writes and %d creates, want 2 and 2", len(m.Writes), len(m.Creates))
	}

	viewer := m.Writes[0]
	if viewer.Gate.Holds != "edit" {
		t.Errorf("viewer gate holds = %q, want edit", viewer.Gate.Holds)
	}
	if !viewer.Wildcard {
		t.Error("viewer rule should allow a wildcard subject")
	}
	if got := viewer.Subject.Types; len(got) != 2 || got[0] != "user" || got[1] != "team#member" {
		t.Errorf("viewer subject types = %v, want [user team#member]", got)
	}
	if len(viewer.Caveats) != 1 || viewer.Caveats[0].Filler("user_ip") != FillerApplication {
		t.Errorf("viewer caveat should fill user_ip from the application, got %+v", viewer.Caveats)
	}
	if viewer.Caveats[0].Filler("cidr") != FillerWriter {
		t.Error("a parameter the caveat says nothing about is the writer's")
	}

	editor := m.Writes[1]
	if !editor.Gate.Anyone || !editor.Subject.Self {
		t.Errorf("editor rule = %+v, want an anyone gate and a self subject", editor)
	}

	if !m.Creates[0].Gate.Anyone || m.Creates[0].Creates != "user" {
		t.Errorf("first creation = %+v, want user gated anyone", m.Creates[0])
	}
	team := m.Creates[1]
	if len(team.Writes) != 1 || team.Writes[0].Subject != CreatorPlaceholder {
		t.Errorf("team creation writes = %+v, want one write of the creator", team.Writes)
	}
}

// A rule cites the lines of the application that make its write, in either form a
// citation takes, and a creation does too; a citation that is not path:line is refused.
func TestParseWriteModelEvidence(t *testing.T) {
	m, err := ParseWriteModel([]byte(`
schema_version: 1
model: relationship-writes
writes:
  - resource: document
    relation: viewer
    operations: [create]
    gate: anyone
    subject: self
    evidence:
      - api/share.go:88
      - {at: api/share.go:91, text: WriteRelationships}
creates:
  - creates: user
    gate: anyone
    evidence: [api/signup.go:12]
`))
	if err != nil {
		t.Fatal(err)
	}
	got := []string{}
	for _, c := range append(slices.Clone(m.Writes[0].Evidence), m.Creates[0].Evidence...) {
		got = append(got, c.String()+" "+c.Text)
	}
	want := []string{"api/share.go:88 ", "api/share.go:91 WriteRelationships", "api/signup.go:12 "}
	if !slices.Equal(got, want) {
		t.Errorf("evidence = %q, want %q", got, want)
	}

	_, err = ParseWriteModel([]byte("schema_version: 1\nmodel: relationship-writes\nwrites:\n  - resource: document\n    relation: viewer\n    operations: [create]\n    gate: anyone\n    subject: self\n    evidence: [api/share.go]\n"))
	if !errors.Is(err, evidence.ErrCitation) {
		t.Errorf("a citation with no line: %v, want %v", err, evidence.ErrCitation)
	}
}

func TestParseWriteModelErrors(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    error
	}{
		{
			name:    "wrong kind",
			content: "schema_version: 1\nmodel: write-paths\n",
			want:    writemodel.ErrNotAWriteModel,
		},
		{
			name:    "wrong version",
			content: "schema_version: 2\nmodel: relationship-writes\n",
			want:    writemodel.ErrSchemaVersion,
		},
		{
			name:    "unknown top-level key",
			content: "schema_version: 1\nmodel: relationship-writes\nentries: []\n",
			want:    writemodel.ErrInvalid, // named as an unknown key, not a Go type
		},
		{
			name:    "no operations",
			content: "schema_version: 1\nmodel: relationship-writes\nwrites:\n  - resource: document\n    relation: viewer\n    gate: anyone\n",
			want:    writemodel.ErrInvalid,
		},
		{
			name:    "unknown operation",
			content: "schema_version: 1\nmodel: relationship-writes\nwrites:\n  - resource: document\n    relation: viewer\n    operations: [grant]\n    gate: anyone\n",
			want:    writemodel.ErrInvalid,
		},
		{
			name:    "no gate",
			content: "schema_version: 1\nmodel: relationship-writes\nwrites:\n  - resource: document\n    relation: viewer\n    operations: [create]\n",
			want:    writemodel.ErrInvalid,
		},
		{
			name:    "gate both holds and service",
			content: "schema_version: 1\nmodel: relationship-writes\nwrites:\n  - resource: document\n    relation: viewer\n    operations: [create]\n    gate: { holds: edit, service: billing }\n",
			want:    writemodel.ErrInvalid,
		},
		{
			name:    "gate both holds and holds_on_subject",
			content: "schema_version: 1\nmodel: relationship-writes\nwrites:\n  - resource: thing\n    relation: admin\n    operations: [create]\n    gate: { holds: edit, holds_on_subject: can_edit }\n    subject: [group#member]\n",
			want:    writemodel.ErrInvalid,
		},
		{
			name:    "holds_on_subject on a creation",
			content: "schema_version: 1\nmodel: relationship-writes\ncreates:\n  - creates: group\n    gate: { holds_on_subject: can_edit }\n",
			want:    writemodel.ErrInvalid,
		},
		{
			name:    "gate word not anyone",
			content: "schema_version: 1\nmodel: relationship-writes\nwrites:\n  - resource: document\n    relation: viewer\n    operations: [create]\n    gate: everyone\n",
			want:    writemodel.ErrInvalid,
		},
		{
			name:    "unknown key in gate",
			content: "schema_version: 1\nmodel: relationship-writes\nwrites:\n  - resource: document\n    relation: viewer\n    operations: [create]\n    gate: { hold: edit }\n",
			want:    writemodel.ErrInvalid,
		},
		{
			name:    "subject word not self or any",
			content: "schema_version: 1\nmodel: relationship-writes\nwrites:\n  - resource: document\n    relation: viewer\n    operations: [create]\n    gate: anyone\n    subject: everyone\n",
			want:    writemodel.ErrInvalid,
		},
		{
			name:    "no subject and no wildcard",
			content: "schema_version: 1\nmodel: relationship-writes\nwrites:\n  - resource: document\n    relation: viewer\n    operations: [create]\n    gate: anyone\n",
			want:    writemodel.ErrInvalid,
		},
		{
			name:    "empty subject list",
			content: "schema_version: 1\nmodel: relationship-writes\nwrites:\n  - resource: document\n    relation: viewer\n    operations: [create]\n    gate: anyone\n    subject: []\n",
			want:    writemodel.ErrInvalid,
		},
		{
			name:    "delete with a wildcard but no subject",
			content: "schema_version: 1\nmodel: relationship-writes\nwrites:\n  - resource: document\n    relation: viewer\n    operations: [delete]\n    gate: anyone\n    wildcard: true\n",
			want:    writemodel.ErrInvalid,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseWriteModel([]byte(tt.content))
			if err == nil {
				t.Fatal("want an error, got nil")
			}
			if tt.want != nil && !errors.Is(err, tt.want) {
				t.Errorf("error = %v, want %v", err, tt.want)
			}
		})
	}
}

// A gate held on the object the subject names, holds_on_subject, parses as such:
// the form that gates granting a group a right by the right to edit the group,
// rather than by a permission on the resource.
func TestParseWriteModelSubjectGate(t *testing.T) {
	content := []byte("schema_version: 1\nmodel: relationship-writes\nwrites:\n  - resource: thing\n    relation: admin\n    operations: [create]\n    gate: { holds_on_subject: can_edit }\n    subject: [group#member]\n")
	m, err := ParseWriteModel(content)
	if err != nil {
		t.Fatalf("ParseWriteModel: %v", err)
	}
	if len(m.Writes) != 1 {
		t.Fatalf("got %d write rules, want 1", len(m.Writes))
	}
	g := m.Writes[0].Gate
	if g.HoldsOnSubject != "can_edit" || g.Holds != "" || g.Anyone || g.Service != "" {
		t.Errorf("gate = %+v, want only HoldsOnSubject can_edit", g)
	}
}

// A rule that only adds the every-object subject needs no subject list: the
// wildcard is the subject it writes, so an add-only wildcard rule with no
// subject is accepted, where a rule that names neither a subject nor a wildcard
// is turned away rather than kept as one that writes nothing.
func TestParseWriteModelWildcardNeedsNoSubject(t *testing.T) {
	content := []byte("schema_version: 1\nmodel: relationship-writes\n" +
		"writes:\n  - resource: document\n    relation: viewer\n    operations: [create, touch]\n    gate: anyone\n    wildcard: true\n")
	m, err := ParseWriteModel(content)
	if err != nil {
		t.Fatalf("ParseWriteModel: %v", err)
	}
	if len(m.Writes) != 1 || !m.Writes[0].Wildcard || !m.Writes[0].Subject.empty() {
		t.Fatalf("want one wildcard rule with an empty subject spec, got %+v", m.Writes)
	}
}

// A key a gate does not have fails with the keys it does have, so the writer
// learns the shape from the error instead of from the source.
func TestUnknownGateKeyListsTheValidKeys(t *testing.T) {
	content := []byte("schema_version: 1\nmodel: relationship-writes\nwrites:\n  - resource: document\n    relation: viewer\n    operations: [create]\n    gate: { hold: edit }\n    subject: [user]\n")
	_, err := ParseWriteModel(content)
	if !errors.Is(err, writemodel.ErrInvalid) {
		t.Fatalf("error is not ErrInvalid: %v", err)
	}
	for _, want := range []string{`unknown key "hold"`, "holds, holds_on_subject, service"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not list the valid keys (%q): %v", want, err)
		}
	}
}
