package writemodel

import (
	"errors"
	"fmt"
	"os"
	"strings"

	yaml "go.yaml.in/yaml/v3"
)

// SchemaVersion is the version of the file format this package reads.
const SchemaVersion = 1

// modelKind is the discriminator every file carries, so that a file of another
// shape fails with a sentence instead of with silence.
const modelKind = "write-paths"

var (
	// ErrSchemaVersion is returned for a file written against another version
	// of the format.
	ErrSchemaVersion = errors.New("writemodel: unsupported schema version")

	// ErrNotAWriteModel is returned for a YAML file that is not one.
	ErrNotAWriteModel = errors.New("writemodel: not a write model")

	// ErrInvalid is returned when a file is a write model but does not hold
	// together.
	ErrInvalid = errors.New("writemodel: invalid entry")
)

// Model is who can write what.
type Model struct {
	SchemaVersion int     `yaml:"schema_version"`
	Kind          string  `yaml:"model"`
	Entries       []Entry `yaml:"entries"`
}

// Entry is one writable path.
type Entry struct {
	// RawPath is the path as declared, kept as written so that errors and
	// reports quote the file rather than a rewriting of it.
	RawPath string `yaml:"path"`

	WritableBy []Writer `yaml:"writable_by"`

	// Path is RawPath parsed, filled in by Load.
	Path Path `yaml:"-"`
}

// Writer is somebody who can write a path.
type Writer struct {
	// Principal is a capture of the path ({owner}), a role (role:admin), a
	// system (system:billing), a derived relation (owner_of:{project}), or a
	// concrete name.
	Principal string `yaml:"principal"`

	// Via is how the write happens: an endpoint, a form, a job. The engine
	// does not read it and the report cannot do without it, because a finding
	// without the how is not something anybody can act on.
	Via string `yaml:"via"`

	Note string `yaml:"note"`

	// Confidence is asserted, declared by a person, or discovered, found by a
	// connector. Empty means asserted.
	Confidence string `yaml:"confidence"`

	// AuthorizedBy names the decision the writing endpoint consumes, when the
	// bundle itself decides what this writer may write. It is what turns a
	// writer that is not the subject into the material of PTD-OPA-006: a role
	// that writes a field another decision grants on, with the rule that
	// governs the write present in the same bundle and therefore askable.
	AuthorizedBy *Authorization `yaml:"authorized_by"`
}

// Authorization says that a write goes through a decision of the bundle, and
// how the request to that decision is shaped.
//
// The link between an endpoint and the decision it consumes is not in the
// policy: it lives in the configuration of the enforcement point. Every PEP in
// the wild names that decision the same way, by its full data path, the path it
// queries: the Kafka authorizer takes opa.authorizer.url ending in
// /v1/data/kafka/authz/allow, the sample HTTP API takes POLICY_PATH
// /v1/data/httpapi/authz, the PAM module takes authz_endpoint /v1/data/sshd/authz
// (open-policy-agent/contrib at 90f7ca9). So the write model names it the same
// way, as data.quill.admin.allow, which is also how the rest of Petard spells a
// decision.
//
// A decision reads the value and the target from its input, while the write
// model speaks of data paths, so the two request fields that matter are named
// here as paths into input. The value is what is written, and the analysis asks
// the decision whether writing each granting value is allowed; the target is
// the record the write lands on, set to the subject when the write is to the
// subject's own document, so that a decision which refuses a principal writing
// to somebody else answers for itself.
type Authorization struct {
	// Decision is the rule the writing endpoint consumes, as a data path:
	// data.quill.admin.allow.
	Decision string `yaml:"decision"`

	// Value is the part of the request that carries the value written, as a
	// path into input: input.role.
	Value string `yaml:"value"`

	// Target is the part of the request that names the record the write lands
	// on, as a path into input. It is optional: a decision that never reads who
	// the write is aimed at needs no target, and the write to one's own record
	// is the shape the pattern starts from.
	Target string `yaml:"target"`
}

// IsCapture reports whether this writer is one of the path's own captures,
// which is how the format says "self" without a keyword for it.
func (w Writer) IsCapture() (string, bool) {
	if strings.HasPrefix(w.Principal, "{") && strings.HasSuffix(w.Principal, "}") {
		return strings.Trim(w.Principal, "{}"), true
	}
	return "", false
}

// Load reads a write model from a YAML file.
func Load(path string) (*Model, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("writemodel: reading %s: %w", path, err)
	}

	var model Model
	if err := yaml.Unmarshal(content, &model); err != nil {
		return nil, fmt.Errorf("writemodel: parsing %s: %w", path, err)
	}
	if model.Kind != modelKind {
		return nil, fmt.Errorf("%w: %s declares model %q, want %q", ErrNotAWriteModel, path, model.Kind, modelKind)
	}
	if model.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("%w: %s is version %d, this reads %d", ErrSchemaVersion, path, model.SchemaVersion, SchemaVersion)
	}

	for i := range model.Entries {
		if err := model.Entries[i].parse(); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	return &model, nil
}

// parse fills in the parsed path and checks what the format calls mandatory.
func (e *Entry) parse() error {
	path, err := ParsePath(e.RawPath)
	if err != nil {
		return err
	}
	e.Path = path

	if len(e.WritableBy) == 0 {
		return fmt.Errorf("%w: %s has no writable_by, and a path nobody writes is simply not declared", ErrInvalid, e.RawPath)
	}
	for _, writer := range e.WritableBy {
		if writer.Principal == "" {
			return fmt.Errorf("%w: %s has a writer with no principal", ErrInvalid, e.RawPath)
		}
		if writer.Via == "" {
			return fmt.Errorf("%w: %s: writer %s has no via, and a finding without the how is not actionable", ErrInvalid, e.RawPath, writer.Principal)
		}
		if name, ok := writer.IsCapture(); ok {
			if _, found := path.CapturePosition(name); !found {
				return fmt.Errorf("%w: %s: writer {%s} names a capture the path does not have", ErrInvalid, e.RawPath, name)
			}
		}
		if err := writer.AuthorizedBy.validate(e.RawPath, writer.Principal); err != nil {
			return err
		}
	}
	return nil
}

// validate checks an authorized_by block, when there is one. A block that names
// no decision, or no value, cannot be asked the question the pattern rests on,
// and accepting it in silence would declare an authorization the engine can
// never use.
func (a *Authorization) validate(rawPath, principal string) error {
	if a == nil {
		return nil
	}
	if !strings.HasPrefix(a.Decision, "data.") {
		return fmt.Errorf("%w: %s: writer %s is authorized_by %q, and a decision is named by its data path", ErrInvalid, rawPath, principal, a.Decision)
	}
	if !strings.HasPrefix(a.Value, "input.") {
		return fmt.Errorf("%w: %s: writer %s is authorized_by a decision with value %q, and the value is a path into input", ErrInvalid, rawPath, principal, a.Value)
	}
	if a.Target != "" && !strings.HasPrefix(a.Target, "input.") {
		return fmt.Errorf("%w: %s: writer %s is authorized_by a decision with target %q, and the target is a path into input", ErrInvalid, rawPath, principal, a.Target)
	}
	return nil
}

// Covering returns the entries that cover a path, in the order they were
// declared.
//
// More than one can cover the same read: a model often declares a field and
// the subtree it sits in, and both are true.
func (m *Model) Covering(read Path) []Entry {
	var covering []Entry
	for _, entry := range m.Entries {
		if entry.Path.Matches(read) {
			covering = append(covering, entry)
		}
	}
	return covering
}

// Covers reports whether anything in the model speaks about a path.
//
// It is the question the coverage number answers, and the reason to report
// that number: without it a clean run and an empty model look the same.
func (m *Model) Covers(read Path) bool {
	return len(m.Covering(read)) > 0
}
