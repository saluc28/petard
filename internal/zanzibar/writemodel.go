package zanzibar

import (
	"fmt"
	"os"
	"slices"

	"github.com/saluc28/petard/internal/writemodel"
	yaml "go.yaml.in/yaml/v3"
)

// WriteModelSchemaVersion is the version of the relationship-writes format this
// package reads. It is counted apart from the write-paths format of the OPA
// engine: the two files share a loader discipline, not a shape.
const WriteModelSchemaVersion = 1

// writeModelKind is the discriminator a relationship-writes file carries, so
// that a write-paths file, or a file of no model at all, fails with a sentence
// instead of decoding into an empty model.
const writeModelKind = "relationship-writes"

// Operation is a kind of write the write model lets a coalition make.
type Operation string

const (
	// Create writes a tuple that is not there.
	Create Operation = "create"

	// Touch writes a tuple whether or not it is there, the write that also sets
	// a new caveat context on one already written.
	Touch Operation = "touch"

	// Delete removes a tuple.
	Delete Operation = "delete"
)

// Filler says who supplies a caveat parameter or an expiration: the writer, who
// fixes it on the tuple, or the application, which brings it with the check.
// Written context wins at check time (SpiceDB copies it over the check's,
// internal/caveats/run.go:222-230 at v1.56.2), so a parameter the writer fills
// is the writer's for every check that follows.
type Filler string

const (
	// FillerWriter is the default: the writer fixes the value on the tuple.
	FillerWriter Filler = "writer"

	// FillerApplication means the value comes with the check, not the tuple.
	FillerApplication Filler = "application"

	// FillerNone is for an expiration no write carries.
	FillerNone Filler = "none"
)

// WriteModel is who may write which relationship tuple, and what objects may be
// created. It is the one input a schema cannot give: the schema says which
// tuples are well formed, the write model says which of them the coalition can
// bring about, and that is the difference between the access a deployment has
// now and the access it can be made to have.
type WriteModel struct {
	SchemaVersion int    `yaml:"schema_version"`
	Kind          string `yaml:"model"`

	// Writes are the rules that let the coalition write a tuple of a relation.
	Writes []*WriteRule `yaml:"writes"`

	// Creates are the rules that let the coalition make a new object, sign-up
	// among them, which is what puts accounts the coalition controls into play.
	Creates []*CreationRule `yaml:"creates"`
}

// WriteRule says who may write a relation, as what subject, and with which
// caveat and expiration. A relation with no rule is taken as not writable by
// the coalition (section 4.3 of the definitions), so the model is closed:
// leaving a rule out produces a missed raise, never an invented one.
type WriteRule struct {
	Resource   string      `yaml:"resource"`
	Relation   string      `yaml:"relation"`
	Operations []Operation `yaml:"operations"`

	// Gate is the permission the writer must hold on the resource, or anyone,
	// or a service no end user can drive.
	Gate Gate `yaml:"gate"`

	// Subject is what the writer may write as the subject of the tuple.
	Subject SubjectSpec `yaml:"subject"`

	// Wildcard says the writer may write the subject that stands for every
	// object of its type, which grants to the coalition as to anyone else.
	Wildcard bool `yaml:"wildcard"`

	// Caveats are the caveats the writer may attach, with who fills each
	// parameter. A write may set any declared parameter of the caveat
	// (internal/relationships/validation.go:248-262 at v1.56.2), so a parameter
	// left to the writer here is one the writer can fix.
	Caveats []CaveatWrite `yaml:"caveat"`

	// Expiration says who sets the expiration a tuple of this relation carries.
	Expiration Filler `yaml:"expiration"`

	Via        string `yaml:"via"`
	Note       string `yaml:"note"`
	Confidence string `yaml:"confidence"`

	// Intended marks a raise this rule allows by design, joining a public group
	// among them. A witness made only of intended rules is not a finding.
	Intended bool `yaml:"intended"`

	Position `yaml:"-"`
}

// CaveatWrite is a caveat a writer may attach to a tuple, and who fills each of
// its parameters. A parameter not named here is the writer's, because written
// context wins.
type CaveatWrite struct {
	Name       string            `yaml:"name"`
	Parameters map[string]Filler `yaml:"parameters"`
}

// Filler returns who fills a parameter, the writer when the caveat says
// nothing about it.
func (c CaveatWrite) Filler(parameter string) Filler {
	if f, ok := c.Parameters[parameter]; ok {
		return f
	}
	return FillerWriter
}

// CreationRule says the coalition may make a new object of a type, under a gate,
// optionally inside objects named in On, and that the creation writes a set of
// tuples. Sign-up is a creation rule on the user type gated anyone.
type CreationRule struct {
	Creates string `yaml:"creates"`

	// Gate is anyone, or a permission held on one of the On objects.
	Gate Gate `yaml:"gate"`

	// On are the objects the creation is made in, a folder for a document, each
	// with its own gate. It is empty for a creation that stands on its own,
	// sign-up among them.
	On []OnSpec `yaml:"on"`

	// Writes are the tuples the creation writes. A resource or subject of
	// CreatorPlaceholder, CreatedPlaceholder or the type of an On object stands
	// for the coalition writer, the object just created, or that On object.
	Writes []CreationWrite `yaml:"writes"`

	Via        string `yaml:"via"`
	Note       string `yaml:"note"`
	Confidence string `yaml:"confidence"`

	// Intended marks a creation a run should not report as a raise, a public
	// workspace anybody may open among them.
	Intended bool `yaml:"intended"`

	Position `yaml:"-"`
}

// OnSpec is one object a creation is made in, with the permission the creator
// must hold on it.
type OnSpec struct {
	Type string `yaml:"type"`
	Gate Gate   `yaml:"gate"`
}

// CreationWrite is one tuple a creation writes, with its resource and subject
// given as placeholders the closure fills with the created object, the creator
// and the On objects.
type CreationWrite struct {
	Resource string `yaml:"resource"`
	Relation string `yaml:"relation"`
	Subject  string `yaml:"subject"`
}

// The placeholders a creation write may name in place of a concrete object.
const (
	// CreatedPlaceholder stands for the object the creation just made.
	CreatedPlaceholder = "{created}"

	// CreatorPlaceholder stands for the coalition subject that made it.
	CreatorPlaceholder = "{creator}"
)

// Gate is who may make a write or a creation: a permission the writer must hold
// on an object, anyone, or a named service no end user can drive. A gate is a
// permission of the same schema, so the schema and the write model are one
// model and a gate is asked the way any permission is (section 4.5).
type Gate struct {
	// Anyone is a gate no permission guards: sign-up, a public share link.
	Anyone bool

	// Holds names a permission the writer must hold on the resource, empty when
	// the gate is Anyone or a service.
	Holds string

	// Service names a layer no end user can drive. A service gate is never held
	// by the coalition, so a write behind it is out of the coalition's reach.
	Service string
}

// UnmarshalYAML reads a gate written as the scalar anyone, or as a mapping with
// holds or service.
func (g *Gate) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		if node.Value != "anyone" {
			return fmt.Errorf("%w: line %d: a gate written as a word is anyone, got %q", writemodel.ErrInvalid, node.Line, node.Value)
		}
		*g = Gate{Anyone: true}
		return nil
	case yaml.MappingNode:
		if err := onlyKeys(node, "holds", "service"); err != nil {
			return err
		}
		var m struct {
			Holds   string `yaml:"holds"`
			Service string `yaml:"service"`
		}
		if err := node.Decode(&m); err != nil {
			return err
		}
		if (m.Holds == "") == (m.Service == "") {
			return fmt.Errorf("%w: line %d: a gate holds a permission or names a service, not both and not neither", writemodel.ErrInvalid, node.Line)
		}
		*g = Gate{Holds: m.Holds, Service: m.Service}
		return nil
	default:
		return fmt.Errorf("%w: line %d: a gate is anyone, {holds: ...} or {service: ...}", writemodel.ErrInvalid, node.Line)
	}
}

// SubjectSpec is what a writer may write as the subject of a tuple: itself, any
// object, one of a list of types or usersets, or any object holding a
// permission. A tuple whose subject the coalition cannot produce does not raise
// its own access, so the spec bounds the subjects the closure writes.
type SubjectSpec struct {
	// Self is the writer as the subject, the shape of adding oneself to a
	// relation.
	Self bool

	// Any is any object of a type the relation allows.
	Any bool

	// Types are the types or usersets the writer may name, user or group#member.
	Types []string

	// Holds names a permission the subject object must hold, empty otherwise.
	Holds string
}

// UnmarshalYAML reads a subject written as the scalar self or any, as a list of
// types or usersets, or as a mapping with holds.
func (s *SubjectSpec) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		switch node.Value {
		case "self":
			*s = SubjectSpec{Self: true}
		case "any":
			*s = SubjectSpec{Any: true}
		default:
			return fmt.Errorf("%w: line %d: a subject written as a word is self or any, got %q", writemodel.ErrInvalid, node.Line, node.Value)
		}
		return nil
	case yaml.SequenceNode:
		types := make([]string, 0, len(node.Content))
		for _, element := range node.Content {
			if element.Kind != yaml.ScalarNode {
				return fmt.Errorf("%w: line %d: a subject list holds types or usersets, and this element is not one", writemodel.ErrInvalid, element.Line)
			}
			types = append(types, element.Value)
		}
		*s = SubjectSpec{Types: types}
		return nil
	case yaml.MappingNode:
		if err := onlyKeys(node, "holds"); err != nil {
			return err
		}
		var m struct {
			Holds string `yaml:"holds"`
		}
		if err := node.Decode(&m); err != nil {
			return err
		}
		if m.Holds == "" {
			return fmt.Errorf("%w: line %d: a subject mapping names the permission it holds", writemodel.ErrInvalid, node.Line)
		}
		*s = SubjectSpec{Holds: m.Holds}
		return nil
	default:
		return fmt.Errorf("%w: line %d: a subject is self, any, a list of types, or {holds: ...}", writemodel.ErrInvalid, node.Line)
	}
}

// LoadWriteModel reads a relationship-writes write model from a YAML file.
func LoadWriteModel(path string) (*WriteModel, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("zanzibar: reading %s: %w", path, err)
	}
	m, err := ParseWriteModel(content)
	if err != nil {
		return nil, fmt.Errorf("zanzibar: parsing %s: %w", path, err)
	}
	return m, nil
}

// ParseWriteModel reads a relationship-writes write model from its bytes. It is
// the part of LoadWriteModel that does not touch the disk, so a test can hold
// the model inline.
func ParseWriteModel(content []byte) (*WriteModel, error) {
	var m WriteModel
	if err := writemodel.DecodeStrict(content, &m); err != nil {
		return nil, err
	}
	if m.Kind != writeModelKind {
		return nil, fmt.Errorf("%w: declares model %q, want %q", writemodel.ErrNotAWriteModel, m.Kind, writeModelKind)
	}
	if m.SchemaVersion != WriteModelSchemaVersion {
		return nil, fmt.Errorf("%w: version %d, this reads %d", writemodel.ErrSchemaVersion, m.SchemaVersion, WriteModelSchemaVersion)
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// validate checks what the format calls mandatory, so that a rule the engine
// cannot act on fails with a sentence rather than passing as a rule that writes
// nothing.
func (m *WriteModel) validate() error {
	for _, w := range m.Writes {
		if w.Resource == "" || w.Relation == "" {
			return fmt.Errorf("%w: a write rule names its resource and its relation", writemodel.ErrInvalid)
		}
		if len(w.Operations) == 0 {
			return fmt.Errorf("%w: %s#%s has no operations, and a rule that writes nothing is not a rule", writemodel.ErrInvalid, w.Resource, w.Relation)
		}
		for _, op := range w.Operations {
			if op != Create && op != Touch && op != Delete {
				return fmt.Errorf("%w: %s#%s has operation %q, want create, touch or delete", writemodel.ErrInvalid, w.Resource, w.Relation, op)
			}
		}
		if err := w.Gate.validate(fmt.Sprintf("%s#%s", w.Resource, w.Relation)); err != nil {
			return err
		}
		if err := w.Expiration.validate(fmt.Sprintf("%s#%s expiration", w.Resource, w.Relation)); err != nil {
			return err
		}
	}
	for _, c := range m.Creates {
		if c.Creates == "" {
			return fmt.Errorf("%w: a creation rule names the type it creates", writemodel.ErrInvalid)
		}
		if err := c.Gate.validate(fmt.Sprintf("creation of %s", c.Creates)); err != nil {
			return err
		}
	}
	return nil
}

// validate rejects a gate that is neither anyone, a held permission nor a
// service, which UnmarshalYAML already enforces for a gate that was present. It
// catches the gate a rule left out, decoded as the zero Gate.
func (g Gate) validate(where string) error {
	if !g.Anyone && g.Holds == "" && g.Service == "" {
		return fmt.Errorf("%w: %s has no gate, and a write nobody is allowed to make is simply not declared", writemodel.ErrInvalid, where)
	}
	return nil
}

// validate rejects an expiration filler that is not one of the three words. An
// empty filler is allowed and read as none by the closure.
func (f Filler) validate(where string) error {
	switch f {
	case "", FillerWriter, FillerApplication, FillerNone:
		return nil
	}
	return fmt.Errorf("%w: %s is %q, want writer, application or none", writemodel.ErrInvalid, where, string(f))
}

// onlyKeys reports an error when a mapping node carries a key that is not among
// the allowed ones, the strictness node.Decode cannot give on its own: a key
// spelled wrong is a fact that goes missing, and a gate or subject read as
// empty would be refused with a less telling message than this one.
func onlyKeys(node *yaml.Node, allowed ...string) error {
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i].Value
		if !slices.Contains(allowed, key) {
			return fmt.Errorf("%w: line %d: unknown key %q", writemodel.ErrInvalid, node.Content[i].Line, key)
		}
	}
	return nil
}
