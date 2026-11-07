// Package identity reads the identity map: which node another collector ingested
// a subject of a Zanzibar type is, so that an export can join the principals of
// an application to the identities of the directory its users sign in with.
//
// The join is exact by construction. An entry names a kind of node in BloodHound
// and one of its properties, and a subject is linked to the node whose property
// equals the subject's id, which BloodHound resolves when the payload is ingested.
// A subject with no such node, or with more than one, has no link, and nothing
// here guesses one from a name that looks alike.
//
// A map is a YAML file beside the schema, the way a write model is:
//
//	schema_version: 1
//	model: identities
//	types:
//	  - type: user        # the type of the subject in the schema
//	    kind: User        # the kind of the node it is in BloodHound
//	    property: objectid # the property of that node that equals the subject's id
package identity

import (
	"errors"
	"fmt"
	"os"
	"slices"

	yaml "go.yaml.in/yaml/v3"

	"github.com/saluc28/petard/internal/graph"
	"github.com/saluc28/petard/internal/writemodel"
	"github.com/saluc28/petard/internal/zanzibar"
)

// SchemaVersion is the version of the file format this package reads.
const SchemaVersion = 1

// modelKind is what a map declares in its model field.
const modelKind = "identities"

var (
	// ErrNotAMap is returned for a YAML file that is not an identity map, a
	// write model or a validation file sitting beside a schema among them.
	ErrNotAMap = errors.New("identity: not an identity map")

	// ErrInvalid is returned for a map that does not hold together.
	ErrInvalid = errors.New("identity: invalid map")
)

// Map is an identity map: for each type it names, which node of BloodHound a
// subject of that type is.
type Map struct {
	SchemaVersion int     `yaml:"schema_version"`
	Kind          string  `yaml:"model"`
	Types         []Entry `yaml:"types"`

	// Path is the file the map was read from, which a link names as the
	// declaration it rests on.
	Path string `yaml:"-"`
}

// Entry says which node a subject of one type is: the node of kind Kind whose
// property Property equals the subject's id.
type Entry struct {
	Type     string `yaml:"type"`
	Kind     string `yaml:"kind"`
	Property string `yaml:"property"`
}

// Load reads a map from path.
func Load(path string) (*Map, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("identity: reading %s: %w", path, err)
	}
	m, err := Parse(content)
	if err != nil {
		return nil, fmt.Errorf("identity: parsing %s: %w", path, err)
	}
	m.Path = path
	return m, nil
}

// Parse reads a map from its bytes. The kind is read first, without the strict
// decoding the rest of the file gets, so that a YAML of another shape is turned
// away with ErrNotAMap rather than failing on a field this format does not have.
func Parse(content []byte) (*Map, error) {
	var head struct {
		Kind string `yaml:"model"`
	}
	if err := yaml.Unmarshal(content, &head); err != nil {
		return nil, err
	}
	if head.Kind != modelKind {
		return nil, fmt.Errorf("%w: declares model %q, want %q", ErrNotAMap, head.Kind, modelKind)
	}
	var m Map
	if err := writemodel.DecodeStrict(content, &m); err != nil {
		return nil, err
	}
	if m.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("%w: version %d, this reads %d", ErrInvalid, m.SchemaVersion, SchemaVersion)
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// validate checks that every entry names a type, a kind and a property, and that
// no type is named twice, since two entries for one type would make a subject two
// different nodes.
func (m *Map) validate() error {
	if len(m.Types) == 0 {
		return fmt.Errorf("%w: it names no type", ErrInvalid)
	}
	var seen []string
	for i, e := range m.Types {
		if e.Type == "" || e.Kind == "" || e.Property == "" {
			return fmt.Errorf("%w: entry %d names its type, kind and property, and has %+v", ErrInvalid, i, e)
		}
		if slices.Contains(seen, e.Type) {
			return fmt.Errorf("%w: the type %s is named twice", ErrInvalid, e.Type)
		}
		seen = append(seen, e.Type)
	}
	return nil
}

// entry is the entry for a type, if the map names it.
func (m *Map) entry(typ string) (Entry, bool) {
	for _, e := range m.Types {
		if e.Type == typ {
			return e, true
		}
	}
	return Entry{}, false
}

// Link is one subject joined to the node it is: the principal Petard drew for the
// subject, the entry of the map that names the node, the subject's id the node's
// property has to equal, and the map that says so.
type Link struct {
	Principal string
	Entry     Entry
	ID        string
	Map       string
}

// Source is a set of relationships and the map that applies to them: the
// relationships of one schema and the map beside it.
type Source struct {
	Relationships []zanzibar.Relationship
	Map           *Map
}

// Links is the subjects of the relationships that are principals of g, of a type
// their map names, each with the node it is, in the order the principals were
// drawn. A subject is linked once however many relationships name it.
//
// Only a subject the relationships name directly is linked: an attacker the
// analysis supposes, or an object a starting position generated, stands for any
// account and is nobody's identity. A wildcard is every subject of its type and
// a userset the members of an object, and neither is one identity either.
//
// The same principal can come from two schemas, since Petard draws one node for
// an id. Two maps that make it two different nodes are an error rather than a
// choice between them.
func Links(g *graph.Graph, sources []Source) ([]Link, error) {
	found := map[string]Link{}
	for _, src := range sources {
		if src.Map == nil {
			continue
		}
		for _, r := range src.Relationships {
			// A userset names the members of an object rather than an identity,
			// and the principals Petard draws for the subjects of a store are the
			// direct ones.
			if r.Subject.Relation != "" || r.Subject.ID == zanzibar.WildcardID {
				continue
			}
			subject := r.Subject.Object
			e, ok := src.Map.entry(subject.Type)
			if !ok {
				continue
			}
			node, ok := g.Node(subject.String())
			if !ok || node.Kind != graph.NodeKindPrincipal {
				continue
			}
			// The relationships of a schema read without a validation file are
			// the positions generated from it, whose subjects are marked as
			// supposed.
			if supposed, _ := node.Properties[graph.PropHypothetical].(bool); supposed {
				continue
			}
			link := Link{Principal: node.ID, Entry: e, ID: subject.ID, Map: src.Map.Path}
			if met, ok := found[node.ID]; ok {
				if met.Entry != link.Entry {
					return nil, fmt.Errorf("%w: %s is a %s by %s in %s and a %s by %s in %s", ErrInvalid,
						node.ID, met.Entry.Kind, met.Entry.Property, met.Map, e.Kind, e.Property, src.Map.Path)
				}
				continue
			}
			found[node.ID] = link
		}
	}

	var out []Link
	for _, node := range g.Nodes() {
		if link, ok := found[node.ID]; ok {
			out = append(out, link)
		}
	}
	return out, nil
}
