package spicedb

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/authzed/spicedb/pkg/tuple"
	yaml "go.yaml.in/yaml/v3"

	"github.com/saluc28/petard/internal/zanzibar"
	"github.com/saluc28/petard/internal/zanzibar/schemafiles"
)

// ErrValidationFile is returned for a validation file that does not hold
// together: a schemaFile that cannot be read or leads out of the directory
// analyzed, a schema given both inline and by file, or a block of the wrong
// shape.
var ErrValidationFile = errors.New("spicedb: invalid validation file")

// File is one SpiceDB input found on disk: a schema file, or a validation file
// that holds a schema or names one, with the relationships written against it.
type File struct {
	// Path is where the file was found, written with forward slashes on every
	// system, as the files of a policy are.
	Path string

	// SchemaPath is the file the schema was read from: Path itself, or the
	// schemaFile a validation file names.
	SchemaPath string

	Schema *Schema

	// Validation is true for a validation file, the format zed validate reads
	// (pkg/validationfile/fileformat.go:21-47 at v1.56.2).
	Validation bool

	Relationships []zanzibar.Relationship

	// Assertions are the checks the file asserts, and ExpectedRelations
	// counts the relations whose subjects it lists.
	Assertions        []zanzibar.Assertion
	ExpectedRelations int
}

// Sample is what the file holds about its schema, for the patterns of the
// engine to read: the relationships, the checks it asserts, and the caveats
// evaluated the way SpiceDB evaluates them. now is when expirations are read.
func (f *File) Sample(now time.Time) zanzibar.Sample {
	return zanzibar.Sample{
		Model:         f.Schema.Model,
		Relationships: f.Relationships,
		Assertions:    f.Assertions,
		Caveats:       f.Schema,
		Now:           now,
	}
}

// validationKeys are the top level keys of a validation file
// (pkg/validationfile/fileformat.go:23-46 at v1.56.2, without the two that
// belong to the format before the schema language). A YAML file whose keys
// are not among them is something else, and is left alone.
var validationKeys = map[string]bool{
	"schema":        true,
	"schemaFile":    true,
	"relationships": true,
	"assertions":    true,
	"validation":    true,
}

// Find reads the SpiceDB inputs under paths: files ending in .zed, and YAML
// files shaped like a validation file. Anything else is skipped, so that a
// directory holding a policy bundle as well is read for what it holds of each.
// Directories whose name starts with a dot are not entered, and nothing outside
// the paths is read (package schemafiles).
func Find(paths []string) ([]*File, error) {
	var found []*File
	err := schemafiles.Each(paths, func(d *schemafiles.Dir, only string) error {
		files, err := findUnder(d, only)
		found = append(found, files...)
		return err
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(found, func(i, j int) bool { return found[i].Path < found[j].Path })
	return found, nil
}

// findUnder reads the inputs under a directory, or the one file named only in it.
func findUnder(d *schemafiles.Dir, only string) ([]*File, error) {
	r := reader{d}
	if only != "" {
		f, err := r.read(only)
		if err != nil || f == nil {
			return nil, err
		}
		return []*File{f}, nil
	}

	var found []*File
	err := d.Walk(func(rel string) error {
		f, err := r.read(rel)
		if err != nil {
			return err
		}
		if f != nil {
			found = append(found, f)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return found, nil
}

// reader reads the files under one directory and nowhere else.
type reader struct {
	*schemafiles.Dir
}

// imports is where a schema at rel reads the files it imports from: its own
// directory, inside the root.
func (r reader) imports(rel string) fs.FS {
	return r.Sub(rel)
}

// read returns the input a file holds, or nil when it holds none.
func (r reader) read(rel string) (*File, error) {
	rel = filepath.ToSlash(rel)
	switch strings.ToLower(path.Ext(rel)) {
	case ".zed":
		name := r.Display(rel)
		text, err := r.Read(rel)
		if err != nil {
			return nil, fmt.Errorf("spicedb: reading %s: %w", name, err)
		}
		schema, err := Compile(name, r.imports(rel), 1, string(text))
		if err != nil {
			return nil, err
		}
		return &File{Path: name, SchemaPath: name, Schema: schema}, nil
	case ".yaml", ".yml":
		return r.readValidation(rel)
	}
	return nil, nil
}

// validationFile is the part of a validation file petard reads.
type validationFile struct {
	Schema        yaml.Node `yaml:"schema"`
	SchemaFile    string    `yaml:"schemaFile"`
	Relationships yaml.Node `yaml:"relationships"`
	Assertions    struct {
		True     []yaml.Node `yaml:"assertTrue"`
		False    []yaml.Node `yaml:"assertFalse"`
		Caveated []yaml.Node `yaml:"assertCaveated"`
	} `yaml:"assertions"`
	Validation map[string]yaml.Node `yaml:"validation"`
}

func (r reader) readValidation(rel string) (*File, error) {
	name := r.Display(rel)
	raw, err := r.Read(rel)
	if err != nil {
		return nil, fmt.Errorf("spicedb: reading %s: %w", name, err)
	}
	if !looksLikeValidation(raw) {
		return nil, nil
	}

	var v validationFile
	if err := yaml.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrValidationFile, name, err)
	}
	if v.SchemaFile != "" && v.Schema.Value != "" {
		// pkg/validationfile/loader.go:124-126 at v1.56.2 refuses it too,
		// rather than choosing one.
		return nil, fmt.Errorf("%w: %s: holds both schema and schemaFile, and only one can be given", ErrValidationFile, name)
	}

	f := &File{
		Path:              name,
		Validation:        true,
		ExpectedRelations: len(v.Validation),
	}
	for _, block := range []struct {
		nodes []yaml.Node
		level zanzibar.Level
	}{
		{nodes: v.Assertions.True, level: zanzibar.Yes},
		{nodes: v.Assertions.False, level: zanzibar.No},
		{nodes: v.Assertions.Caveated, level: zanzibar.Conditional},
	} {
		for _, node := range block.nodes {
			a, err := parseAssertion(name, node, block.level)
			if err != nil {
				return nil, err
			}
			f.Assertions = append(f.Assertions, a)
		}
	}

	if v.SchemaFile != "" {
		// As SpiceDB resolves it (pkg/validationfile/loader.go:153-158 at v1.56.2).
		schemaRel, err := r.Named(rel, v.SchemaFile)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: schemaFile %s: %w", ErrValidationFile, name, v.SchemaFile, err)
		}
		f.SchemaPath = r.Display(schemaRel)
		text, err := r.Read(schemaRel)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: schemaFile %s: %w", ErrValidationFile, name, v.SchemaFile, err)
		}
		if f.Schema, err = Compile(f.SchemaPath, r.imports(schemaRel), 1, string(text)); err != nil {
			return nil, err
		}
	} else {
		f.SchemaPath = name
		if f.Schema, err = Compile(name, r.imports(rel), schemafiles.ContentLine(v.Schema), v.Schema.Value); err != nil {
			return nil, err
		}
	}

	if v.Relationships.Kind != 0 {
		if v.Relationships.Kind != yaml.ScalarNode {
			return nil, fmt.Errorf("%w: %s:%d: relationships is not a string", ErrValidationFile, name, v.Relationships.Line)
		}
		f.Relationships, err = ParseRelationships(name, schemafiles.ContentLine(v.Relationships), v.Relationships.Value)
		if err != nil {
			return nil, err
		}
	}
	return f, nil
}

// parseAssertion reads one assertion the way SpiceDB does
// (pkg/validationfile/blocks/assertions.go:82-128 at v1.56.2): a check in the
// notation of a relationship, then, after " with ", the context it supplies as
// a JSON object.
func parseAssertion(file string, node yaml.Node, level zanzibar.Level) (zanzibar.Assertion, error) {
	pos := zanzibar.Position{File: file, Line: node.Line, Column: node.Column}
	if node.Kind != yaml.ScalarNode {
		return zanzibar.Assertion{}, fmt.Errorf("%w: %s: an assertion is not a string", ErrValidationFile, pos)
	}
	check, context, withContext := strings.Cut(strings.TrimSpace(node.Value), " with ")
	rel, err := tuple.Parse(strings.TrimSpace(check))
	if err != nil {
		return zanzibar.Assertion{}, fmt.Errorf("%w: %s: assertion %q: %w", ErrValidationFile, pos, node.Value, err)
	}
	a := zanzibar.Assertion{
		Resource: zanzibar.Object{Type: rel.Resource.ObjectType, ID: rel.Resource.ObjectID},
		Name:     rel.Resource.Relation,
		Subject:  lowerSubject(rel.Subject),
		Level:    level,
		Position: pos,
	}
	if withContext {
		if err := json.Unmarshal([]byte(context), &a.Context); err != nil {
			return zanzibar.Assertion{}, fmt.Errorf("%w: %s: context of assertion %q: %w", ErrValidationFile, pos, node.Value, err)
		}
	}
	return a, nil
}

// looksLikeValidation says whether a YAML document is a mapping whose keys
// are all keys of a validation file and that holds or names a schema.
func looksLikeValidation(raw []byte) bool {
	var top map[string]yaml.Node
	if err := yaml.NewDecoder(bytes.NewReader(raw)).Decode(&top); err != nil {
		return false
	}
	if len(top) == 0 {
		return false
	}
	for key := range top {
		if !validationKeys[key] {
			return false
		}
	}
	schema, inline := top["schema"]
	_, named := top["schemaFile"]
	return named || (inline && schema.Kind == yaml.ScalarNode)
}
