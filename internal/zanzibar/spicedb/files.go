package spicedb

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/authzed/spicedb/pkg/tuple"
	yaml "go.yaml.in/yaml/v3"

	"github.com/saluc28/petard/internal/zanzibar"
)

// ErrValidationFile is returned for a validation file that does not hold
// together: a schemaFile that cannot be read or leads out of the directory
// analyzed, a schema given both inline and by file, or a block of the wrong
// shape.
var ErrValidationFile = errors.New("spicedb: invalid validation file")

// File is one SpiceDB input found on disk: a schema file, or a validation file
// that holds a schema or names one, with the relationships written against it.
type File struct {
	// Path is where the file was found.
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
// Directories whose name starts with a dot are not entered.
//
// Nothing outside the paths is read. A validation file names its schema with a
// path of its own choosing, and a repository is not always somebody's own; the
// files are opened through an os.Root, so a schemaFile or a link that leads out
// of the directory is refused rather than followed.
func Find(paths []string) ([]*File, error) {
	var found []*File
	for _, p := range paths {
		// What is read under p goes through the os.Root of findUnder.
		info, err := os.Stat(p) //nolint:gosec // G703: p is a path the user named on the command line
		if err != nil {
			// A URL or a bundle archive is not a SpiceDB input, and the
			// command that was handed it says what it is.
			continue
		}
		dir, only := p, ""
		if !info.IsDir() {
			dir, only = filepath.Dir(p), filepath.Base(p)
		}
		files, err := findUnder(dir, only)
		if err != nil {
			return nil, err
		}
		found = append(found, files...)
	}
	sort.Slice(found, func(i, j int) bool { return found[i].Path < found[j].Path })
	return found, nil
}

// findUnder reads the inputs under dir, or the one file named only in it.
func findUnder(dir, only string) (_ []*File, err error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("spicedb: %w", err)
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	r := reader{root: root, dir: dir}

	if only != "" {
		f, err := r.read(only)
		if err != nil || f == nil {
			return nil, err
		}
		return []*File{f}, nil
	}

	var found []*File
	err = fs.WalkDir(root.FS(), ".", func(rel string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if rel != "." && strings.HasPrefix(d.Name(), ".") {
				return fs.SkipDir
			}
			return nil
		}
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

// reader reads the files under one directory and nowhere else. Paths given to
// it are relative to the directory, with forward slashes.
type reader struct {
	root *os.Root
	dir  string
}

// display is the path a report prints for a file of the directory.
func (r reader) display(rel string) string {
	return filepath.Join(r.dir, filepath.FromSlash(rel))
}

func (r reader) readFile(rel string) ([]byte, error) {
	return r.root.ReadFile(filepath.FromSlash(rel))
}

// imports is where a schema at rel reads the files it imports from: its own
// directory, inside the root.
func (r reader) imports(rel string) fs.FS {
	sub, err := fs.Sub(r.root.FS(), path.Dir(rel))
	if err != nil {
		return nil
	}
	return sub
}

// read returns the input a file holds, or nil when it holds none.
func (r reader) read(rel string) (*File, error) {
	rel = filepath.ToSlash(rel)
	switch strings.ToLower(path.Ext(rel)) {
	case ".zed":
		name := r.display(rel)
		text, err := r.readFile(rel)
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
	name := r.display(rel)
	raw, err := r.readFile(rel)
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
		schemaRel, err := r.schemaFile(rel, v.SchemaFile)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: schemaFile %s: %w", ErrValidationFile, name, v.SchemaFile, err)
		}
		f.SchemaPath = r.display(schemaRel)
		text, err := r.readFile(schemaRel)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: schemaFile %s: %w", ErrValidationFile, name, v.SchemaFile, err)
		}
		if f.Schema, err = Compile(f.SchemaPath, r.imports(schemaRel), 1, string(text)); err != nil {
			return nil, err
		}
	} else {
		f.SchemaPath = name
		if f.Schema, err = Compile(name, r.imports(rel), contentLine(v.Schema), v.Schema.Value); err != nil {
			return nil, err
		}
	}

	if v.Relationships.Kind != 0 {
		if v.Relationships.Kind != yaml.ScalarNode {
			return nil, fmt.Errorf("%w: %s:%d: relationships is not a string", ErrValidationFile, name, v.Relationships.Line)
		}
		f.Relationships, err = ParseRelationships(name, contentLine(v.Relationships), v.Relationships.Value)
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

// schemaFile resolves the schemaFile of the validation file at rel against the
// directory of the validation file, as SpiceDB does
// (pkg/validationfile/loader.go:153-158 at v1.56.2). A path that is absolute,
// or that climbs out of the directory analyzed, is refused here with a reason;
// the os.Root behind every read refuses the links that would.
func (r reader) schemaFile(rel, named string) (string, error) {
	slashed := filepath.ToSlash(named)
	if path.IsAbs(slashed) || filepath.IsAbs(named) || filepath.VolumeName(named) != "" {
		return "", errors.New("is absolute: it has to name a file under the directory analyzed")
	}
	joined := path.Join(path.Dir(rel), slashed)
	if joined == ".." || strings.HasPrefix(joined, "../") {
		return "", fmt.Errorf("leads out of %s, the directory analyzed", r.dir)
	}
	return joined, nil
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

// contentLine is the line of the file the text of a scalar starts on: the line
// after the indicator for a block scalar, schema: |, and the line of the value
// otherwise.
func contentLine(node yaml.Node) int {
	if node.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0 {
		return node.Line + 1
	}
	return node.Line
}
