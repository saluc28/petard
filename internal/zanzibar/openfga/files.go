package openfga

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	yaml "go.yaml.in/yaml/v3"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/saluc28/petard/internal/zanzibar"
	"github.com/saluc28/petard/internal/zanzibar/schemafiles"
)

// ErrStoreFile is returned for a store file that does not hold together: no model,
// a file it names that cannot be read or leads out of the directory analyzed, a
// tuple the model does not admit, or a check of the wrong shape.
var ErrStoreFile = errors.New("openfga: invalid store file")

// modFile is the name of the file that lists the modules of a modular model.
const modFile = "fga.mod"

// File is one OpenFGA input found on disk: a model, or a store file that holds or
// names one with the tuples and the tests written against it, the format fga model
// test reads (internal/storetest/storedata.go:45-89 at openfga/cli v0.8.2).
type File struct {
	// Path is where the file was found, written with forward slashes on every
	// system, as the files of a policy are.
	Path string

	// SchemaPath is the file the model was read from: Path itself, or the
	// model_file a store file names.
	SchemaPath string

	Schema *Schema

	// Store is true for a store file.
	Store bool

	// Test names the test of a store file this is read with, when the test brings
	// tuples of its own: fga model test sends them with that test's checks alone
	// (internal/storetest/localtest.go:237-265 at openfga/cli v0.8.2), so they make
	// a state of their own. It is empty for what the whole file shares.
	Test string

	Relationships []zanzibar.Relationship
	Assertions    []zanzibar.Assertion
}

// Find reads the OpenFGA inputs under paths: models in the DSL (.fga), modular
// models (fga.mod, with the modules it lists), models in JSON, and store files.
// Anything else is skipped, so that a directory holding a policy bundle as well is
// read for what it holds of each. Directories whose name starts with a dot are not
// entered, and nothing outside the paths is read (package schemafiles).
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
	sort.SliceStable(found, func(i, j int) bool {
		if found[i].Path != found[j].Path {
			return found[i].Path < found[j].Path
		}
		return found[i].Test < found[j].Test
	})
	return found, nil
}

// findUnder reads the inputs under a directory, or the one file named only in it.
// The fga.mod files come first, because the modules they list are not models of
// their own.
func findUnder(d *schemafiles.Dir, only string) ([]*File, error) {
	r := reader{d}
	if only != "" {
		return r.read(only)
	}

	var rels []string
	if err := d.Walk(func(rel string) error {
		rels = append(rels, rel)
		return nil
	}); err != nil {
		return nil, err
	}

	var found []*File
	listed := map[string]bool{}
	for _, rel := range rels {
		if path.Base(rel) != modFile {
			continue
		}
		schema, modules, err := r.compileMod(rel)
		if err != nil {
			return nil, err
		}
		name := r.Display(rel)
		found = append(found, &File{Path: name, SchemaPath: name, Schema: schema})
		for _, module := range modules {
			listed[module] = true
		}
	}
	for _, rel := range rels {
		if path.Base(rel) == modFile || listed[rel] {
			continue
		}
		files, err := r.read(rel)
		if err != nil {
			return nil, err
		}
		found = append(found, files...)
	}
	return found, nil
}

// reader reads the files under one directory and nowhere else.
type reader struct {
	*schemafiles.Dir
}

// read returns the inputs a file holds, none when it holds none.
func (r reader) read(rel string) ([]*File, error) {
	rel = filepath.ToSlash(rel)
	name := r.Display(rel)
	switch {
	case path.Base(rel) == modFile, strings.HasSuffix(strings.ToLower(rel), ".fga"):
		schema, err := r.compileModel(rel)
		if err != nil {
			return nil, err
		}
		return []*File{{Path: name, SchemaPath: name, Schema: schema}}, nil
	case strings.ToLower(path.Ext(rel)) == ".json":
		raw, err := r.Read(rel)
		if err != nil {
			return nil, fmt.Errorf("openfga: reading %s: %w", name, err)
		}
		if !looksLikeJSONModel(raw) {
			return nil, nil
		}
		schema, err := CompileJSON(name, string(raw))
		if err != nil {
			return nil, err
		}
		return []*File{{Path: name, SchemaPath: name, Schema: schema}}, nil
	case isYAML(rel):
		return r.readStore(rel)
	}
	return nil, nil
}

// compileModel compiles the model in a file, told apart the way fga tells it apart
// (internal/authorizationmodel/read-from-input.go:63-71 at openfga/cli v0.8.2).
func (r reader) compileModel(rel string) (*Schema, error) {
	if strings.HasSuffix(rel, modFile) {
		schema, _, err := r.compileMod(rel)
		return schema, err
	}
	name := r.Display(rel)
	raw, err := r.Read(rel)
	if err != nil {
		return nil, fmt.Errorf("openfga: reading %s: %w", name, err)
	}
	if strings.HasSuffix(rel, "json") {
		return CompileJSON(name, string(raw))
	}
	if declaresModule(string(raw)) {
		return nil, r.moduleGuidance(name)
	}
	return Compile(name, string(raw))
}

// moduleGuidance is the error for a .fga that opens as a module with no fga.mod to
// list it. petard does not combine modules on its own, because a directory may hold
// models that are not one, so instead of auto merging it names the two ways out: the
// assembled JSON model it reads directly, and an fga.mod listing the modules, written
// with the module files found under the path so it can be pasted in rather than
// recalled. The guidance keeps the "no fga.mod" wording so a scripted check still
// recognizes the case.
func (r reader) moduleGuidance(name string) error {
	var modules []string
	_ = r.Walk(func(rel string) error {
		if !strings.HasSuffix(strings.ToLower(rel), ".fga") {
			return nil
		}
		if raw, err := r.Read(rel); err == nil && declaresModule(string(raw)) {
			// The relative path, not the display name, since an fga.mod lists its
			// modules relative to itself, and this block is written to be pasted in.
			modules = append(modules, filepath.ToSlash(rel))
		}
		return nil
	})
	slices.Sort(modules)
	if len(modules) == 0 {
		modules = []string{name}
	}
	var contents strings.Builder
	for _, module := range modules {
		fmt.Fprintf(&contents, "    - %s\n", module)
	}
	return fmt.Errorf("%w: %s opens as a module of a modular model, and no fga.mod under the path lists it. "+
		"petard does not combine modules on its own, since a directory may hold models that are not one. "+
		"Either give petard the model assembled into one JSON model, which it reads directly (for example with "+
		"fga model transform, or by having the application dump the model it builds), or add an fga.mod beside the "+
		"modules that lists them:\n  schema: '1.2'\n  contents:\n%s",
		ErrModel, name, contents.String())
}

// compileMod compiles the modular model an fga.mod lists, and returns the modules
// it read. A module it names is held to the directory analyzed, as anything else a
// file names is.
func (r reader) compileMod(rel string) (*Schema, []string, error) {
	name := r.Display(rel)
	raw, err := r.Read(rel)
	if err != nil {
		return nil, nil, fmt.Errorf("openfga: reading %s: %w", name, err)
	}
	version, names, err := parseMod(name, string(raw))
	if err != nil {
		return nil, nil, err
	}
	modules := make([]Module, 0, len(names))
	rels := make([]string, 0, len(names))
	for _, named := range names {
		moduleRel, err := r.Named(rel, named)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %s: module %s: %w", ErrModel, name, named, err)
		}
		text, err := r.Read(moduleRel)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %s: module %s: %w", ErrModel, name, named, err)
		}
		modules = append(modules, Module{File: r.Display(moduleRel), Text: string(text)})
		rels = append(rels, moduleRel)
	}
	schema, err := CompileModules(name, version, modules)
	return schema, rels, err
}

// declaresModule says whether DSL text opens as a module rather than a model.
func declaresModule(text string) bool {
	for line := range strings.Lines(text) {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		return strings.HasPrefix(trimmed, "module ")
	}
	return false
}

// looksLikeJSONModel says whether a JSON document is a mapping that holds a model.
// Any other JSON is something else, and is left alone.
func looksLikeJSONModel(raw []byte) bool {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return false
	}
	_, version := top["schema_version"]
	_, types := top["type_definitions"]
	return version && types
}

func isYAML(rel string) bool {
	ext := strings.ToLower(path.Ext(rel))
	return ext == ".yaml" || ext == ".yml"
}

// storeKeys are the top level keys of a store file
// (internal/storetest/storedata.go:82-89 at openfga/cli v0.8.2).
var storeKeys = []string{"name", "model", "model_file", "tuples", "tuple_file", "tuple_files", "tests"}

// dslHeader finds the header a model in the DSL opens with.
var dslHeader = regexp.MustCompile(`(?m)^\s*model\s*$`)

// looksLikeStore says whether a YAML document is a store file. One named .fga.yaml
// says so, and any other has to show it: every key among those of a store file, and
// a model that reads as one. Many YAML files have a name and a model, and a file of
// somebody else's that happens to is left alone.
func looksLikeStore(rel string, raw []byte) bool {
	lower := strings.ToLower(rel)
	if strings.HasSuffix(lower, ".fga.yaml") || strings.HasSuffix(lower, ".fga.yml") {
		return true
	}
	var top map[string]yaml.Node
	if err := yaml.NewDecoder(bytes.NewReader(raw)).Decode(&top); err != nil || len(top) == 0 {
		return false
	}
	for key := range top {
		if !slices.Contains(storeKeys, key) {
			return false
		}
	}
	if model, ok := top["model"]; ok && model.Kind == yaml.ScalarNode && dslHeader.MatchString(model.Value) {
		return true
	}
	file := strings.ToLower(top["model_file"].Value)
	return strings.HasSuffix(file, ".fga") || strings.HasSuffix(file, modFile) || strings.HasSuffix(file, ".json")
}

// storeFile is the part of a store file petard reads. The list_objects and
// list_users tests say nothing a check does not.
type storeFile struct {
	Model      yaml.Node   `yaml:"model"`
	ModelFile  string      `yaml:"model_file"`
	Tuples     []yaml.Node `yaml:"tuples"`
	TupleFile  string      `yaml:"tuple_file"`
	TupleFiles []string    `yaml:"tuple_files"`
	Tests      []storeTest `yaml:"tests"`
}

type storeTest struct {
	Name      string      `yaml:"name"`
	Tuples    []yaml.Node `yaml:"tuples"`
	TupleFile string      `yaml:"tuple_file"`
	Check     []yaml.Node `yaml:"check"`
}

type storeCheck struct {
	User       string          `yaml:"user"`
	Users      []string        `yaml:"users"`
	Object     string          `yaml:"object"`
	Objects    []string        `yaml:"objects"`
	Context    map[string]any  `yaml:"context"`
	Assertions map[string]bool `yaml:"assertions"`
}

type storeTuple struct {
	User      string          `yaml:"user" json:"user"`
	Relation  string          `yaml:"relation" json:"relation"`
	Object    string          `yaml:"object" json:"object"`
	Condition *storeCondition `yaml:"condition" json:"condition"`
}

type storeCondition struct {
	Name    string         `yaml:"name" json:"name"`
	Context map[string]any `yaml:"context" json:"context"`
}

// readStore reads a store file, into one File for what the file shares and one more
// for each test that brings tuples of its own.
func (r reader) readStore(rel string) ([]*File, error) {
	name := r.Display(rel)
	raw, err := r.Read(rel)
	if err != nil {
		return nil, fmt.Errorf("openfga: reading %s: %w", name, err)
	}
	if !looksLikeStore(rel, raw) {
		return nil, nil
	}
	var store storeFile
	if err := yaml.Unmarshal(raw, &store); err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrStoreFile, name, err)
	}

	schema, schemaPath, err := r.storeModel(rel, store)
	if err != nil {
		return nil, err
	}

	shared, err := r.nodeTuples(schema, name, store.Tuples)
	if err != nil {
		return nil, err
	}
	for _, named := range slices.DeleteFunc(append([]string{store.TupleFile}, store.TupleFiles...), func(s string) bool { return s == "" }) {
		tuples, err := r.tupleFile(schema, rel, named)
		if err != nil {
			return nil, err
		}
		shared = append(shared, tuples...)
	}

	base := &File{Path: name, SchemaPath: schemaPath, Schema: schema, Store: true, Relationships: shared}
	files := []*File{base}
	for _, test := range store.Tests {
		own, err := r.nodeTuples(schema, name, test.Tuples)
		if err != nil {
			return nil, err
		}
		if test.TupleFile != "" {
			tuples, err := r.tupleFile(schema, rel, test.TupleFile)
			if err != nil {
				return nil, err
			}
			own = append(own, tuples...)
		}
		checks, err := parseChecks(schema, name, test)
		if err != nil {
			return nil, err
		}
		if len(own) == 0 {
			base.Assertions = append(base.Assertions, checks...)
			continue
		}
		files = append(files, &File{
			Path:          name,
			SchemaPath:    schemaPath,
			Schema:        schema,
			Store:         true,
			Test:          test.Name,
			Relationships: slices.Concat(shared, own),
			Assertions:    checks,
		})
	}
	return files, nil
}

// storeModel compiles the model of a store file. The model written in the file wins
// over a model_file, as it does for fga (internal/storetest/storedata.go:160-162 at
// openfga/cli v0.8.2).
func (r reader) storeModel(rel string, store storeFile) (*Schema, string, error) {
	name := r.Display(rel)
	if store.Model.Value != "" {
		schema, err := compileAt(name, schemafiles.ContentLine(store.Model), store.Model.Value)
		return schema, name, err
	}
	if store.ModelFile == "" {
		return nil, "", fmt.Errorf("%w: %s: holds no model and names no model_file", ErrStoreFile, name)
	}
	modelRel, err := r.Named(rel, store.ModelFile)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %s: model_file %s: %w", ErrStoreFile, name, store.ModelFile, err)
	}
	schema, err := r.compileModel(modelRel)
	if err != nil {
		return nil, "", err
	}
	return schema, r.Display(modelRel), nil
}

// nodeTuples lowers the tuples written in a store file.
func (r reader) nodeTuples(schema *Schema, name string, nodes []yaml.Node) ([]zanzibar.Relationship, error) {
	out := make([]zanzibar.Relationship, 0, len(nodes))
	for _, node := range nodes {
		pos := zanzibar.Position{File: name, Line: node.Line, Column: node.Column}
		var tuple storeTuple
		if err := node.Decode(&tuple); err != nil {
			return nil, fmt.Errorf("%w: %s: %w", ErrStoreFile, pos, err)
		}
		lowered, err := lowerStoreTuple(schema, pos, tuple)
		if err != nil {
			return nil, err
		}
		out = append(out, lowered)
	}
	return out, nil
}

// lowerStoreTuple lowers a tuple of a store file and holds it to the model. fga model
// test sends these tuples with every check, and OpenFGA refuses a check with one its
// model does not admit, so a file that holds one does not hold together.
func lowerStoreTuple(schema *Schema, pos zanzibar.Position, tuple storeTuple) (zanzibar.Relationship, error) {
	key := &openfgav1.TupleKey{User: tuple.User, Relation: tuple.Relation, Object: tuple.Object}
	if tuple.Condition != nil {
		context, err := structpb.NewStruct(plainContext(tuple.Condition.Context))
		if err != nil {
			return zanzibar.Relationship{}, fmt.Errorf("%w: %s: context of condition %s: %w", ErrStoreFile, pos, tuple.Condition.Name, err)
		}
		key.Condition = &openfgav1.RelationshipCondition{Name: tuple.Condition.Name, Context: context}
	}
	lowered := LowerTuple(pos, key)
	if err := schema.Admit(lowered); err != nil {
		return zanzibar.Relationship{}, fmt.Errorf("%w: %s: %w", ErrStoreFile, pos, err)
	}
	return lowered, nil
}

// tupleFile reads the tuples of a file a store file names, in the formats fga reads
// (internal/tuplefile/read.go:37-49 at openfga/cli v0.8.2).
func (r reader) tupleFile(schema *Schema, storeRel, named string) ([]zanzibar.Relationship, error) {
	storeName := r.Display(storeRel)
	rel, err := r.Named(storeRel, named)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: tuple file %s: %w", ErrStoreFile, storeName, named, err)
	}
	raw, err := r.Read(rel)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: tuple file %s: %w", ErrStoreFile, storeName, named, err)
	}
	name := r.Display(rel)

	switch path.Ext(rel) {
	case ".json", ".yaml", ".yml":
		var nodes []yaml.Node
		if err := yaml.Unmarshal(raw, &nodes); err != nil {
			return nil, fmt.Errorf("%w: %s: %w", ErrStoreFile, name, err)
		}
		return r.nodeTuples(schema, name, nodes)
	case ".jsonl":
		return jsonlTuples(schema, name, raw)
	case ".csv":
		return csvTuples(schema, name, raw)
	}
	return nil, fmt.Errorf("%w: %s: tuple file %s is none of .json, .yaml, .yml, .jsonl, .csv", ErrStoreFile, storeName, named)
}

func jsonlTuples(schema *Schema, name string, raw []byte) ([]zanzibar.Relationship, error) {
	var out []zanzibar.Relationship
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for number := 1; scanner.Scan(); number++ {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		pos := zanzibar.Position{File: name, Line: number}
		var tuple storeTuple
		if err := json.Unmarshal(line, &tuple); err != nil {
			return nil, fmt.Errorf("%w: %s: %w", ErrStoreFile, pos, err)
		}
		lowered, err := lowerStoreTuple(schema, pos, tuple)
		if err != nil {
			return nil, err
		}
		out = append(out, lowered)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrStoreFile, name, err)
	}
	return out, nil
}

// csvTuples reads a tuple file in CSV, by the names of its columns
// (internal/tuplefile/csv.go:98-117 at openfga/cli v0.8.2).
func csvTuples(schema *Schema, name string, raw []byte) ([]zanzibar.Relationship, error) {
	reader := csv.NewReader(bytes.NewReader(raw))
	header, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrStoreFile, name, err)
	}
	columns := map[string]int{}
	for i, column := range header {
		columns[strings.TrimSpace(column)] = i
	}
	for _, required := range []string{"user_type", "user_id", "relation", "object_type", "object_id"} {
		if _, ok := columns[required]; !ok {
			return nil, fmt.Errorf("%w: %s: has no %s column", ErrStoreFile, name, required)
		}
	}

	var out []zanzibar.Relationship
	for {
		row, err := reader.Read()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %w", ErrStoreFile, name, err)
		}
		line, _ := reader.FieldPos(0)
		pos := zanzibar.Position{File: name, Line: line}
		cell := func(column string) string {
			if i, ok := columns[column]; ok && i < len(row) {
				return strings.TrimSpace(row[i])
			}
			return ""
		}
		tuple := storeTuple{
			User:     cell("user_type") + ":" + cell("user_id"),
			Relation: cell("relation"),
			Object:   cell("object_type") + ":" + cell("object_id"),
		}
		if relation := cell("user_relation"); relation != "" {
			tuple.User += "#" + relation
		}
		if condition := cell("condition_name"); condition != "" {
			tuple.Condition = &storeCondition{Name: condition}
			if context := cell("condition_context"); context != "" {
				if err := json.Unmarshal([]byte(context), &tuple.Condition.Context); err != nil {
					return nil, fmt.Errorf("%w: %s: condition_context: %w", ErrStoreFile, pos, err)
				}
			}
		}
		lowered, err := lowerStoreTuple(schema, pos, tuple)
		if err != nil {
			return nil, err
		}
		out = append(out, lowered)
	}
}

// parseChecks reads the checks of a test into the assertions of the engine, one for
// each user, object and relation a check names. A check that asks with a wildcard is
// left out: OpenFGA answers it, and the engine has no question it stands for.
func parseChecks(schema *Schema, name string, test storeTest) ([]zanzibar.Assertion, error) {
	var out []zanzibar.Assertion
	for _, node := range test.Check {
		pos := zanzibar.Position{File: name, Line: node.Line, Column: node.Column}
		var check storeCheck
		if err := node.Decode(&check); err != nil {
			return nil, fmt.Errorf("%w: %s: %w", ErrStoreFile, pos, err)
		}
		users, err := oneOrMany(check.User, check.Users, "user")
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %w", ErrStoreFile, pos, err)
		}
		objects, err := oneOrMany(check.Object, check.Objects, "object")
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %w", ErrStoreFile, pos, err)
		}
		relations := make([]string, 0, len(check.Assertions))
		for relation := range check.Assertions {
			relations = append(relations, relation)
		}
		slices.Sort(relations)

		values := plainContext(check.Context)
		for _, user := range users {
			for _, object := range objects {
				for _, relation := range relations {
					asked := LowerTuple(pos, &openfgav1.TupleKey{User: user, Relation: relation, Object: object})
					if err := schema.admitCheck(asked); err != nil {
						return nil, fmt.Errorf("%w: %s: %w", ErrStoreFile, pos, err)
					}
					if asked.Subject.ID == zanzibar.WildcardID {
						continue
					}
					level := zanzibar.No
					if check.Assertions[relation] {
						level = zanzibar.Yes
					}
					out = append(out, zanzibar.Assertion{
						Resource: asked.Resource,
						Name:     asked.Relation,
						Subject:  asked.Subject,
						Context:  values,
						Level:    level,
						Position: pos,
					})
				}
			}
		}
	}
	return out, nil
}

// oneOrMany is the values of a field a check can write singly or as a list, not both
// and not neither (internal/storetest/storedata.go:237-258 at openfga/cli v0.8.2).
func oneOrMany(one string, many []string, field string) ([]string, error) {
	switch {
	case one != "" && len(many) > 0:
		return nil, fmt.Errorf("a check holds both %s and %ss", field, field)
	case one != "":
		return []string{one}, nil
	case len(many) > 0:
		return many, nil
	}
	return nil, fmt.Errorf("a check names no %s", field)
}

// plainContext makes a context read from YAML what a check takes. An unquoted date
// reads as a time, which a condition takes as text and structpb refuses, and a
// mapping with a key that is not text reads as a map no JSON object can be.
func plainContext(values map[string]any) map[string]any {
	if values == nil {
		return nil
	}
	out := make(map[string]any, len(values))
	for key, value := range values {
		out[key] = plainValue(value)
	}
	return out
}

func plainValue(value any) any {
	switch v := value.(type) {
	case time.Time:
		return v.Format(time.RFC3339Nano)
	case map[string]any:
		return plainContext(v)
	case map[any]any:
		out := make(map[string]any, len(v))
		for key, inner := range v {
			out[plainKey(key)] = plainValue(inner)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, inner := range v {
			out[i] = plainValue(inner)
		}
		return out
	}
	return value
}

func plainKey(key any) string {
	switch k := key.(type) {
	case string:
		return k
	case int:
		return strconv.Itoa(k)
	}
	return fmt.Sprint(key)
}
