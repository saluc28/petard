package openfga

import (
	"errors"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/saluc28/petard/internal/zanzibar"
)

const fileModel = `model
  schema 1.1
type user
type group
  relations
    define member: [user]
type document
  relations
    define viewer: [user, group#member, user with within]
condition within(limit: int, value: int) {
  value < limit
}
`

// write puts files in a new directory and returns it.
func write(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		full := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func base(files []*File) []string {
	out := make([]string, 0, len(files))
	for _, f := range files {
		out = append(out, path.Base(f.Path))
	}
	return out
}

// A directory is read for what it holds of OpenFGA and nothing else: a model, a model
// in JSON, a store file, and no YAML or JSON of somebody else's. A directory whose name
// starts with a dot is not entered.
func TestFindReadsWhatIsOpenFGAAndLeavesTheRest(t *testing.T) {
	dir := write(t, map[string]string{
		"model.fga":       fileModel,
		"model.json":      `{"schema_version":"1.1","type_definitions":[{"type":"user"}]}`,
		"package.json":    `{"name":"x","version":"1.0.0"}`,
		"store.fga.yaml":  "model: |\n  model\n    schema 1.1\n  type user\n",
		"ml.yaml":         "name: classifier\nmodel: gpt\n",
		"writes.yaml":     "schema_version: 1\nmodel: relationship-writes\nwrites: []\n",
		"validation.yaml": "schema: |\n  definition user {}\n",
		"policy.rego":     "package x\n",
		".git/x.fga":      "this would not compile",
	})
	found, err := Find([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"model.fga", "model.json", "store.fga.yaml"}
	if got := base(found); !reflect.DeepEqual(got, want) {
		t.Errorf("found %v, want %v", got, want)
	}
}

// A path that does not exist is left for the command that was handed it: a URL or a
// bundle archive is not a file of a model.
func TestFindSkipsWhatIsNotThere(t *testing.T) {
	found, err := Find([]string{"http://localhost:8181", filepath.Join(t.TempDir(), "bundle.tar.gz")})
	if err != nil || len(found) != 0 {
		t.Errorf("Find = %v, %v, want nothing", found, err)
	}
}

// A modular model is one model, whatever number of files it spans. The modules an
// fga.mod lists are not models of their own, a relation a module adds by extending a
// type is reported where it is written, and the type where it is declared.
func TestFindReadsAModularModel(t *testing.T) {
	dir := write(t, map[string]string{
		"fga.mod": "schema: '1.2'\ncontents:\n  - core.fga\n  - sub/wiki.fga\n",
		"core.fga": `module core
type user
type document
  relations
    define viewer: [user]
`,
		"sub/wiki.fga": `module wiki

extend type document
  relations
    define editor: [user]
`,
	})
	found, err := Find([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := base(found), []string{"fga.mod"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("found %v, want %v", got, want)
	}
	document := found[0].Schema.Model.Type("document")
	if document == nil || !document.Declares("viewer") || !document.Declares("editor") {
		t.Fatalf("document = %+v, want viewer and editor", document)
	}
	if got := path.Base(document.File); got != "core.fga" {
		t.Errorf("document is reported in %s, want core.fga", got)
	}
	if got := path.Base(document.Permission("editor").File); got != "wiki.fga" {
		t.Errorf("editor is reported in %s, want wiki.fga", got)
	}
	if got := document.Permission("editor").Line; got != 5 {
		t.Errorf("editor is reported at line %d, want 5", got)
	}
}

// A module with no fga.mod to list it cannot be read as a model, and saying so beats
// the parser's complaint about what follows the word module.
func TestFindRefusesAModuleNoModFileLists(t *testing.T) {
	dir := write(t, map[string]string{"core.fga": "module core\ntype user\n"})
	_, err := Find([]string{dir})
	if !errors.Is(err, ErrModel) || !strings.Contains(err.Error(), "no fga.mod") {
		t.Errorf("Find error = %v, want one saying no fga.mod lists it", err)
	}
}

// The refusal says how to go on: the JSON model petard reads directly, and an
// fga.mod listing the module files found under the path, so the fix is to paste one
// rather than to learn the format.
func TestModuleErrorShowsHowToFixIt(t *testing.T) {
	dir := write(t, map[string]string{
		"core.fga":     "module core\ntype user\n",
		"sub/wiki.fga": "module wiki\n",
	})
	_, err := Find([]string{dir})
	if err == nil {
		t.Fatal("Find read a modular model with no fga.mod, want an error")
	}
	for _, want := range []string{"fga model transform", "schema: '1.2'", "contents:", "- core.fga", "- sub/wiki.fga"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not mention %q:\n%v", want, err)
		}
	}
}

// A store file holds its model or names one, brings tuples and checks, and a position
// for each. Tuples read from a file a store file names are held to the same model.
func TestFindReadsAStoreFile(t *testing.T) {
	store := `name: docs
model: |
  model
    schema 1.1
  type user
  type group
    relations
      define member: [user]
  type document
    relations
      define viewer: [user, group#member, user with within]
  condition within(limit: int, value: int) {
    value < limit
  }
tuples:
  - user: user:anne
    relation: viewer
    object: document:1
  - user: user:bob
    relation: viewer
    object: document:1
    condition:
      name: within
      context:
        limit: 10
tuple_files:
  - more.yaml
  - more.jsonl
  - more.csv
tests:
  - name: reads
    check:
      - user: user:bob
        object: document:1
        context:
          value: 3
        assertions:
          viewer: true
      - users: [user:anne, user:carol]
        objects: [document:1, document:2]
        assertions:
          viewer: false
    list_objects:
      - user: user:anne
        type: document
        assertions:
          viewer: [document:1]
`
	dir := write(t, map[string]string{
		"store.fga.yaml": store,
		"more.yaml":      "- user: user:dan\n  relation: viewer\n  object: document:1\n",
		"more.jsonl":     `{"user":"group:g#member","relation":"viewer","object":"document:1"}` + "\n",
		"more.csv": "user_type,user_id,user_relation,relation,object_type,object_id,condition_name,condition_context\n" +
			"user,erin,,member,group,g,,\n" +
			`user,frank,,viewer,document,1,within,"{""limit"":5}"` + "\n" +
			"group,h,member,viewer,document,1,,\n",
	})
	found, err := Find([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 {
		t.Fatalf("found %d files, want 1", len(found))
	}
	f := found[0]
	if !f.Store || f.SchemaPath != f.Path {
		t.Errorf("Store = %v, SchemaPath = %s, want a store file holding its model", f.Store, f.SchemaPath)
	}
	if got := len(f.Relationships); got != 7 {
		t.Fatalf("read %d tuples, want 7: %v", got, f.Relationships)
	}
	if got := f.Relationships[6].Subject.Relation; got != "member" {
		t.Errorf("the userset of the CSV has relation %q, want member", got)
	}
	if got, want := f.Relationships[1].Caveat.Context["limit"], any(float64(10)); got != want {
		t.Errorf("context limit = %v, want %v", got, want)
	}
	if got := f.Relationships[1].Line; got != 19 {
		t.Errorf("the second tuple is at line %d, want 19", got)
	}
	if got := f.Relationships[5].Line; got != 3 {
		t.Errorf("the second tuple of the CSV is at line %d, want 3", got)
	}
	if got := f.Relationships[5].Caveat.Context["limit"]; got != any(float64(5)) {
		t.Errorf("context limit from CSV = %v, want 5", got)
	}
	if got := len(f.Assertions); got != 5 {
		t.Fatalf("read %d checks, want 5: %v", got, f.Assertions)
	}
	first := f.Assertions[0]
	if first.Level != zanzibar.Yes || first.Name != "viewer" || first.Subject.ID != "bob" || first.Context["value"] != 3 {
		t.Errorf("first check = %+v", first)
	}
	if got := f.Assertions[1].Level; got != zanzibar.No {
		t.Errorf("a check asserted false reads as %s", got)
	}
	if got := f.Schema.Model.Type("document").Line; got != 9 {
		t.Errorf("document is at line %d, want 9, the line of the file", got)
	}
}

// A model_file is read in the format its name says, modular among them.
func TestFindReadsTheModelAStoreFileNames(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{
			name: "dsl",
			files: map[string]string{
				"sub/store.fga.yaml": "model_file: ../model.fga\n",
				"model.fga":          fileModel,
			},
			want: "model.fga",
		},
		{
			name: "json",
			files: map[string]string{
				"store.fga.yaml": "model_file: model.json\n",
				"model.json":     `{"schema_version":"1.1","type_definitions":[{"type":"user"}]}`,
			},
			want: "model.json",
		},
		{
			name: "modular",
			files: map[string]string{
				"store.fga.yaml": "model_file: fga.mod\n",
				"fga.mod":        "schema: '1.2'\ncontents:\n  - core.fga\n",
				"core.fga":       "module core\ntype user\n",
			},
			want: "fga.mod",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			found, err := Find([]string{write(t, tt.files)})
			if err != nil {
				t.Fatal(err)
			}
			var store *File
			for _, f := range found {
				if f.Store {
					store = f
				}
			}
			if store == nil {
				t.Fatalf("no store file among %v", base(found))
			}
			if got := path.Base(store.SchemaPath); got != tt.want {
				t.Errorf("SchemaPath = %s, want %s", got, tt.want)
			}
			if store.Schema.Model.Type("user") == nil {
				t.Error("the model was not read")
			}
		})
	}
}

// A model written in the file wins over a model_file, as it does for fga, and the file
// named is not even read.
func TestFindPrefersTheModelWrittenInAStoreFile(t *testing.T) {
	store := "model_file: missing.fga\nmodel: |\n  model\n    schema 1.1\n  type written\n"
	found, err := Find([]string{write(t, map[string]string{"store.fga.yaml": store})})
	if err != nil {
		t.Fatal(err)
	}
	if found[0].Schema.Model.Type("written") == nil || found[0].SchemaPath != found[0].Path {
		t.Errorf("read %s, want the model written in the file", found[0].SchemaPath)
	}
}

// A test that brings tuples is a state of its own: fga sends them with that test's
// checks alone, so they do not leak into the other tests or into what the file shares.
func TestFindKeepsTheTuplesOfATestApart(t *testing.T) {
	store := "model_file: model.fga\n" +
		"tuples:\n  - {user: user:anne, relation: viewer, object: document:1}\n" +
		"tests:\n" +
		"  - name: shared\n    check:\n      - {user: user:anne, object: document:1, assertions: {viewer: true}}\n" +
		"  - name: own\n    tuples:\n      - {user: user:bob, relation: viewer, object: document:1}\n" +
		"    check:\n      - {user: user:bob, object: document:1, assertions: {viewer: true}}\n"
	found, err := Find([]string{filepath.Join(write(t, map[string]string{"store.fga.yaml": store, "model.fga": fileModel}), "store.fga.yaml")})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 2 {
		t.Fatalf("found %d files, want 2", len(found))
	}
	shared, own := found[0], found[1]
	if shared.Test != "" || len(shared.Relationships) != 1 || len(shared.Assertions) != 1 {
		t.Errorf("shared = test %q, %d tuples, %d checks, want 1 and 1", shared.Test, len(shared.Relationships), len(shared.Assertions))
	}
	if own.Test != "own" || len(own.Relationships) != 2 || len(own.Assertions) != 1 {
		t.Errorf("own = test %q, %d tuples, %d checks, want 2 and 1", own.Test, len(own.Relationships), len(own.Assertions))
	}
}

// An unquoted date in YAML reads as a time, which structpb refuses and a check would
// abort on. It reaches the condition as the text it was written as.
func TestFindReadsAnUnquotedTimestamp(t *testing.T) {
	store := `model: |
  model
    schema 1.1
  type user
  type document
    relations
      define viewer: [user with before]
  condition before(ts: timestamp) {
    ts < timestamp("2023-10-11T10:00:00.000Z")
  }
tuples:
  - user: user:anne
    relation: viewer
    object: document:1
    condition:
      name: before
      context:
        ts: 2023-10-11T09:00:00Z
tests:
  - name: t
    check:
      - user: user:anne
        object: document:1
        context:
          nested: [{at: 2023-10-11T09:00:00Z}]
        assertions:
          viewer: true
`
	found, err := Find([]string{write(t, map[string]string{"store.fga.yaml": store})})
	if err != nil {
		t.Fatal(err)
	}
	f := found[0]
	got, err := zanzibar.NewChecker(f.Schema.Model, f.Relationships, f.Schema, time.Now()).Check(
		f.Assertions[0].Resource, f.Assertions[0].Name, f.Assertions[0].Subject, f.Assertions[0].Context)
	if err != nil || got.Level != zanzibar.Yes {
		t.Errorf("Check = %+v, %v, want yes", got, err)
	}
}

// A check that asks with a wildcard is one OpenFGA answers and the engine has no
// question for, so it is left out rather than stopping the run on it.
func TestFindLeavesOutACheckThatAsksWithAWildcard(t *testing.T) {
	store := "model_file: model.fga\ntests:\n  - name: t\n    check:\n" +
		"      - {user: 'user:*', object: document:1, assertions: {viewer: false}}\n"
	found, err := Find([]string{write(t, map[string]string{"store.fga.yaml": store, "model.fga": fileModel})})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range found {
		if len(f.Assertions) != 0 {
			t.Errorf("%s holds checks %v, want none", f.Path, f.Assertions)
		}
	}
}

// A store file that does not hold together is refused with a reason, and nothing it
// names outside the directory analyzed is read.
func TestFindRefusesAStoreFileThatDoesNotHoldTogether(t *testing.T) {
	const tuples = "model_file: model.fga\ntuples:\n"
	tests := []struct {
		name  string
		store string
		want  string
	}{
		{name: "no model", store: "name: x\n", want: "holds no model"},
		{name: "a model_file that climbs out", store: "model_file: ../outside.fga\n", want: "leads out of"},
		{name: "an absolute model_file", store: "model_file: /etc/passwd\n", want: "is absolute"},
		{name: "a tuple file that climbs out", store: "model_file: model.fga\ntuple_file: ../t.yaml\n", want: "leads out of"},
		{name: "a tuple file of no format", store: "model_file: model.fga\ntuple_file: model.fga\n", want: "none of"},
		{name: "a relation the model lacks", store: tuples + "  - {user: user:anne, relation: nope, object: document:1}\n", want: "is not declared"},
		{name: "a subject the relation refuses", store: tuples + "  - {user: group:g, relation: viewer, object: document:1}\n", want: "does not admit"},
		{name: "a condition the relation refuses", store: tuples + "  - {user: group:g#member, relation: viewer, object: document:1, condition: {name: within}}\n", want: "does not admit"},
		{
			name:  "a check with both user and users",
			store: "model_file: model.fga\ntests:\n  - name: t\n    check:\n      - {user: user:a, users: [user:b], object: document:1, assertions: {viewer: true}}\n",
			want:  "both user and users",
		},
		{
			name:  "a check with no object",
			store: "model_file: model.fga\ntests:\n  - name: t\n    check:\n      - {user: user:a, assertions: {viewer: true}}\n",
			want:  "names no object",
		},
		{
			name:  "a check of a relation the model lacks",
			store: "model_file: model.fga\ntests:\n  - name: t\n    check:\n      - {user: user:a, object: document:1, assertions: {nope: true}}\n",
			want:  "is not declared",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := write(t, map[string]string{"store.fga.yaml": tt.store, "model.fga": fileModel})
			_, err := Find([]string{filepath.Join(dir, "store.fga.yaml")})
			if !errors.Is(err, ErrStoreFile) || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Find error = %v, want ErrStoreFile saying %q", err, tt.want)
			}
		})
	}
}

// A module an fga.mod names is held to the directory analyzed as well, and a link out
// of it is refused by the os.Root every read goes through.
func TestFindReadsNothingOutsideTheDirectory(t *testing.T) {
	outside := write(t, map[string]string{"secret.fga": "module secret\ntype user\n"})
	dir := write(t, map[string]string{"fga.mod": "schema: '1.2'\ncontents:\n  - link.fga\n"})
	if err := os.Symlink(filepath.Join(outside, "secret.fga"), filepath.Join(dir, "link.fga")); err != nil {
		t.Skipf("no symlinks here: %v", err)
	}
	_, err := Find([]string{dir})
	if !errors.Is(err, ErrModel) {
		t.Errorf("Find error = %v, want the link refused", err)
	}
}

// A file the language package does not expect makes it panic, and a file in a
// repository that is not the user's own is no reason for a run to crash. A module that
// declares a condition under no module header is one such file.
func TestFindRefusesWhatTheLanguagePackagePanicsOn(t *testing.T) {
	dir := write(t, map[string]string{
		"fga.mod":  "schema: '1.2'\ncontents:\n  - core.fga\n",
		"core.fga": fileModel,
	})
	_, err := Find([]string{dir})
	if !errors.Is(err, ErrModel) {
		t.Errorf("Find error = %v, want ErrModel", err)
	}
}
