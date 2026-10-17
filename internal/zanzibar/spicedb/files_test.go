package spicedb

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// A directory is read for its schema files and its validation files, and
// nothing else: a YAML file of another shape and a hidden directory are left
// alone.
func TestFind(t *testing.T) {
	root := filepath.Join("testdata", "find")
	files, err := Find([]string{root})
	if err != nil {
		t.Fatalf("Find() error = %v", err)
	}

	got := make(map[string]*File, len(files))
	for _, f := range files {
		got[filepath.Base(f.Path)] = f
	}
	if len(got) != 3 {
		t.Fatalf("Find() found %v, want inline.yml, named.yaml and schema.zed", keys(got))
	}

	schema := got["schema.zed"]
	if schema == nil || schema.Validation || schema.Schema.Model.Type("team") == nil {
		t.Errorf("schema.zed = %+v, want a schema file declaring team", schema)
	}

	named := got["named.yaml"]
	if named == nil || !named.Validation {
		t.Fatalf("named.yaml = %+v, want a validation file", named)
	}
	if named.SchemaPath != filepath.Join(root, "schema.zed") {
		t.Errorf("named.yaml schema read from %s, want %s", named.SchemaPath, filepath.Join(root, "schema.zed"))
	}
	if len(named.Relationships) != 2 || named.Assertions != 2 {
		t.Errorf("named.yaml = %d relationships and %d assertions, want 2 and 2", len(named.Relationships), named.Assertions)
	}
	if line := named.Relationships[0].Line; line != 3 {
		t.Errorf("first relationship of named.yaml at line %d, want 3", line)
	}

	inline := got["inline.yml"]
	if inline == nil || inline.SchemaPath != inline.Path || inline.ExpectedRelations != 1 {
		t.Errorf("inline.yml = %+v, want its own schema and one expected relation", inline)
	}
	if line := inline.Schema.Model.Type("room").Line; line != 4 {
		t.Errorf("room declared at line %d of inline.yml, want 4", line)
	}
}

// A file named on the command line is read as it is, and a path that is not
// on disk, such as the URL of a running OPA, is left to the command.
func TestFindReadsFilesAndSkipsWhatIsNotThere(t *testing.T) {
	files, err := Find([]string{
		filepath.Join("testdata", "find", "schema.zed"),
		"https://opa.example/v1/policies",
	})
	if err != nil {
		t.Fatalf("Find() error = %v", err)
	}
	if len(files) != 1 {
		t.Errorf("Find() found %d files, want 1", len(files))
	}
}

// A validation file whose schema cannot be had is an error, whether the file
// it names is missing or it names one and holds one too, which SpiceDB refuses
// rather than choosing.
func TestFindRefusesAValidationFileWithoutOneSchema(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{name: "missing", path: filepath.Join("testdata", "broken", "missing.yaml"), want: "nowhere.zed"},
		{name: "both", path: filepath.Join("testdata", "both", "both.yaml"), want: "only one can be given"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Find([]string{tt.path})
			if !errors.Is(err, ErrValidationFile) || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Find() error = %v, want ErrValidationFile saying %q", err, tt.want)
			}
		})
	}
}

// A validation file names its schema itself, and the name cannot take petard
// out of the directory it was pointed at, whether it climbs or is absolute.
func TestFindStaysUnderTheDirectory(t *testing.T) {
	tests := []struct {
		name string
		file string
		want string
	}{
		{name: "climbing", file: filepath.Join("inner", "climbs.yaml"), want: "leads out of"},
		{name: "absolute", file: "absolute.yaml", want: "is absolute"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Find([]string{filepath.Join("testdata", "escape", tt.file)})
			if !errors.Is(err, ErrValidationFile) || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Find() error = %v, want ErrValidationFile saying %q", err, tt.want)
			}
		})
	}
}

// findOne reads the one input a file holds.
func findOne(t *testing.T, path string) *File {
	t.Helper()

	files, err := Find([]string{path})
	if err != nil {
		t.Fatalf("Find(%s) error = %v", path, err)
	}
	if len(files) != 1 {
		t.Fatalf("Find(%s) found %d inputs, want 1", path, len(files))
	}
	return files[0]
}

func keys(m map[string]*File) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
