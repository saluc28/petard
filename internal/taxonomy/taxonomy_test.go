package taxonomy

import (
	"strings"
	"testing"
	"testing/fstest"

	registry "github.com/saluc28/petard/taxonomy-registry"
)

// minimal is the smallest pattern file the loader accepts, for an engine.
func minimal(id, engine string) *fstest.MapFile {
	return &fstest.MapFile{Data: []byte("schema_version: 2\nid: " + id + "\nengine: " + engine + "\ncloses: it\n")}
}

// The registry built into the binary is read whole, every engine under its own
// directory.
func TestLoadRegistriesReadsTheBuiltInRegistry(t *testing.T) {
	patterns, err := LoadRegistries(registry.FS)
	if err != nil {
		t.Fatalf("LoadRegistries() error = %v", err)
	}
	opa, err := LoadRegistry(registry.OPA)
	if err != nil {
		t.Fatalf("LoadRegistry() error = %v", err)
	}
	if len(patterns) < len(opa) {
		t.Errorf("LoadRegistries() = %d patterns, fewer than the %d of the OPA engine alone", len(patterns), len(opa))
	}
	for _, pattern := range patterns {
		if pattern.Engine == "" || strings.Contains(pattern.File, "/") {
			t.Errorf("%s: engine %q, file %q; want an engine and a file name", pattern.ID, pattern.Engine, pattern.File)
		}
	}
}

func TestLoadRegistriesRefuses(t *testing.T) {
	tests := []struct {
		name string
		root fstest.MapFS
		want string
	}{
		{
			name: "the directory of one engine",
			root: fstest.MapFS{"PTD-OPA-001.yaml": minimal("PTD-OPA-001", "opa")},
			want: "at the top of the registry",
		},
		{
			name: "a file under the wrong engine",
			root: fstest.MapFS{"opa/PTD-ZAN-001.yaml": minimal("PTD-ZAN-001", "zanzibar")},
			want: `says its engine is "zanzibar"`,
		},
		{
			name: "no engine at all",
			root: fstest.MapFS{"README.md": {Data: []byte("the registry")}},
			want: "no engine directory",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := LoadRegistries(tt.root)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("LoadRegistries() error = %v, want one saying %q", err, tt.want)
			}
		})
	}
}

// Each engine directory is held to the same rules as a registry of one engine,
// and the error says which directory broke them.
func TestLoadRegistriesNamesTheEngine(t *testing.T) {
	_, err := LoadRegistries(fstest.MapFS{
		"opa/PTD-OPA-001.yaml":      minimal("PTD-OPA-001", "opa"),
		"zanzibar/PTD-ZAN-001.yaml": {Data: []byte("schema_version: 1\nid: PTD-ZAN-001\nengine: zanzibar\ncloses: it\n")},
	})
	if err == nil || !strings.Contains(err.Error(), "under zanzibar") || !strings.Contains(err.Error(), "schema version 1") {
		t.Errorf("LoadRegistries() error = %v, want the version of the zanzibar file", err)
	}
}
