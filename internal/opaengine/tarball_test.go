package opaengine

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// writeTarball writes a bundle archive the way opa build does, every path with
// a leading slash.
func writeTarball(t *testing.T, files map[string]string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "bundle.tar.gz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("creating the archive: %v", err)
	}
	defer f.Close()
	compressed := gzip.NewWriter(f)
	archive := tar.NewWriter(compressed)

	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		header := &tar.Header{Name: "/" + name, Mode: 0o600, Size: int64(len(files[name])), Typeflag: tar.TypeReg}
		if err := archive.WriteHeader(header); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
		if _, err := archive.Write([]byte(files[name])); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatalf("closing the archive: %v", err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatalf("closing the archive: %v", err)
	}
	return path
}

// A bundle archive is read in place: the policies inside it are the bundle,
// named after the archive, and its data files land where OPA puts them, while
// the other JSON in it is left alone, as it is in a directory.
func TestReadsABundleArchive(t *testing.T) {
	path := writeTarball(t, map[string]string{
		"authz/policy.rego": `package authz

# METADATA
# entrypoint: true
allow if "admin" in data.users[input.user].roles
`,
		"users/data.json": `{"alice": {"roles": ["admin"]}}`,
		"input.json":      `{"user": "alice"}`,
		".manifest":       `{"revision": "1"}`,
	})

	bundle, err := Load([]string{path}, ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	want := filepath.ToSlash(path) + "/authz/policy.rego"
	if !slices.Equal(bundle.Files, []string{want}) {
		t.Errorf("Files = %v, want [%s]", bundle.Files, want)
	}

	data, err := LoadBundleData([]string{path})
	if err != nil {
		t.Fatalf("LoadBundleData() error = %v", err)
	}
	if len(data.Files) != 1 {
		t.Errorf("data files = %v, want users/data.json alone", data.Files)
	}
	granted, err := Holds(t.Context(), bundle, data, "data.authz.allow", map[string]any{"user": "alice"})
	if err != nil {
		t.Fatalf("Holds() error = %v", err)
	}
	if !granted {
		t.Error("alice is not granted, so the data did not land at data.users")
	}

	// Given as -data, the archive is the same data.
	given, err := LoadData([]string{path})
	if err != nil {
		t.Fatalf("LoadData() error = %v", err)
	}
	if !slices.Equal(given.Files, data.Files) {
		t.Errorf("LoadData() files = %v, want %v", given.Files, data.Files)
	}
}
