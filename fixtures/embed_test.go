package fixtures

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// A fixture unpacks under the directory it has in the repository, and only the
// ones named are written.
func TestUnpackWritesTheFixturesNamed(t *testing.T) {
	dir := t.TempDir()
	if err := Unpack(dir, SpiceDBDir); err != nil {
		t.Fatalf("Unpack() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, SpiceDBDir, "validation.yaml")); err != nil {
		t.Errorf("the SpiceDB fixture is not there: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, BundleDir)); err == nil {
		t.Error("the bundle was written, and only the SpiceDB fixture was named")
	}
}

// A fixture already under the directory, edited perhaps, is not written over,
// and the refusal writes nothing at all.
func TestUnpackRefusesAFixtureAlreadyThere(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, BundleDir), 0o750); err != nil {
		t.Fatal(err)
	}

	err := Unpack(dir, SpiceDBDir, BundleDir)
	var exists *ExistsError
	if !errors.As(err, &exists) || exists.Path != filepath.Join(dir, BundleDir) {
		t.Fatalf("Unpack() error = %v, want an ExistsError for %s", err, BundleDir)
	}
	if _, err := os.Stat(filepath.Join(dir, SpiceDBDir)); err == nil {
		t.Error("the refusal wrote the SpiceDB fixture")
	}
}

// A link with the name of a fixture is refused like the directory, so nothing
// is written where it leads.
func TestUnpackDoesNotWriteThroughALink(t *testing.T) {
	dir, outside := t.TempDir(), t.TempDir()
	if err := os.Symlink(outside, filepath.Join(dir, SpiceDBDir)); err != nil {
		t.Skipf("no symbolic link here: %v", err)
	}
	var exists *ExistsError
	if err := Unpack(dir, SpiceDBDir); !errors.As(err, &exists) {
		t.Errorf("Unpack() through a link error = %v, want an ExistsError", err)
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Errorf("Unpack() wrote through the link: %v", entries)
	}
}
