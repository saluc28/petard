// Package fixtures carries the fixtures written by hand into the binary.
//
// It exists so that `petard demo` has something to analyze. Somebody who
// downloads a release has the binary and nothing else, and a tool that cannot
// show what it does without a git clone first does not get tried.
package fixtures

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// Embedded holds the fixtures, each under the directory it has in the
// repository.
//
//go:embed vulnerable-bundle vulnerable-spicedb
var Embedded embed.FS

const (
	// BundleDir is the policy with escalation built into it on purpose, with
	// the data and the write model that turn its patterns into findings about
	// named principals. `fixtures/vulnerable-bundle/EXPECTED.md` declares in
	// words what an analysis has to find in it.
	BundleDir = "vulnerable-bundle"

	// SpiceDBDir is the SpiceDB schema of the same documents service, with a
	// validation file whose relationships and checks hold a case and a counter
	// case for each Zanzibar pattern. `fixtures/vulnerable-spicedb/EXPECTED.md`
	// declares what an analysis has to find in it.
	SpiceDBDir = "vulnerable-spicedb"
)

// ExistsError is returned when the directory a fixture unpacks into is already
// there. What it holds may be the edits somebody made to the fixture, and
// writing over them would lose them without a word.
type ExistsError struct {
	Path string
}

// Error names the directory that is in the way.
func (e *ExistsError) Error() string { return e.Path + " is already there" }

// Unpack writes the fixtures named by their directory, BundleDir or
// SpiceDBDir, under dir, creating dir if it is not there.
//
// Nothing is written when the directory of one of them is already under dir.
// The files are written through an os.Root, so a link under dir cannot lead a
// write out of it.
func Unpack(dir string, names ...string) (err error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, root.Close()) }()

	for _, name := range names {
		_, err := root.Lstat(name)
		if err == nil {
			return &ExistsError{Path: filepath.Join(dir, name)}
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	for _, name := range names {
		if err := unpack(root, name); err != nil {
			return fmt.Errorf("unpacking %s: %w", name, err)
		}
	}
	return nil
}

func unpack(root *os.Root, fixture string) error {
	return fs.WalkDir(Embedded, fixture, func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		target := filepath.FromSlash(name)
		if entry.IsDir() {
			return root.Mkdir(target, 0o750)
		}
		content, err := Embedded.ReadFile(name)
		if err != nil {
			return err
		}
		return root.WriteFile(target, content, 0o600)
	})
}
