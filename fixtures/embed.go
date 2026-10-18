// Package fixtures carries the fixtures written by hand into the binary.
//
// It exists so that `petard demo` has something to analyze. Somebody who
// downloads a release has the binary and nothing else, and a tool that cannot
// show what it does without a git clone first does not get tried.
package fixtures

import (
	"embed"
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

// Unpack writes every fixture under dir, each in the directory it has in the
// repository, creating dir if it is not there.
func Unpack(dir string) error {
	for _, name := range []string{BundleDir, SpiceDBDir} {
		if err := unpack(dir, name); err != nil {
			return fmt.Errorf("unpacking %s: %w", name, err)
		}
	}
	return nil
}

func unpack(dir, fixture string) error {
	return fs.WalkDir(Embedded, fixture, func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		target := filepath.Join(dir, filepath.FromSlash(name))
		if entry.IsDir() {
			return os.MkdirAll(target, 0o750)
		}
		content, err := Embedded.ReadFile(name)
		if err != nil {
			return err
		}
		return os.WriteFile(target, content, 0o600)
	})
}
