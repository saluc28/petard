// Package fixtures carries the hand-written bundle into the binary.
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

// VulnerableBundle is the policy with escalation built into it on purpose,
// with the data and the write model that turn its patterns into findings about
// named principals. `fixtures/vulnerable-bundle/EXPECTED.md` declares in words
// what an analysis has to find in it.
//
//go:embed vulnerable-bundle
var VulnerableBundle embed.FS

// BundleDir is the directory the bundle unpacks into, and the prefix its files
// carry inside the embedded filesystem.
const BundleDir = "vulnerable-bundle"

// Unpack writes the embedded bundle under dir, creating it if it is not there,
// and returns the directory the bundle itself landed in.
func Unpack(dir string) (string, error) {
	root := filepath.Join(dir, BundleDir)

	err := fs.WalkDir(VulnerableBundle, BundleDir, func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		target := filepath.Join(dir, filepath.FromSlash(name))
		if entry.IsDir() {
			return os.MkdirAll(target, 0o750)
		}
		content, err := VulnerableBundle.ReadFile(name)
		if err != nil {
			return err
		}
		return os.WriteFile(target, content, 0o600)
	})
	if err != nil {
		return "", fmt.Errorf("unpacking the bundle: %w", err)
	}
	return root, nil
}
