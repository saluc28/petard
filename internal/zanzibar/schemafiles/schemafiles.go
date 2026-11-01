// Package schemafiles reads the files of a schema from under the paths a command
// was given, and from nowhere else. A file can name another with a path of its own
// choosing, and a repository is not always somebody's own, so every read goes
// through an os.Root: a name or a link that leads out of the directory is refused
// rather than followed.
package schemafiles

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Dir is one directory the files of a schema are read from. Paths given to it are
// relative to the directory, with forward slashes.
type Dir struct {
	root *os.Root
	name string
}

// Each opens the directory of every path that exists and hands it over, with only
// naming the one file when the path named a file. A path that does not exist is
// skipped: a URL or a bundle archive is not a file of a schema, and the command
// that was handed it says what it is.
func Each(paths []string, visit func(d *Dir, only string) error) error {
	for _, p := range paths {
		// What is read under p goes through the os.Root of the Dir.
		info, err := os.Stat(p) //nolint:gosec // G703: p is a path the user named on the command line
		if err != nil {
			continue
		}
		dir, only := p, ""
		if !info.IsDir() {
			dir, only = filepath.Dir(p), filepath.Base(p)
		}
		if err := visitDir(dir, only, visit); err != nil {
			return err
		}
	}
	return nil
}

func visitDir(dir, only string, visit func(d *Dir, only string) error) (err error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	return visit(&Dir{root: root, name: dir}, only)
}

// Walk visits every file under the directory. Directories whose name starts with a
// dot are not entered.
func (d *Dir) Walk(visit func(rel string) error) error {
	return fs.WalkDir(d.root.FS(), ".", func(rel string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if rel != "." && strings.HasPrefix(entry.Name(), ".") {
				return fs.SkipDir
			}
			return nil
		}
		return visit(rel)
	})
}

// Display is the path a report prints for a file of the directory. It has forward
// slashes on every system, so a report reads the same on Windows and names a schema
// the way it names a policy beside it.
func (d *Dir) Display(rel string) string {
	return filepath.ToSlash(filepath.Join(d.name, filepath.FromSlash(rel)))
}

// Read reads a file of the directory.
func (d *Dir) Read(rel string) ([]byte, error) {
	return d.root.ReadFile(filepath.FromSlash(rel))
}

// Sub is the directory a file at rel sits in, inside the root.
func (d *Dir) Sub(rel string) fs.FS {
	sub, err := fs.Sub(d.root.FS(), path.Dir(rel))
	if err != nil {
		return nil
	}
	return sub
}

// Named resolves a path the file at rel names against the directory of that file. A
// path that is absolute, or that climbs out of the directory analyzed, is refused
// here with a reason; the os.Root behind every read refuses the links that would.
func (d *Dir) Named(rel, named string) (string, error) {
	slashed := filepath.ToSlash(named)
	if path.IsAbs(slashed) || filepath.IsAbs(named) || filepath.VolumeName(named) != "" {
		return "", errors.New("is absolute: it has to name a file under the directory analyzed")
	}
	joined := path.Join(path.Dir(rel), slashed)
	if joined == ".." || strings.HasPrefix(joined, "../") {
		return "", fmt.Errorf("leads out of %s, the directory analyzed", d.name)
	}
	return joined, nil
}
