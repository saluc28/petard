// Package registry carries the taxonomy into the binary.
//
// A report that files a result under PTD-OPA-003 and stops there leaves the
// reader holding a code to look up in a repository they may not have. Somebody
// who downloads a release has the binary and nothing else, so the binary
// carries the patterns the same way it carries the demo bundle.
//
// The files are the registry as it stands in the repository, unmodified: one
// directory per engine, named after it, holding one file per pattern. What the
// engine makes of them is in internal/taxonomy, and what a person reads of them
// is in the explain command: this package only holds the bytes.
package registry

import (
	"embed"
	"io/fs"
	"os"
)

// OPADir is where the patterns of the OPA engine sit, in the repository and
// inside the embedded filesystem alike.
const OPADir = "opa"

// Dir is where the registry sits in the repository, which is what a reader
// with a checkout needs and what URL is built from.
const Dir = "taxonomy-registry"

// BlobURL is where a file of the repository is read on GitHub, its path away.
const BlobURL = "https://github.com/saluc28/petard/blob/main/"

// URL is where the file of a pattern of an engine is read on GitHub.
func URL(engine, file string) string {
	return BlobURL + Path(engine, file)
}

// Path is where the file of a pattern of an engine sits in a checkout,
// slashed the way a report prints every other path.
func Path(engine, file string) string {
	return Dir + "/" + engine + "/" + file
}

// FlagUsage describes the -registry flag, worded once for the three commands
// that take it.
const FlagUsage = "read the patterns from this registry directory, which holds one directory per engine, instead of the ones built into the binary"

//go:embed opa/*.yaml
var files embed.FS

// FS is the whole registry built into the binary, one directory per engine.
var FS fs.FS = files

// OPA is every pattern of the OPA engine, one YAML file each, rooted at the
// directory holding them so that a caller reading from disk and a caller
// reading from here see the same names.
var OPA = mustSub(OPADir)

// mustSub panics on a directory that is not there. The tree is fixed at build
// time, so the only way this fails is a build that embedded the wrong thing,
// and that has to be loud rather than left to surface as a registry with
// nothing in it.
func mustSub(dir string) fs.FS {
	sub, err := fs.Sub(files, dir)
	if err != nil {
		panic(err)
	}
	return sub
}

// Source is where a command reads the registry from: the copy built into the
// binary, or the registry directory somebody working on it named.
func Source(dir string) fs.FS {
	if dir == "" {
		return FS
	}
	return os.DirFS(dir)
}
