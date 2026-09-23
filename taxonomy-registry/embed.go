// Package registry carries the taxonomy into the binary.
//
// A report that files a result under PTD-OPA-003 and stops there leaves the
// reader holding a code to look up in a repository they may not have. Somebody
// who downloads a release has the binary and nothing else, so the binary
// carries the patterns the same way it carries the demo bundle.
//
// The files are the registry as it stands in the repository, unmodified. What
// the engine makes of them is in internal/taxonomy, and what a person reads of
// them is in the explain command: this package only holds the bytes.
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
// with a checkout needs and what the URL below is built from.
const Dir = "taxonomy-registry"

// URL is where the file of a pattern is read on GitHub, one name away.
const URL = "https://github.com/saluc28/petard/blob/main/" + Dir + "/" + OPADir + "/"

// Path is where a pattern file sits in a checkout, slashed the way a report
// prints every other path.
func Path(file string) string {
	return Dir + "/" + OPADir + "/" + file
}

// FlagUsage describes the -registry flag, worded once for the three commands
// that take it.
const FlagUsage = "read the patterns from this directory instead of the ones built into the binary"

//go:embed opa/*.yaml
var files embed.FS

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

// Source is where a command reads the patterns from: the copy built into the
// binary, or the directory somebody working on the registry named.
func Source(dir string) fs.FS {
	if dir == "" {
		return OPA
	}
	return os.DirFS(dir)
}
