// Package opaengine wraps the OPA libraries. Everything in Petard that knows
// what Rego is lives here; the rest of the program sees only the engine
// neutral model of internal/graph.
//
// Loading is the first step of a linear pipeline: read, parse as Rego v1 or
// v0, compile. Whatever comes after works on the compiled AST alone, which
// does not lose what the raw AST holds but turns it into explicit dataflow.
package opaengine

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
)

const regoExt = ".rego"

var (
	// ErrNoModules is returned when none of the given paths holds a .rego file.
	// It is its own error because an empty run looks exactly like a clean run
	// otherwise: zero findings, zero refs, nothing wrong in sight.
	ErrNoModules = errors.New("opaengine: no rego file found")

	// ErrParse is returned when a source does not parse. The wrapped error
	// names the file and the syntax that was attempted.
	ErrParse = errors.New("opaengine: parse failed")

	// ErrCompile is returned when the modules parse but do not compile.
	ErrCompile = errors.New("opaengine: compile failed")
)

// ParseMode selects which Rego syntax the loader accepts.
type ParseMode int

const (
	// ParseModeAuto parses as Rego v1 and falls back to v0 if that fails.
	//
	// It is the zero value because it is the right default for this tool:
	// Petard reads policies written by other people, and a good share of them
	// is still v0. Which attempt succeeded is recorded in Bundle.RegoVersion,
	// never guessed by the caller.
	ParseModeAuto ParseMode = iota

	// ParseModeV1 parses as Rego v1 only, and fails instead of falling back.
	ParseModeV1

	// ParseModeV0 parses as Rego v0 only. It is the equivalent of the opa CLI
	// --v0-compatible flag, and exists for the same reason: a bundle that
	// happens to parse both ways should be read the way its author meant it.
	ParseModeV0
)

// String returns the mode as it is spelled on the command line.
func (m ParseMode) String() string {
	switch m {
	case ParseModeAuto:
		return "auto"
	case ParseModeV1:
		return "v1"
	case ParseModeV0:
		return "v0"
	default:
		return "unknown"
	}
}

// Bundle is a set of Rego modules parsed and compiled together.
type Bundle struct {
	// Compiler holds the compiled modules, and is the single source of truth
	// for everything downstream. The parsed AST is not kept: the compiler
	// resolves imports, desugars the syntax and rewrites the bodies into
	// explicit dataflow, and rebuilding any of that by hand would mean
	// rewriting parts of OPA.
	Compiler *ast.Compiler

	// RegoVersion is the syntax the modules were parsed as. Under
	// ParseModeAuto it records which of the two attempts succeeded, which is a
	// fact about the analyzed bundle and belongs in the report.
	RegoVersion ast.RegoVersion

	// Files are the sources that produced the modules, in load order and with
	// forward slashes on every platform, so that a graph built on Windows and
	// one built on macOS carry the same provenance.
	Files []string

	// Entrypoints are the rules the caller declares that the PEP queries, on
	// top of the ones the policy annotates itself. Each is spelled either the
	// way a report prints a decision, data.authz.allow, or the way opa build
	// takes one, authz/allow.
	//
	// It is a field of the bundle and not an argument of the analysis because
	// which rules are decisions is a fact about the deployment rather than about
	// the source, and it is set from outside for the same reason the write model
	// is: the source does not say it, and a policy that does not say it is
	// common. Whole families of Rego declare nothing, Gatekeeper constraint
	// templates among them, and without this the only alternative to guessing
	// would be refusing to analyze them at all.
	Entrypoints []string
}

// Load reads every .rego file under paths, parses them together and compiles
// them into a Bundle. A path may be a file or a directory, and directories are
// walked recursively.
//
// The whole bundle is parsed as one syntax, not file by file. A bundle that is
// half v0 and half v1 therefore fails both attempts, and the error says so for
// every file involved: reporting one syntax per file would produce a bundle
// whose recorded version is a half truth.
//
// Annotations are processed while parsing, so that Compiler.GetAnnotationSet
// has something to return. That is where entrypoint declarations come from,
// and they are what tells the analysis which rules are decisions.
func Load(paths []string, mode ParseMode) (*Bundle, error) {
	files, err := collectFiles(paths)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("%w under %s", ErrNoModules, strings.Join(paths, ", "))
	}

	sources, err := readSources(files)
	if err != nil {
		return nil, err
	}

	modules, version, err := parseSources(sources, mode)
	if err != nil {
		return nil, err
	}

	compiler := ast.NewCompiler()
	compiler.Compile(modules)
	if compiler.Failed() {
		return nil, fmt.Errorf("%w, parsed as rego %s: %w", ErrCompile, version, compiler.Errors)
	}

	loaded := make([]string, 0, len(sources))
	for _, src := range sources {
		loaded = append(loaded, src.name)
	}

	return &Bundle{Compiler: compiler, RegoVersion: version, Files: loaded}, nil
}

// source is one file, read once so that the second parsing attempt does not go
// back to disk.
type source struct {
	name string
	text string
}

// collectFiles lists the .rego files under the given paths: in the order the
// paths were given, and lexicographically inside each directory.
func collectFiles(paths []string) ([]string, error) {
	var found []string
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("opaengine: reading %s: %w", path, err)
		}
		if !info.IsDir() {
			found = append(found, path)
			continue
		}

		err = filepath.WalkDir(path, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || filepath.Ext(path) != regoExt {
				return nil
			}
			found = append(found, path)
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("opaengine: walking %s: %w", path, err)
		}
	}
	return dedup(found), nil
}

// dedup keeps the first occurrence of each path. Two arguments reaching the
// same file is a plausible mistake, and compiling it twice would be a rule
// conflict reported against a policy that has none.
func dedup(paths []string) []string {
	unique := make([]string, 0, len(paths))
	seen := make(map[string]bool, len(paths))
	for _, path := range paths {
		path = filepath.Clean(path)
		if seen[path] {
			continue
		}
		seen[path] = true
		unique = append(unique, path)
	}
	return unique
}

// readSources reads the files once. Paths reach the filesystem in their native
// form and are stored with forward slashes, so that normalization happens here
// and nowhere else.
func readSources(files []string) ([]source, error) {
	sources := make([]source, 0, len(files))
	for _, file := range files {
		text, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("opaengine: reading %s: %w", file, err)
		}
		sources = append(sources, source{name: filepath.ToSlash(file), text: string(text)})
	}
	return sources, nil
}

// parseSources parses every source under the syntax the mode asks for, and
// reports which syntax was used.
func parseSources(sources []source, mode ParseMode) (map[string]*ast.Module, ast.RegoVersion, error) {
	switch mode {
	case ParseModeV1:
		modules, err := parseAs(sources, ast.RegoV1)
		return modules, ast.RegoV1, err
	case ParseModeV0:
		modules, err := parseAs(sources, ast.RegoV0)
		return modules, ast.RegoV0, err
	}

	// ParseModeAuto: v1 first, v0 only if v1 does not accept the bundle.
	modules, v1Err := parseAs(sources, ast.RegoV1)
	if v1Err == nil {
		return modules, ast.RegoV1, nil
	}
	modules, v0Err := parseAs(sources, ast.RegoV0)
	if v0Err == nil {
		return modules, ast.RegoV0, nil
	}
	return nil, ast.RegoUndefined, fmt.Errorf("neither rego v1 nor rego v0 parses this bundle:\n%w", errors.Join(v1Err, v0Err))
}

// parseAs collects every failure instead of stopping at the first one. On a
// bundle that mixes the two syntaxes, one message per file is what tells the
// reader which half is which.
func parseAs(sources []source, version ast.RegoVersion) (map[string]*ast.Module, error) {
	opts := ast.ParserOptions{RegoVersion: version, ProcessAnnotation: true}

	modules := make(map[string]*ast.Module, len(sources))
	var errs []error
	for _, src := range sources {
		module, err := ast.ParseModuleWithOpts(src.name, src.text, opts)
		if err != nil {
			errs = append(errs, fmt.Errorf("%w: %s as rego %s: %w", ErrParse, src.name, version, err))
			continue
		}
		modules[src.name] = module
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return modules, nil
}
