// Package spicesetup finds the SpiceDB side of a command's inputs: the schema
// and validation files under the paths, the write model beside each schema, and
// the paths left for the policy loader once those files are taken out.
//
// The analyze and export commands both start from it, so the two read the same
// files the same way and the write-model flag is told apart between the engines
// in one place rather than in each command.
package spicesetup

import (
	"context"
	"errors"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/saluc28/petard/internal/writemodel"
	"github.com/saluc28/petard/internal/zanzibar"
	"github.com/saluc28/petard/internal/zanzibar/spicedb"
)

// Found is the SpiceDB side of a command's inputs.
type Found struct {
	// Files are the schema and validation files found under the paths.
	Files []*spicedb.File

	// WriteModels is the relationship-writes write model for each schema's
	// directory, keyed by that directory, for the directories that have one.
	WriteModels map[string]*zanzibar.WriteModel

	// PolicyPaths are the paths with the SpiceDB files named one by one taken
	// out, for the policy loader: a schema named on the command line is not a
	// Rego file, and the loader reads every file it is handed as one. A directory
	// stays, since the loader takes only the Rego files under it.
	PolicyPaths []string

	// PolicyWriteModel is the write model path left for the policy engine: the
	// one writeModelPath named, or empty when that file was a relationship-writes
	// model and so belongs to the Zanzibar engine instead.
	PolicyWriteModel string
}

// Load finds the SpiceDB files under paths and the write models beside them.
//
// A path may also name a running SpiceDB (spicedb://host:port, or
// spicedb+insecure://host:port for a local development one), whose schema is
// read over its API, read only, and compiled the way a .zed file on disk is.
// This is the SpiceDB counterpart to naming a running OPA in place of a path,
// and it is how a schema that lives only inside a running SpiceDB is analyzed; a
// write model for such a schema comes from the -write-model flag, since a live
// schema has no directory beside it to hold one. The offline default is
// untouched: nothing here connects unless a path names an endpoint.
//
// The write-model flag feeds both engines, told apart by the kind the file
// declares. A relationship-writes model named there overrides the ones found
// beside the schemas and is kept out of the policy loader's paths; a write-paths
// model, or no flag at all, is left for the policy engine to load.
func Load(ctx context.Context, paths []string, writeModelPath string) (Found, error) {
	disk, endpoints := partitionEndpoints(paths)
	files, err := spicedb.Find(disk)
	if err != nil {
		return Found{}, err
	}
	if len(endpoints) > 0 {
		token := os.Getenv(spicedb.TokenEnv)
		for _, ep := range endpoints {
			f, err := spicedb.ReadLive(ctx, ep, token)
			if err != nil {
				return Found{}, err
			}
			files = append(files, f)
		}
		// Find sorts what it read from disk; the live schemas are appended after,
		// so the whole set is sorted again to keep a command reading the same
		// inputs in the same order on every run.
		slices.SortFunc(files, func(a, b *spicedb.File) int { return strings.Compare(a.Path, b.Path) })
	}
	writeModels, err := discoverWriteModels(files)
	if err != nil {
		return Found{}, err
	}

	policyWriteModel := writeModelPath
	if writeModelPath != "" {
		wm, err := zanzibar.LoadWriteModel(writeModelPath)
		switch {
		case err == nil:
			policyWriteModel = ""
			for _, dir := range dirs(files) {
				writeModels[dir] = wm
			}
		case errors.Is(err, writemodel.ErrNotAWriteModel):
			// A write-paths model for the policy engine; left for it to load.
		default:
			return Found{}, err
		}
	}

	return Found{
		Files:            files,
		WriteModels:      writeModels,
		PolicyPaths:      nonSchemaPaths(paths, files),
		PolicyWriteModel: policyWriteModel,
	}, nil
}

// Analysis is one schema the patterns run on: the sample to read it with, and
// the write model that says who writes its relations. A validation file brings
// its own relationships and checks; a bare schema brings none, and the patterns
// take their starting state from the positions the schema generates instead.
type Analysis struct {
	// SchemaPath is the schema the analysis is about, so a caller can report a
	// fact about one schema once even when two validation files read it.
	SchemaPath string
	Sample     zanzibar.Sample
	WriteModel *zanzibar.WriteModel
}

// Analyses is what the patterns run on, and the schemas left with nothing to run
// from. A schema a validation file reads is analyzed with that file, one entry
// per file, so its relationships and checks are evidence. A schema no validation
// file reads is still analyzed, from its bare schema, when a write model beside
// it says who writes its relations: the patterns start from the positions the
// schema generates, which is what lets a schema be validated without a
// validation file written by hand. A schema with neither is left out of the
// first value and named in the second, for the caller to report as lacking
// evidence rather than read as clean.
//
// The entries come in the order the files sort, so a command reads the same
// inputs the same way on every run.
func (f Found) Analyses(now time.Time) (run []Analysis, noEvidence []string) {
	readByValidation := map[string]bool{}
	for _, file := range f.Files {
		if file.Validation {
			readByValidation[file.SchemaPath] = true
		}
	}
	seen := map[string]bool{}
	for _, file := range f.Files {
		wm := f.WriteModels[path.Dir(file.SchemaPath)]
		if file.Validation {
			run = append(run, Analysis{SchemaPath: file.SchemaPath, Sample: file.Sample(now), WriteModel: wm})
			continue
		}
		// A schema a validation file reads is analyzed with that file above; a bare
		// schema named more than once is analyzed once.
		if readByValidation[file.SchemaPath] || seen[file.SchemaPath] {
			continue
		}
		seen[file.SchemaPath] = true
		if wm == nil {
			noEvidence = append(noEvidence, file.Path)
			continue
		}
		run = append(run, Analysis{SchemaPath: file.SchemaPath, Sample: file.Sample(now), WriteModel: wm})
	}
	return run, noEvidence
}

// discoverWriteModels reads a relationship-writes write model from the
// directory of each schema the SpiceDB files name, so that a schema with a
// write model beside it is analyzed with one and its matches become findings.
// A YAML that is not a write model, a validation file among them, is left
// alone; a write model that does not hold together is an error named to the
// user.
func discoverWriteModels(files []*spicedb.File) (map[string]*zanzibar.WriteModel, error) {
	models := map[string]*zanzibar.WriteModel{}
	for _, dir := range dirs(files) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			// A schema held inline in a validation file has no directory of its
			// own to read, and a directory already walked for the schema is read
			// for what it holds either way.
			continue
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || (!strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml")) {
				continue
			}
			wm, err := zanzibar.LoadWriteModel(path.Join(dir, name))
			switch {
			case err == nil:
				models[dir] = wm
			case errors.Is(err, writemodel.ErrNotAWriteModel):
				// A validation file or some other YAML; not a write model.
			default:
				return nil, err
			}
		}
	}
	return models, nil
}

// dirs is the distinct directories the schemas live in, in a stable order.
func dirs(files []*spicedb.File) []string {
	var out []string
	for _, f := range files {
		dir := path.Dir(f.SchemaPath)
		if !slices.Contains(out, dir) {
			out = append(out, dir)
		}
	}
	return out
}

// partitionEndpoints splits the paths into the ones that name a running SpiceDB
// and the rest, so the live schemas are read over the API and the rest are read
// from disk. A running OPA's http(s) URL is not an endpoint here and stays with
// the rest, for the policy loader to read.
func partitionEndpoints(paths []string) (disk []string, endpoints []spicedb.Endpoint) {
	for _, p := range paths {
		if ep, ok := spicedb.ParseEndpoint(p); ok {
			endpoints = append(endpoints, ep)
			continue
		}
		disk = append(disk, p)
	}
	return disk, endpoints
}

// nonSchemaPaths are the paths left for the policy loader once the SpiceDB
// files named one by one are taken out.
func nonSchemaPaths(paths []string, files []*spicedb.File) []string {
	named := map[string]bool{}
	for _, f := range files {
		named[filepath.Clean(f.Path)] = true
	}
	var out []string
	for _, p := range paths {
		if !named[filepath.Clean(p)] {
			out = append(out, p)
		}
	}
	return out
}
