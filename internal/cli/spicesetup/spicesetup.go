// Package spicesetup finds the SpiceDB side of a command's inputs: the schema
// and validation files under the paths, the write model beside each schema, and
// the paths left for the policy loader once those files are taken out.
//
// The analyze and export commands both start from it, so the two read the same
// files the same way and the write-model flag is told apart between the engines
// in one place rather than in each command.
package spicesetup

import (
	"errors"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

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
// The write-model flag feeds both engines, told apart by the kind the file
// declares. A relationship-writes model named there overrides the ones found
// beside the schemas and is kept out of the policy loader's paths; a write-paths
// model, or no flag at all, is left for the policy engine to load.
func Load(paths []string, writeModelPath string) (Found, error) {
	files, err := spicedb.Find(paths)
	if err != nil {
		return Found{}, err
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
