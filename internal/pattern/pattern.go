// Package pattern reads the panel metadata of the taxonomy patterns from the
// registry: enough to name a pattern, link its file, and say what closes it.
//
// It is the subset of a registry entry the BloodHound Entity Panel needs,
// parsed from the same YAML the engine reads, so a pattern added to the
// registry appears in the panel without being copied anywhere. The full entry,
// with the detection signals and the graph marks, is parsed in
// internal/taxonomy; this package deliberately reads only what a panel shows,
// so the serialization layer need not depend on the analysis engine.
package pattern

import (
	"fmt"
	"io/fs"
	"sort"
	"strings"

	yaml "go.yaml.in/yaml/v3"

	registry "github.com/saluc28/petard/taxonomy-registry"
)

// Note is what the panel says about one pattern: its id and name, which make
// its file, the engine whose directory the file sits in, its title, and what
// closes it.
type Note struct {
	ID     string
	Name   string
	Engine string
	Title  string
	Closes string
}

// Notes are every pattern's panel metadata, OPA first then Zanzibar, each
// engine in file order, which is the order the committed schema lists them in.
func Notes() ([]Note, error) {
	var notes []Note
	for _, engine := range []struct {
		dir string
		fs  fs.FS
	}{
		{registry.OPADir, registry.OPA},
		{registry.ZanzibarDir, registry.Zanzibar},
	} {
		loaded, err := load(engine.fs, engine.dir)
		if err != nil {
			return nil, err
		}
		notes = append(notes, loaded...)
	}
	return notes, nil
}

// load reads the notes of one engine from its directory of the registry, in
// file order.
func load(fsys fs.FS, engine string) ([]Note, error) {
	names, err := fs.Glob(fsys, "*.yaml")
	if err != nil {
		return nil, fmt.Errorf("pattern: listing the %s registry: %w", engine, err)
	}
	sort.Strings(names)

	notes := make([]Note, 0, len(names))
	for _, name := range names {
		content, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, fmt.Errorf("pattern: reading %s: %w", name, err)
		}
		var entry struct {
			ID     string `yaml:"id"`
			Name   string `yaml:"name"`
			Title  string `yaml:"title"`
			Closes string `yaml:"closes"`
		}
		if err := yaml.Unmarshal(content, &entry); err != nil {
			return nil, fmt.Errorf("pattern: parsing %s: %w", name, err)
		}
		// Closes is folded in the YAML and trimmed the way internal/taxonomy
		// trims it, so the panel reads the same text the engine does.
		notes = append(notes, Note{
			ID:     entry.ID,
			Name:   entry.Name,
			Engine: engine,
			Title:  entry.Title,
			Closes: strings.TrimSpace(entry.Closes),
		})
	}
	return notes, nil
}
