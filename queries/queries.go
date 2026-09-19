// Package queries holds the saved Cypher queries that come with Petard, one
// file per query, in the format of the BloodHound Query Library.
//
// They are the way into the graph for somebody who opens BloodHound after an
// export: every pattern leaves its id on the nodes and edges it reports on, and
// a query per question asks for them. The files are embedded, so the binary
// carries the queries it was built with, and queries.json next to them is the
// same set in the form queries.specterops.io reads from a custom source.
package queries

import (
	"embed"
	"fmt"
	"io/fs"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

//go:embed *.yml
var files embed.FS

// LibraryFile is the name of the file that holds every query as one list.
const LibraryFile = "queries.json"

// Query is one saved query, with the fields of the BloodHound Query Library in
// its order. BloodHound's own import reads name, description and query, and
// leaves the rest alone.
type Query struct {
	Name             string   `yaml:"name" json:"name"`
	GUID             string   `yaml:"guid" json:"guid"`
	Prebuilt         bool     `yaml:"prebuilt" json:"prebuilt"`
	Platforms        []string `yaml:"platforms" json:"platforms"`
	Category         string   `yaml:"category" json:"category"`
	Description      string   `yaml:"description" json:"description"`
	Query            string   `yaml:"query" json:"query"`
	Revision         int      `yaml:"revision" json:"revision"`
	Resources        []string `yaml:"resources" json:"resources"`
	Acknowledgements []string `yaml:"acknowledgements" json:"acknowledgements"`
}

// All returns every query, sorted by name, which is the order BloodHound lists
// them in.
func All() ([]Query, error) {
	names, err := fs.Glob(files, "*.yml")
	if err != nil {
		return nil, fmt.Errorf("queries: listing the files: %w", err)
	}

	all := make([]Query, 0, len(names))
	for _, name := range names {
		content, err := files.ReadFile(name)
		if err != nil {
			return nil, fmt.Errorf("queries: reading %s: %w", name, err)
		}
		var query Query
		if err := yaml.Unmarshal(content, &query); err != nil {
			return nil, fmt.Errorf("queries: parsing %s: %w", name, err)
		}
		query.Description = strings.TrimSpace(query.Description)
		all = append(all, query)
	}
	slices.SortFunc(all, func(a, b Query) int { return strings.Compare(a.Name, b.Name) })
	return all, nil
}
