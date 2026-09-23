// Package patterns lists the taxonomy the binary carries.
//
// It answers the question a report raises and cannot answer in place: what else
// does this thing look for. The list is short on purpose, an id and a line
// each, with petard explain for the rest.
package patterns

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/saluc28/petard/internal/taxonomy"
	registry "github.com/saluc28/petard/taxonomy-registry"
)

const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2
)

// Run prints the registry, grouped or as JSON.
func Run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("petard patterns", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprint(stderr, "usage: petard patterns [flags]\n\n"+
			"Lists the patterns this binary carries.\n\n")
		flags.PrintDefaults()
	}
	format := flags.String("format", "text", "text or json")
	registryPath := flags.String("registry", "", registry.FlagUsage)

	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if flags.NArg() > 0 {
		fmt.Fprintf(stderr, "petard patterns: %q is not an argument this command takes; "+
			"run petard explain %s for one pattern\n", flags.Arg(0), flags.Arg(0))
		return exitUsage
	}
	if *format != "text" && *format != "json" {
		fmt.Fprintf(stderr, "petard patterns: -format %s is neither text nor json\n", *format)
		return exitUsage
	}

	all, err := taxonomy.LoadRegistry(registry.Source(*registryPath))
	if err != nil {
		fmt.Fprintf(stderr, "petard patterns: %v\n", err)
		return exitFailure
	}
	slices.SortFunc(all, func(a, b taxonomy.Pattern) int { return strings.Compare(a.ID, b.ID) })

	if *format == "json" {
		if err := printJSON(stdout, all); err != nil {
			fmt.Fprintf(stderr, "petard patterns: %v\n", err)
			return exitFailure
		}
		return exitOK
	}
	printText(stdout, all)
	return exitOK
}

// printText groups the patterns under the category each belongs to.
//
// The grouping is the one thing this list says that a flat table would not:
// three OPA patterns are the same category seen from three angles, and that
// category is what a second engine will have to answer for. Inside a group and
// between groups the order comes from the ids, so the list reads in the order
// the patterns were written down.
func printText(out io.Writer, all []taxonomy.Pattern) {
	categories := map[string][]taxonomy.Pattern{}
	var order []string
	for _, pattern := range all {
		id := pattern.Category.ID
		if _, seen := categories[id]; !seen {
			order = append(order, id)
		}
		categories[id] = append(categories[id], pattern)
	}

	fmt.Fprintf(out, "%d patterns, in %d categories.\n", len(all), len(order))
	for _, id := range order {
		group := categories[id]
		fmt.Fprintf(out, "\n%s, %s\n", id, group[0].Category.Title)
		for _, pattern := range group {
			fmt.Fprintf(out, "  %s  %s%s\n", pattern.ID, pattern.Title, unlessVerified(pattern))
		}
	}
	fmt.Fprint(out, "\nRun petard explain <id> for what a pattern looks for and what it will not report.\n")
}

// unlessVerified marks a pattern whose declared false positives have not all
// been settled. Saying so costs a word here and saves a reader from taking a
// young pattern for a finished one; a registry where everything is verified
// prints nothing at all.
func unlessVerified(pattern taxonomy.Pattern) string {
	if pattern.Status == taxonomy.StatusVerified {
		return ""
	}
	return " (" + pattern.Status + ")"
}

// jsonPattern is the list as a program reads it.
//
// It is the identity of a pattern and nothing else: what the tool looks for and
// what it declines to report stay in the files, which are prose and belong to a
// reader. The object around the array is what lets a later release add a field
// next to the patterns without moving them.
type jsonPattern struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Title    string `json:"title"`
	Engine   string `json:"engine"`
	Status   string `json:"status"`
	Category struct {
		ID    string `json:"id"`
		Title string `json:"title"`
	} `json:"category"`
	RequiresWriteModel bool   `json:"requires_write_model"`
	URL                string `json:"url"`
}

func printJSON(out io.Writer, all []taxonomy.Pattern) error {
	list := make([]jsonPattern, 0, len(all))
	for _, pattern := range all {
		entry := jsonPattern{
			ID:                 pattern.ID,
			Name:               pattern.Name,
			Title:              pattern.Title,
			Engine:             pattern.Engine,
			Status:             pattern.Status,
			RequiresWriteModel: pattern.Detection.RequiresWriteModel,
			URL:                registry.URL + pattern.File,
		}
		entry.Category.ID = pattern.Category.ID
		entry.Category.Title = pattern.Category.Title
		list = append(list, entry)
	}

	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(struct {
		Patterns []jsonPattern `json:"patterns"`
	}{list})
}
