package analyze

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/saluc28/petard/internal/cli/render"
	"github.com/saluc28/petard/internal/zanzibar/spicedb"
)

// printSpiceDB says what the SpiceDB files under the analyzed paths declare.
// No pattern runs on them in this version, and the summary says so, so that a
// run with nothing to report is not read as a schema with nothing wrong.
func printSpiceDB(out io.Writer, files []*spicedb.File, style render.Style) {
	fmt.Fprintln(out, style.Bold(render.Count(len(files), "SpiceDB file")))
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	for _, f := range files {
		fmt.Fprintf(tw, "  %s\t%s\n", f.Path, describeSpiceDB(f))
	}
	tw.Flush()
	fmt.Fprintln(out, "No pattern runs on SpiceDB schemas in this version, so nothing in them was checked.")
}

func describeSpiceDB(f *spicedb.File) string {
	m := f.Schema.Model
	relations, permissions := 0, 0
	for _, t := range m.Types {
		relations += len(t.Relations)
		permissions += len(t.Permissions)
	}
	declares := strings.Join([]string{
		render.Count(len(m.Types), "definition"),
		render.Count(relations, "relation"),
		render.Count(permissions, "permission"),
		render.Count(len(m.Caveats), "caveat"),
	}, ", ")
	if !f.Validation {
		return declares
	}

	holds := []string{render.Count(len(f.Relationships), "relationship"), render.Count(len(f.Assertions), "assertion")}
	if f.ExpectedRelations > 0 {
		holds = append(holds, render.Count(f.ExpectedRelations, "expected relation"))
	}
	if f.SchemaPath != f.Path {
		return fmt.Sprintf("validation file of %s, %s", f.SchemaPath, strings.Join(holds, ", "))
	}
	return fmt.Sprintf("validation file, %s; %s", strings.Join(holds, ", "), declares)
}
