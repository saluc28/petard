package analyze

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/saluc28/petard/internal/cli/render"
	"github.com/saluc28/petard/internal/taxonomy"
	"github.com/saluc28/petard/internal/writemodel"
	"github.com/saluc28/petard/internal/zanzibar"
	"github.com/saluc28/petard/internal/zanzibar/spicedb"
)

// spiceDBRun is what the patterns of the Zanzibar engine made of the SpiceDB
// files under the analyzed paths.
type spiceDBRun struct {
	files   []*spicedb.File
	matches []zanzibar.Match

	// unread are the schema files no validation file under the paths reads,
	// which leaves the patterns no relationship and no check to take
	// evidence from.
	unread []string
}

// runSpiceDB applies the patterns of the Zanzibar engine to every file found.
//
// A schema read by two validation files is one schema, and a fact about it is
// reported once: the first file that shows it, in the order the files sort,
// is the one the report cites.
func runSpiceDB(files []*spicedb.File, now time.Time, writeModels map[string]*zanzibar.WriteModel) spiceDBRun {
	run := spiceDBRun{files: files}
	read := map[string]bool{}
	seen := map[string]bool{}
	for _, f := range files {
		if !f.Validation {
			continue
		}
		read[f.SchemaPath] = true
		wm := writeModels[path.Dir(f.SchemaPath)]
		for _, m := range zanzibar.Run(f.Sample(now), wm) {
			key := m.PatternID + "\x00" + f.SchemaPath + "\x00" + m.Subject
			if seen[key] {
				continue
			}
			seen[key] = true
			run.matches = append(run.matches, m)
		}
	}
	for _, f := range files {
		if !f.Validation && !read[f.Path] {
			run.unread = append(run.unread, f.Path)
		}
	}
	return run
}

// discoverWriteModels reads a relationship-writes write model from the
// directory of each schema the SpiceDB files name, so that a schema with a
// write model beside it is analyzed with one and its matches become findings.
// A YAML that is not a write model, a validation file among them, is left
// alone; a write model that does not hold together is an error named to the
// user.
func discoverWriteModels(files []*spicedb.File) (map[string]*zanzibar.WriteModel, error) {
	models := map[string]*zanzibar.WriteModel{}
	for _, dir := range spiceDirs(files) {
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

// spiceDirs is the distinct directories the schemas live in, in a stable order.
func spiceDirs(files []*spicedb.File) []string {
	var dirs []string
	for _, f := range files {
		dir := path.Dir(f.SchemaPath)
		if !slices.Contains(dirs, dir) {
			dirs = append(dirs, dir)
		}
	}
	return dirs
}

// policyPaths are the paths left for the policy loader once the SpiceDB files
// named one by one are taken out. A schema named on the command line is not a
// Rego file, and the loader reads every file it is handed as one; a directory
// stays, since the loader takes only the Rego files under it.
func policyPaths(paths []string, files []*spicedb.File) []string {
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

// counts are the matches by pattern, the way the summary of a policy counts
// its findings.
func (r spiceDBRun) counts(patterns []taxonomy.Pattern) []patternCount {
	byID := map[string]*patternCount{}
	for _, m := range r.matches {
		c, ok := byID[m.PatternID]
		if !ok {
			c = &patternCount{id: m.PatternID, title: titleOf(patterns, m.PatternID)}
			byID[m.PatternID] = c
		}
		if m.Verdict == zanzibar.Finding {
			c.findings++
		} else {
			c.candidates++
		}
	}
	out := make([]patternCount, 0, len(byID))
	for _, c := range byID {
		out = append(out, *c)
	}
	slices.SortFunc(out, func(a, b patternCount) int { return strings.Compare(a.id, b.id) })
	return out
}

// exitCode is the exit code the matches alone ask for, decided by the rule the
// findings of a policy are decided by.
func (r spiceDBRun) exitCode(failOn string) int {
	return exitCode(summary{byPattern: r.counts(nil)}, failOn)
}

// printSpiceDB says what the SpiceDB files declare and what the patterns found
// in them. Quiet, it prints the matches alone, and nothing when there are none.
func printSpiceDB(out io.Writer, r spiceDBRun, patterns []taxonomy.Pattern, p printing) {
	style := p.style
	if p.quiet && len(r.matches) == 0 {
		return
	}
	if !p.quiet {
		fmt.Fprintln(out, style.Bold(render.Count(len(r.files), "SpiceDB file")))
		tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		for _, f := range r.files {
			fmt.Fprintf(tw, "  %s\t%s\n", f.Path, describeSpiceDB(f))
		}
		tw.Flush()
	}

	counts := r.counts(patterns)
	printCounts(out, headingFindings, counts, style, sayNothing, func(c patternCount) int { return c.findings })
	printCounts(out, headingCandidates, counts, style, stayQuiet, func(c patternCount) int { return c.candidates })
	for _, m := range r.matches {
		printMatch(out, m, style)
	}

	if p.quiet {
		return
	}
	for _, path := range r.unread {
		fmt.Fprintln(out)
		render.Print(out, path+" is read by no validation file under the paths, so the patterns had "+
			"no relationship and no check to take evidence from.", "")
	}
}

// matchLabelWidth is how wide the labels of a match are printed, so that the
// text of every line starts in the same column.
const matchLabelWidth = 12

// printMatch prints one match under its subject, a line per detail.
func printMatch(out io.Writer, m zanzibar.Match, style render.Style) {
	fmt.Fprintf(out, "\n  %s  (%s)\n", style.Bold(m.Subject), m.PatternID)
	hanging := strings.Repeat(" ", 4+matchLabelWidth+1)
	for _, d := range m.Details {
		lines := render.Wrap(d.Text, hanging)
		if len(lines) == 0 {
			continue
		}
		lines[0] = fmt.Sprintf("    %-*s %s", matchLabelWidth, d.Label, strings.TrimPrefix(lines[0], hanging))
		for _, line := range lines {
			fmt.Fprintln(out, line)
		}
	}
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
