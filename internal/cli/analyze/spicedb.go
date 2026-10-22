package analyze

import (
	"fmt"
	"io"
	"path"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/saluc28/petard/internal/cli/render"
	"github.com/saluc28/petard/internal/taxonomy"
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

	// proposals are, per schema with a write model, the safe gates for the
	// relations the model leaves without a rule: the write model petard proposes
	// for the author to confirm (section 6 of the definitions).
	proposals []schemaProposals
}

// schemaProposals are the safe-gate proposals for one schema.
type schemaProposals struct {
	schema    string
	proposals []zanzibar.GateProposal
}

// runSpiceDB applies the patterns of the Zanzibar engine to every file found.
//
// A schema read by two validation files is one schema, and a fact about it is
// reported once: the first file that shows it, in the order the files sort,
// is the one the report cites.
func runSpiceDB(files []*spicedb.File, now time.Time, writeModels map[string]*zanzibar.WriteModel, propose bool) (spiceDBRun, error) {
	run := spiceDBRun{files: files}
	read := map[string]bool{}
	seen := map[string]bool{}
	proposed := map[string]bool{}
	for _, f := range files {
		if !f.Validation {
			continue
		}
		read[f.SchemaPath] = true
		wm := writeModels[path.Dir(f.SchemaPath)]
		sample := f.Sample(now)
		for _, m := range zanzibar.Run(sample, wm) {
			key := m.PatternID + "\x00" + f.SchemaPath + "\x00" + m.Subject
			if seen[key] {
				continue
			}
			seen[key] = true
			run.matches = append(run.matches, m)
		}
		// Safe gates are proposed where a write model leaves relations without a
		// rule, once per schema, so the author sees which gate to fill in. The
		// closure they run is skipped when nothing will show or serialize them, so
		// a quiet pipeline run does not pay for them.
		if propose && wm != nil && !proposed[f.SchemaPath] {
			proposed[f.SchemaPath] = true
			gates, err := zanzibar.SafeGates(sample.Model, wm, sample.Caveats, zanzibar.Options{})
			if err != nil {
				return spiceDBRun{}, err
			}
			if len(gates) > 0 {
				run.proposals = append(run.proposals, schemaProposals{schema: f.SchemaPath, proposals: gates})
			}
		}
	}
	for _, f := range files {
		if !f.Validation && !read[f.Path] {
			run.unread = append(run.unread, f.Path)
		}
	}
	return run, nil
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
	printProposals(out, r.proposals, style)
	for _, path := range r.unread {
		fmt.Fprintln(out)
		render.Print(out, path+" is read by no validation file under the paths, so the patterns had "+
			"no relationship and no check to take evidence from.", "")
	}
}

// printProposals prints, per schema, the relations the write model leaves
// without a rule and the permission that is a safe gate to write each, the write
// model petard proposes for the author to confirm.
func printProposals(out io.Writer, groups []schemaProposals, style render.Style) {
	for _, g := range groups {
		fmt.Fprintln(out)
		heading := "Relations with no write rule"
		if len(groups) > 1 {
			heading += ", in " + g.schema
		}
		fmt.Fprintln(out, style.Bold(heading))
		tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		for _, p := range g.proposals {
			rel := p.Type + "#" + p.Relation
			if len(p.Safe) > 0 {
				fmt.Fprintf(tw, "  %s\tsafe to gate on %s\n", rel, strings.Join(p.Safe, ", "))
			} else {
				fmt.Fprintf(tw, "  %s\tno safe gate: any lets a coalition escalate\n", rel)
			}
		}
		tw.Flush()
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
