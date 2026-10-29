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
	"github.com/saluc28/petard/internal/cli/spicesetup"
	"github.com/saluc28/petard/internal/taxonomy"
	"github.com/saluc28/petard/internal/zanzibar"
	"github.com/saluc28/petard/internal/zanzibar/spicedb"
)

// spiceDBRun is what the patterns of the Zanzibar engine made of the SpiceDB
// files under the analyzed paths.
type spiceDBRun struct {
	files   []*spicedb.File
	matches []zanzibar.Match

	// unread are the schema files that no validation file reads and that have no
	// write model beside them, so the patterns have no rule for who writes their
	// relations and no relationship or check to take as evidence. A schema with a
	// write model is analyzed from the positions generated from it instead, and
	// does not appear here.
	unread []string

	// proposals are, per schema, the safe gates for the relations its write model
	// leaves without a rule, or every writable relation when it has no write
	// model: the write model petard proposes for the author to confirm (section 6
	// of the definitions).
	proposals []schemaProposals
}

// schemaProposals are the safe-gate proposals for one schema, with the model
// the skeleton reads each relation's allowed subjects and caveats from.
type schemaProposals struct {
	schema    string
	model     *zanzibar.Model
	proposals []zanzibar.GateProposal
}

// runSpiceDB applies the patterns of the Zanzibar engine to the SpiceDB files
// found. A schema a validation file reads is analyzed with that file; a schema
// no validation file reads is analyzed from the positions generated from it
// when a write model stands beside it, so findings surface without a validation
// file written by hand. Found.Analyses decides which, so analyze and export read
// the same schemas the same way.
//
// A schema read by two validation files is one schema, and a fact about it is
// reported once: the first file that shows it, in the order the files sort,
// is the one the report cites.
func runSpiceDB(found spicesetup.Found, now time.Time, propose bool) (spiceDBRun, error) {
	run := spiceDBRun{files: found.Files}
	analyses, noEvidence := found.Analyses(now)
	run.unread = noEvidence

	seen := map[string]bool{}
	for _, a := range analyses {
		for _, m := range zanzibar.Run(a.Sample, a.WriteModel) {
			key := m.PatternID + "\x00" + a.SchemaPath + "\x00" + m.Subject
			if seen[key] {
				continue
			}
			seen[key] = true
			run.matches = append(run.matches, m)
		}
	}
	// Safe gates are proposed per schema, so the author sees which gate to fill
	// in even from a schema with no write model and no validation file. The
	// closure they run is skipped when a quiet run will neither show nor
	// serialize them, so a pipeline run does not pay for them.
	if propose {
		props, err := spiceProposals(found.Files, found.WriteModels)
		if err != nil {
			return spiceDBRun{}, err
		}
		run.proposals = props
	}
	return run, nil
}

// spiceProposals are, per schema among the files, the safe gates SafeGates finds
// for the relations its write model leaves without a rule. The gates rest on the
// positions generated from the schema, so a schema with no write model yields a
// skeleton for every writable relation, and one needs no validation file. A
// schema whose write model already rules every relation leaves nothing to
// propose and does not appear. One entry per schema, in the order the files
// sort, so the same inputs print the same bytes.
func spiceProposals(files []*spicedb.File, writeModels map[string]*zanzibar.WriteModel) ([]schemaProposals, error) {
	var out []schemaProposals
	done := map[string]bool{}
	for _, f := range files {
		if done[f.SchemaPath] {
			continue
		}
		done[f.SchemaPath] = true
		wm := writeModels[path.Dir(f.SchemaPath)]
		if wm == nil {
			// No write model yet: propose a gate for every writable relation, the
			// skeleton the author starts from, rather than nothing.
			wm = &zanzibar.WriteModel{}
		}
		gates, err := zanzibar.SafeGates(f.Schema.Model, wm, f.Schema, zanzibar.Options{})
		if err != nil {
			return nil, err
		}
		if len(gates) > 0 {
			out = append(out, schemaProposals{schema: f.SchemaPath, model: f.Schema.Model, proposals: gates})
		}
	}
	return out, nil
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

// hasEvidence reports whether any match carries a line -v would add, so the
// footer offers -v only where it shows something the first screen did not.
func (r spiceDBRun) hasEvidence() bool {
	for _, m := range r.matches {
		for _, d := range m.Details {
			if d.Verbose {
				return true
			}
		}
	}
	return false
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
		printMatch(out, m, style, p.verbose)
	}

	if p.quiet {
		return
	}
	printProposals(out, r.proposals, style)
	for _, path := range r.unread {
		fmt.Fprintln(out)
		render.Print(out, path+" has no write model and is read by no validation file under the paths, "+
			"so the patterns had no rule for who writes its relations and no relationship or check to take as evidence.", "")
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
			switch {
			case len(p.Safe) > 0:
				fmt.Fprintf(tw, "  %s\tsafe to gate on %s\n", rel, strings.Join(p.Safe, ", "))
			case len(p.Unsafe) > 0:
				fmt.Fprintf(tw, "  %s\tno safe gate: every permission lets a coalition escalate\n", rel)
			case len(p.Raises) > 0:
				fmt.Fprintf(tw, "  %s\tno permission on %s to gate on; writing it raises %s\n", rel, p.Type, strings.Join(p.Raises, ", "))
			default:
				fmt.Fprintf(tw, "  %s\tnothing to gate: writing it raises no permission\n", rel)
			}
		}
		tw.Flush()
	}
}

// matchLabelWidth is how wide the labels of a match are printed, so that the
// text of every line starts in the same column.
const matchLabelWidth = 12

// printMatch prints one match under its subject, a line per detail. A detail
// marked verbose is the evidence behind the finding, printed only under -v, so
// the default report is the claim and -v is the proof.
func printMatch(out io.Writer, m zanzibar.Match, style render.Style, verbose bool) {
	fmt.Fprintf(out, "\n  %s  (%s)\n", style.Bold(m.Subject), m.PatternID)
	hanging := strings.Repeat(" ", 4+matchLabelWidth+1)
	for _, d := range m.Details {
		if d.Verbose && !verbose {
			continue
		}
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
