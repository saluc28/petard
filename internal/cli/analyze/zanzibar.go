package analyze

import (
	"cmp"
	"fmt"
	"io"
	"path"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/saluc28/petard/internal/cli/render"
	"github.com/saluc28/petard/internal/cli/zanzibarsetup"
	"github.com/saluc28/petard/internal/taxonomy"
	"github.com/saluc28/petard/internal/zanzibar"
)

// zanzibarRun is what the patterns of the Zanzibar engine made of the schema files
// under the analyzed paths.
type zanzibarRun struct {
	files   []*zanzibarsetup.File
	matches []zanzibar.Match

	// causes are the matches that are escalations, by the write rule behind them.
	causes []causeGroup

	// limits say where the analysis stopped short of weighing everything.
	limits zanzibar.Limits

	// unread are the schema files that no validation file or store file reads and
	// that have no write model beside them, so the patterns have no rule for who
	// writes their relations and no relationship or check to take as evidence. A
	// schema with a write model is analyzed from the positions generated from it
	// instead, and does not appear here.
	unread []*zanzibarsetup.File

	// proposals are, per schema, the safe gates for the relations its write model
	// leaves without a rule, or every writable relation when it has no write
	// model: the write model petard proposes for the author to confirm (section 6
	// of the definitions).
	proposals []schemaProposals
}

// schemaProposals are the safe-gate proposals for one schema, with the model
// the skeleton reads each relation's allowed subjects and caveats from.
type schemaProposals struct {
	product   zanzibarsetup.Product
	schema    string
	model     *zanzibar.Model
	proposals []zanzibar.GateProposal
}

// runZanzibar applies the patterns of the Zanzibar engine to the schema files
// found. A schema a validation file reads is analyzed with that file; a schema
// no validation file reads is analyzed from the positions generated from it
// when a write model stands beside it, so findings surface without a validation
// file written by hand. Found.Analyses decides which, so analyze and export read
// the same schemas the same way.
//
// A schema read by two validation files is one schema, and a fact about it is
// reported once: the first file that shows it, in the order the files sort,
// is the one the report cites.
func runZanzibar(found zanzibarsetup.Found, now time.Time, propose bool) (zanzibarRun, error) {
	run := zanzibarRun{files: found.Files}
	analyses, noEvidence := found.Analyses(now)
	run.unread = noEvidence

	seen := map[string]bool{}
	causes := causesOf{}
	for _, a := range analyses {
		matches, limits := zanzibar.RunWithLimits(a.Sample, a.WriteModel)
		run.limits.Add(limits)
		for _, m := range matches {
			key := m.PatternID + "\x00" + a.SchemaPath + "\x00" + m.Subject
			if seen[key] {
				continue
			}
			seen[key] = true
			run.matches = append(run.matches, m)
			causes.add(a.SchemaPath, m)
		}
	}
	run.causes = causes.groups()
	// Safe gates are proposed per schema, so the author sees which gate to fill
	// in even from a schema with no write model and no validation file. The
	// closure they run is skipped when a quiet run will neither show nor
	// serialize them, so a pipeline run does not pay for them.
	if propose {
		props, err := proposalsOf(found.Files, found.WriteModels)
		if err != nil {
			return zanzibarRun{}, err
		}
		run.proposals = props
	}
	return run, nil
}

// proposalsOf are, per schema among the files, the safe gates SafeGates finds
// for the relations its write model leaves without a rule. The gates rest on the
// positions generated from the schema, so a schema with no write model yields a
// skeleton for every writable relation, and one needs no validation file. A
// schema whose write model already rules every relation leaves nothing to
// propose and does not appear. One entry per schema, in the order the files
// sort, so the same inputs print the same bytes.
func proposalsOf(files []*zanzibarsetup.File, writeModels map[string]*zanzibar.WriteModel) ([]schemaProposals, error) {
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
		gates, err := zanzibar.SafeGates(f.Model, wm, f.Caveats, zanzibar.Options{})
		if err != nil {
			return nil, err
		}
		if len(gates) > 0 {
			out = append(out, schemaProposals{product: f.Product, schema: f.SchemaPath, model: f.Model, proposals: gates})
		}
	}
	return out, nil
}

// counts are the matches by pattern, the way the summary of a policy counts
// its findings.
func (r zanzibarRun) counts(patterns []taxonomy.Pattern) []patternCount {
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
func (r zanzibarRun) exitCode(failOn string) int {
	return exitCode(summary{byPattern: r.counts(nil)}, failOn)
}

// hasEvidence reports whether any match carries a line -v would add, so the
// footer offers -v only where it shows something the first screen did not.
func (r zanzibarRun) hasEvidence() bool {
	for _, m := range r.matches {
		for _, d := range m.Details {
			if d.Verbose {
				return true
			}
		}
	}
	return false
}

// printZanzibar says what the schema files declare and what the patterns found in
// them. Quiet, it prints the matches alone, and nothing when there are none.
func printZanzibar(out io.Writer, r zanzibarRun, patterns []taxonomy.Pattern, p printing) {
	style := p.style
	if p.quiet && len(r.matches) == 0 {
		return
	}
	if !p.quiet {
		printFiles(out, r.files, style)
	}

	counts := r.counts(patterns)
	printCounts(out, headingFindings, counts, style, sayNothing, func(c patternCount) int { return c.findings })
	printCounts(out, headingCandidates, counts, style, stayQuiet, func(c patternCount) int { return c.candidates })
	for _, m := range r.matches {
		if m.Raise == nil {
			printMatch(out, m, style, p.verbose)
		}
	}
	namesSchema := spansSchemas(r.causes)
	for _, g := range r.causes {
		printCause(out, g, namesSchema, style, p.verbose)
	}

	if p.quiet {
		return
	}
	for _, line := range r.limits.Lines() {
		fmt.Fprintln(out)
		render.Print(out, line, "")
	}
	printProposals(out, r.proposals, style)
	for _, f := range r.unread {
		fmt.Fprintln(out)
		render.Print(out, f.Path+" has no write model and is read by no "+holderOf(f)+" under the paths, "+
			"so the patterns had no rule for who writes its relations and no "+relationshipOf(f)+" or check to take as evidence.", "")
	}
}

// printFiles lists the files of each product under a heading of its own.
func printFiles(out io.Writer, files []*zanzibarsetup.File, style render.Style) {
	var products []zanzibarsetup.Product
	for _, f := range files {
		if !slices.Contains(products, f.Product) {
			products = append(products, f.Product)
		}
	}
	slices.Sort(products)
	for _, product := range products {
		of := slices.DeleteFunc(slices.Clone(files), func(f *zanzibarsetup.File) bool { return f.Product != product })
		// A store file whose tests bring tuples of their own is read once for each
		// of them, and it is one file.
		paths := map[string]bool{}
		for _, f := range of {
			paths[f.Path] = true
		}
		fmt.Fprintln(out, style.Bold(render.Count(len(paths), string(product)+" file")))
		tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		for _, f := range of {
			fmt.Fprintf(tw, "  %s\t%s\n", f.Path, describeFile(f))
		}
		tw.Flush()
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
	for _, d := range m.Details {
		if d.Verbose && !verbose {
			continue
		}
		printLabelled(out, d.Label, d.Text)
	}
}

// printLabelled prints a line of a match under its label, wrapped so that what runs
// on lines up with the text.
func printLabelled(out io.Writer, label, text string) {
	hanging := strings.Repeat(" ", 4+matchLabelWidth+1)
	lines := render.Wrap(text, hanging)
	if len(lines) == 0 {
		return
	}
	lines[0] = fmt.Sprintf("    %-*s %s", matchLabelWidth, label, strings.TrimPrefix(lines[0], hanging))
	for _, line := range lines {
		fmt.Fprintln(out, line)
	}
}

// causeGroup is the escalations one write rule opens in one schema, a rule being what
// somebody changes. A raise is told under the rule of the witness kept, so one with another
// way up comes back under that way's rule once this one changes.
type causeGroup struct {
	schema, cause string
	matches       []zanzibar.Match
}

// causesOf gathers escalations by schema and rule. Two schemas are kept apart even
// when their rules read alike, since a rule of one says nothing about the other.
type causesOf map[[2]string]*causeGroup

func (c causesOf) add(schema string, m zanzibar.Match) {
	if m.Raise == nil {
		return
	}
	key := [2]string{schema, m.Raise.Cause}
	if c[key] == nil {
		c[key] = &causeGroup{schema: schema, cause: m.Raise.Cause}
	}
	c[key].matches = append(c[key].matches, m)
}

// groups are the rules with the one that opens the most first, since that is the
// one to change first. Ties break on the words, so the same inputs print the same
// bytes.
func (c causesOf) groups() []causeGroup {
	out := make([]causeGroup, 0, len(c))
	for _, g := range c {
		out = append(out, *g)
	}
	slices.SortFunc(out, func(a, b causeGroup) int {
		return cmp.Or(
			cmp.Compare(len(b.matches), len(a.matches)),
			cmp.Compare(a.schema, b.schema),
			cmp.Compare(a.cause, b.cause),
		)
	})
	return out
}

// spansSchemas says whether the groups come from more than one schema, which is when
// a group has to say which it comes from.
func spansSchemas(groups []causeGroup) bool {
	return slices.ContainsFunc(groups, func(g causeGroup) bool { return g.schema != groups[0].schema })
}

// printCause prints a write rule and, for each pattern that reads a raise out of it,
// what it raises. Permissions that rise the same way share a line. What is true of
// only some of them stays on a line of its own, so nothing a match says is lost; a
// witness is evidence, printed under -v, and one that several permissions share is
// printed once.
func printCause(out io.Writer, g causeGroup, namesSchema bool, style render.Style, verbose bool) {
	fmt.Fprintln(out)
	for _, line := range render.Wrap(g.cause, "  ") {
		fmt.Fprintln(out, style.Bold(line))
	}
	if namesSchema {
		printLabelled(out, "in", g.schema)
	}

	var patterns []string
	byPattern := map[string][]zanzibar.Match{}
	for _, m := range g.matches {
		if byPattern[m.PatternID] == nil {
			patterns = append(patterns, m.PatternID)
		}
		byPattern[m.PatternID] = append(byPattern[m.PatternID], m)
	}
	for _, id := range patterns {
		of := byPattern[id]
		printLabelled(out, id, of[0].Raise.Kind)
		for _, line := range raiseLines(of) {
			printLabelled(out, "raises", line)
		}
		for _, d := range sharedDetails(of) {
			printLabelled(out, d.Label, d.Text)
		}
		if verbose {
			printWitnesses(out, of)
		}
	}
}

// raiseLines says what the matches raise, one line per type and pair of levels.
func raiseLines(of []zanzibar.Match) []string {
	type rise struct {
		typ           string
		before, after zanzibar.Level
	}
	var order []rise
	names := map[rise][]string{}
	for _, m := range of {
		r := rise{m.Raise.Type, m.Raise.Before, m.Raise.After}
		if names[r] == nil {
			order = append(order, r)
		}
		names[r] = append(names[r], m.Raise.Permission)
	}
	lines := make([]string, 0, len(order))
	for _, r := range order {
		lines = append(lines, fmt.Sprintf("%s on %s, from %s to %s", render.List(names[r]), r.typ, r.before, r.after))
	}
	return lines
}

// sharedDetails are the lines the matches print on the first screen beside what they
// raise, each once.
func sharedDetails(of []zanzibar.Match) []zanzibar.Detail {
	var details []zanzibar.Detail
	for _, m := range of {
		for _, d := range m.Details {
			if !d.Verbose && !slices.Contains(details, d) {
				details = append(details, d)
			}
		}
	}
	return details
}

// printWitnesses prints the writes behind the matches, each witness once. When
// permissions rise through different writes, each witness says which it is for.
func printWitnesses(out io.Writer, of []zanzibar.Match) {
	var order []string
	steps := map[string][]string{}
	names := map[string][]string{}
	for _, m := range of {
		var witness []string
		for _, d := range m.Details {
			if d.Verbose {
				witness = append(witness, d.Text)
			}
		}
		key := strings.Join(witness, "\n")
		if names[key] == nil {
			order = append(order, key)
			steps[key] = witness
		}
		names[key] = append(names[key], m.Raise.Permission)
	}
	label := "path"
	for _, key := range order {
		if len(order) > 1 {
			printLabelled(out, label, "for "+render.List(names[key])+":")
			label = ""
		}
		for _, step := range steps[key] {
			printLabelled(out, label, step)
			label = ""
		}
	}
}

// relationshipOf is the word for what is stored against a schema of the product of f.
func relationshipOf(f *zanzibarsetup.File) string {
	if f.Product == zanzibarsetup.OpenFGA {
		return "tuple"
	}
	return "relationship"
}

// holderOf is the word for a file that holds a schema of the product of f.
func holderOf(f *zanzibarsetup.File) string {
	if f.Product == zanzibarsetup.OpenFGA {
		return "store file"
	}
	return "validation file"
}

func describeFile(f *zanzibarsetup.File) string {
	if f.Product == zanzibarsetup.OpenFGA {
		return describeOpenFGA(f)
	}
	m := f.Model
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
	if !f.Holds {
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

// describeOpenFGA says what an OpenFGA file declares and holds, in the words of the
// product. A name that is written and asked counts once.
func describeOpenFGA(f *zanzibarsetup.File) string {
	m := f.Model
	relations := 0
	for _, t := range m.Types {
		relations += len(t.Relations)
		for _, p := range t.Permissions {
			if t.Relation(p.Name) == nil {
				relations++
			}
		}
	}
	declares := strings.Join([]string{
		render.Count(len(m.Types), "type"),
		render.Count(relations, "relation"),
		render.Count(len(m.Caveats), "condition"),
	}, ", ")
	if !f.Holds {
		return declares
	}

	holds := []string{render.Count(len(f.Relationships), "tuple"), render.Count(len(f.Assertions), "check")}
	if f.Test != "" {
		holds = append([]string{"test " + f.Test}, holds...)
	}
	if f.SchemaPath != f.Path {
		return fmt.Sprintf("store file of %s, %s", f.SchemaPath, strings.Join(holds, ", "))
	}
	return fmt.Sprintf("store file, %s; %s", strings.Join(holds, ", "), declares)
}
