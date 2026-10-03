package analyze

import (
	"fmt"
	"io"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/saluc28/petard/internal/cli/render"
	"github.com/saluc28/petard/internal/taxonomy"
)

// This file is the first screen of an analysis: the escalations, what was
// found, and how much of it to believe. The rest of the report is the evidence
// for it, and evidence is what somebody asks for after they have understood the
// claim, which is why it sits behind -v.
//
// Nothing here composes a new sentence out of a finding's fields. Each pattern
// writes its own fact, and a printer guessing at what a decision and a path
// mean together would be guessing at the very thing each pattern exists to
// state. What this does is arrange: who over whom first, counts second,
// evidence on request.

// summary is what the first screen needs, worked out once so that printing it
// cannot disagree with counting it.
type summary struct {
	escalations []taxonomy.Finding
	byPattern   []patternCount
	skipped     []skippedPattern

	// questions are the paths a candidate rests on that nobody declared a writer
	// for, which is what a reader does next to settle them.
	questions []taxonomy.Question
}

// patternCount is one pattern and what it made of this bundle.
type patternCount struct {
	id, title  string
	findings   int
	candidates int
}

type skippedPattern struct {
	id, why string
}

// summarize sorts the results into the shape the first screen prints.
//
// Everything is ordered by the id of the pattern, because two runs of the same
// bundle have to print the same bytes: the counts and the skipped patterns come
// out of maps, and Go walks a map in a different order every time.
func summarize(a taxonomy.Analysis, findings taxonomy.Findings, patterns []taxonomy.Pattern) summary {
	var s summary

	counts := map[string]*patternCount{}
	for _, finding := range findings.All() {
		count, seen := counts[finding.PatternID]
		if !seen {
			count = &patternCount{id: finding.PatternID, title: titleOf(patterns, finding.PatternID)}
			counts[finding.PatternID] = count
		}
		if finding.Verdict == taxonomy.VerdictCandidate {
			count.candidates++
		} else {
			count.findings++
		}

		// The same rule the graph uses for a PTD_CanEscalateTo, so that the
		// terminal and BloodHound cannot come to different conclusions about
		// who can take whose place. A candidate has a target but has not proven
		// the reach, so it is a candidate below rather than an escalation here.
		if finding.Verdict == taxonomy.VerdictFinding && finding.Principal != "" && finding.Target != "" {
			s.escalations = append(s.escalations, finding)
		}
	}

	s.byPattern = make([]patternCount, 0, len(counts))
	for _, count := range counts {
		s.byPattern = append(s.byPattern, *count)
	}
	slices.SortFunc(s.byPattern, func(a, b patternCount) int { return strings.Compare(a.id, b.id) })
	slices.SortStableFunc(s.escalations, func(a, b taxonomy.Finding) int {
		return strings.Compare(a.PatternID, b.PatternID)
	})

	for id, why := range findings.Skipped {
		s.skipped = append(s.skipped, skippedPattern{id: id, why: why})
	}
	slices.SortFunc(s.skipped, func(a, b skippedPattern) int { return strings.Compare(a.id, b.id) })

	s.questions = taxonomy.OpenQuestions(a, findings)
	return s
}

// findings and candidates are the totals the exit code is decided on.
func (s summary) findings() int {
	total := 0
	for _, count := range s.byPattern {
		total += count.findings
	}
	return total
}

func (s summary) candidates() int {
	total := 0
	for _, count := range s.byPattern {
		total += count.candidates
	}
	return total
}

// empty is a run with nothing to report, which is the run quiet says nothing
// about. An escalation is a finding, so the two totals cover it.
func (s summary) empty() bool {
	return s.findings()+s.candidates() == 0
}

// printing is how much of the report to print, and how.
//
// Quiet keeps the escalations and the findings and drops everything around
// them, for the pipeline that wants a line in the log when something is found
// and silence when nothing is. Verbose is the evidence below, which the
// summary knows about only so that it does not offer what is already there.
type printing struct {
	style   render.Style
	quiet   bool
	verbose bool
}

// printSummary writes the first screen.
func printSummary(out io.Writer, a taxonomy.Analysis, s summary, coverage taxonomy.Coverage, p printing) {
	style, quiet := p.style, p.quiet
	if quiet && s.empty() {
		return
	}

	if !quiet {
		fmt.Fprintf(out, "%s, %s, parsed as rego %s\n",
			count(len(a.Bundle.Files), "file"), count(len(a.Reads.Decisions), "decision"),
			a.Bundle.RegoVersion)
	}

	printEscalations(out, s.escalations, style, a.Model != nil)
	printCounts(out, headingFindings, s.byPattern, style, sayNothing, func(c patternCount) int { return c.findings })
	printCounts(out, headingCandidates, s.byPattern, style, stayQuiet, func(c patternCount) int { return c.candidates })

	if quiet {
		return
	}

	printScopeNote(out, a, s, style)
	printQuestions(out, s.questions, style)

	if len(s.skipped) > 0 {
		fmt.Fprintf(out, "\n%s\n", style.Bold("Patterns that did not run"))
		for _, skipped := range s.skipped {
			fmt.Fprintf(out, "  %s  %s\n", skipped.id, skipped.why)
		}
	}

	printTrust(out, a, coverage, style)

	fmt.Fprintln(out)
	if !p.verbose {
		fmt.Fprint(out, "Run with -v for the reads behind this, and every place to look.\n")
	}
	fmt.Fprint(out, "Run petard explain <id> for what a pattern looks for and what it will not report.\n")
}

// printQuestions names the paths a candidate rests on that nobody declared a
// writer for, so a reader sees what to find out next instead of a bare count of
// candidates. Each line is the path, what to ask about it, and the patterns it
// would settle.
func printQuestions(out io.Writer, questions []taxonomy.Question, style render.Style) {
	if len(questions) == 0 {
		return
	}

	fmt.Fprintf(out, "\n%s\n", style.Bold("Questions, which turn candidates into findings"))
	fmt.Fprintln(out, "  Declare who writes each path in a write model, or write one to fill in with -questions <file>.")
	table := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	for _, question := range questions {
		fmt.Fprintf(table, "  %s\t%s\t(%s)\n", question.Path, question.Asks(), strings.Join(question.Patterns, ", "))
	}
	table.Flush()
}

// printScopeNote explains a result that comes from the shape of the policy
// rather than from a clean bundle. When the decisions read no data document,
// the patterns that ask who can write the data a decision trusts have nothing
// to weigh, and a reader is owed the difference between that and a verdict that
// the policy is safe. The common case is an admission or validation policy,
// which decides on the request it is handed and consults no stored document.
func printScopeNote(out io.Writer, a taxonomy.Analysis, s summary, style render.Style) {
	if len(a.Reads.Reads) > 0 {
		return
	}

	fmt.Fprintf(out, "\n%s\n", style.Bold("These decisions read no data"))
	render.Print(out, "The patterns that ask who can write the data a decision trusts need a data "+
		"document to work on, and these decisions read none.", "  ")

	switch {
	case len(a.Reads.Taints) > 0:
		render.Print(out, "They do read values from outside the policy, which are the external-source "+
			"patterns rather than the write model.", "  ")
	case len(a.Reads.InputPaths) == 0:
		render.Print(out, "They read neither the request nor any data.", "  ")
	default:
		render.Print(out, fmt.Sprintf("They decide on the request alone, over %s.",
			count(len(a.Reads.InputPaths), "input path")), "  ")
	}

	if s.empty() {
		render.Print(out, "An empty result here reflects the shape of the policy, not a verdict that it is safe.", "  ")
	}
	if a.EnforcementPoint == nil {
		render.Print(out, "If the caller controls part of the request, name the enforcement point with -pep, "+
			"and the request-side patterns can speak to it.", "  ")
	}
	render.Print(out, "See docs/ten-minutes.md for a policy Petard is built for, worked end to end.", "  ")
}

// printEscalations puts who can take whose place at the top, because it is the
// one result that is about people rather than about the policy, and the reason
// somebody ran this rather than a linter.
func printEscalations(out io.Writer, escalations []taxonomy.Finding, style render.Style, model bool) {
	fmt.Fprintf(out, "\n%s\n", style.Bold("Escalations"))
	if len(escalations) == 0 {
		if !model {
			fmt.Fprintln(out, "  none named: without a write model nobody is declared able to write,")
			fmt.Fprintln(out, "  so a chain that would escalate stays a candidate below.")
			return
		}
		fmt.Fprintln(out, "  none")
		return
	}

	for i, escalation := range escalations {
		if i > 0 {
			fmt.Fprintln(out)
		}
		fmt.Fprintf(out, "  %s  (%s, confidence %s)\n",
			style.Bold(escalation.Principal+" -> "+escalation.Target),
			escalation.PatternID, escalation.Confidence)
		for _, line := range []struct{ label, value string }{
			{"writes", written(escalation)},
			{"through", escalation.Via},
			{"allowed by", escalation.AuthorizedBy},
			{"in", escalation.Decision},
			{"proven by", provenBy(escalation)},
		} {
			if line.value != "" {
				fmt.Fprintf(out, "    %-10s %s\n", line.label, line.value)
			}
		}
	}
}

// written is what the principal puts where. The value is part of it for the
// pattern that knows which one opens the door, and left out by the ones whose
// fact is the path alone.
func written(escalation taxonomy.Finding) string {
	if escalation.ViaWritePath == "" {
		return ""
	}
	if escalation.Value != "" {
		return escalation.Value + " into " + escalation.ViaWritePath
	}
	return escalation.ViaWritePath
}

// provenBy is the request of the witness, which the decision refuses today and
// grants after the write. The write itself is in the evidence under -v.
func provenBy(escalation taxonomy.Finding) string {
	if escalation.Witness == nil {
		return ""
	}
	return taxonomy.JSON(escalation.Witness.Request)
}

// What an empty section does. A run that found no findings has to say so, since
// the reader is entitled to the difference between a clean bundle and a section
// somebody forgot to print; a run with no candidates has nothing to say, since
// candidates are what is left over rather than a result of their own.
const (
	sayNothing = true
	stayQuiet  = false
)

const (
	headingFindings   = "Findings"
	headingCandidates = "Candidates, which need a write model to become findings"
)

// printCounts prints one line per pattern that has something, with the count
// first: the number is what the eye is looking for, and a title it has to read
// past to find it is a title in the way.
func printCounts(out io.Writer, heading string, counts []patternCount, style render.Style, whenEmpty bool, of func(patternCount) int) {
	var printed int
	for _, count := range counts {
		if of(count) == 0 {
			continue
		}
		if printed == 0 {
			fmt.Fprintf(out, "\n%s\n", style.Bold(heading))
		}
		printed++
		fmt.Fprintf(out, "  %3d  %s  %s\n", of(count), count.id, count.title)
	}
	if printed == 0 && whenEmpty {
		fmt.Fprintf(out, "\n%s\n  nothing\n", style.Bold(heading))
	}
}

// printTrust is the line that says how much of this to believe.
//
// It is one line because it is read as one thing: the subject the whole
// analysis rests on, how much of the policy was actually read, and how much of
// what it reads anybody declared a writer for. A report that states findings
// and hides what they stand on is asking to be believed rather than checked.
func printTrust(out io.Writer, a taxonomy.Analysis, coverage taxonomy.Coverage, style render.Style) {
	fmt.Fprintf(out, "\n%s\n", style.Bold("How much to trust this"))

	subject := "the subject was not recognized"
	if a.Shape.Subject != "" {
		subject = "the subject is " + a.Shape.Subject
	}
	render.Print(out, fmt.Sprintf("Level %s (%s): %s. %d reads over %d data paths.",
		a.Shape.Confidence, a.Shape.Recognizer, subject, len(a.Reads.Reads), len(coverage.Read)), "  ")

	if a.DecisionsInferred {
		render.Print(out, "No rule is annotated as an entrypoint and none was declared, so every rule no "+
			"other rule uses is taken as a decision. If the enforcement point queries others, name them "+
			"with -entrypoint.", "  ")
	}
	if a.DataFromBundle {
		render.Print(out, fmt.Sprintf("The data is what the bundle carries, %s called data.json, data.yaml "+
			"or data.yml. -data replaces it.", count(len(a.Data.Files), "file")), "  ")
	}
	if a.DataFromLive {
		render.Print(out, fmt.Sprintf("The data is what the running OPA holds, read over its API for the %s "+
			"the decisions read. -data replaces it.", count(len(a.Data.Files), "root")), "  ")
	}

	if point := a.EnforcementPoint; point != nil {
		request := taxonomy.RequestCoverageOf(a.Reads, point)
		render.Print(out, fmt.Sprintf("The enforcement point is %s: it says who sets %d of the %s of the "+
			"request the decisions read, and the caller sets %d of them.",
			point.ID, len(request.Declared), count(len(request.Read), "part"), len(request.ByCaller)), "  ")
	}

	if a.Model == nil {
		render.Print(out, "No write model: every match stays a candidate, because nobody is named "+
			"as able to write what the decisions read.", "  ")
		return
	}
	render.Print(out, fmt.Sprintf("The write model covers %d of %d paths read (%d%%).",
		len(coverage.Covered), len(coverage.Read), coverage.Percent()), "  ")
}

// count writes a number and what it counts, plural when it has to be. A line
// that reads "1 files" is a line somebody wrote without looking at it.
func count(n int, thing string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, thing)
	}
	return fmt.Sprintf("%d %ss", n, thing)
}

// titleOf names a pattern the way a report should, and falls back to the id
// when the registry has no such pattern, which is what a finding filed under an
// id nobody wrote down looks like.
func titleOf(patterns []taxonomy.Pattern, id string) string {
	if pattern, found := taxonomy.Find(patterns, id); found {
		return pattern.Title
	}
	return id
}

// closesOf is the one line the registry holds about how a pattern is closed,
// and the empty string when the registry could not be read, where a report
// prints no closing line rather than inventing one.
func closesOf(patterns []taxonomy.Pattern, id string) string {
	if pattern, found := taxonomy.Find(patterns, id); found {
		return pattern.Closes
	}
	return ""
}
