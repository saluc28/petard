package analyze

import (
	"fmt"
	"io"
	"slices"
	"strings"

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
func summarize(findings taxonomy.Findings, patterns []taxonomy.Pattern) summary {
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
		// who can take whose place.
		if finding.Principal != "" && finding.Target != "" {
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

	if point := a.EnforcementPoint; point != nil {
		request := taxonomy.RequestCoverageOf(a.Reads, point)
		render.Print(out, fmt.Sprintf("The enforcement point is %s (%s): it says who sets %d of the %s the "+
			"decisions read, and the caller sets %d of them.",
			point.ID, point.File, len(request.Declared), count(len(request.Read), "part")+" of the request",
			len(request.ByCaller)), "  ")
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
