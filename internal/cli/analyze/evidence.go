package analyze

import (
	"cmp"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"text/tabwriter"

	"github.com/saluc28/petard/internal/cli/render"
	"github.com/saluc28/petard/internal/evidence"
	"github.com/saluc28/petard/internal/zanzibar"
)

// This file holds the write models of the schemas to the source of the application they
// describe. A rule can cite the lines that make its write; a run checks that each line is
// still there and fails when one is not, so a write model the code has moved away from
// shows up in CI. With -code the run also lists the places in the source that call a
// write of SpiceDB or OpenFGA and that no rule cites. Whether a cited line does what the
// rule declares, and whether the application checks the gate, is for a person to read.

// evidenceRun is what the source says of the write models.
type evidenceRun struct {
	// rules counts the rules of the write models, and cited those that cite a line.
	rules, cited int

	// broken are the citations the source no longer holds.
	broken []brokenCitation

	// source is the directory -code named, sites the places in it that call a write,
	// and uncited those no rule cites.
	source         string
	sites, uncited []evidence.Site
}

// brokenCitation is a citation of a rule that no longer holds, and why.
type brokenCitation struct {
	rule     string
	citation evidence.Citation
	why      string
}

// checkEvidence holds the rules of the write models to the source: the directory code
// names, or, without it, the directory of each write model. A citation is read inside
// that directory and never outside it.
func checkEvidence(models []*zanzibar.WriteModel, code string) (evidenceRun, error) {
	run := evidenceRun{source: code}
	cited := map[string]bool{}
	for _, wm := range models {
		root := code
		if root == "" {
			if wm.Path == "" {
				continue
			}
			root = filepath.Dir(wm.Path)
		}
		dir, err := os.OpenRoot(root)
		if err != nil {
			return evidenceRun{}, fmt.Errorf("reading the source the evidence of %s cites: %w", wm.Path, err)
		}
		for _, rule := range rulesOf(wm) {
			run.rules++
			if len(rule.evidence) > 0 {
				run.cited++
			}
			for _, c := range rule.evidence {
				cited[c.String()] = true
				if err := evidence.Check(dir.FS(), c); err != nil {
					run.broken = append(run.broken, brokenCitation{rule: rule.name, citation: c, why: err.Error()})
				}
			}
		}
		if err := dir.Close(); err != nil {
			return evidenceRun{}, err
		}
	}

	if code == "" {
		return run, nil
	}
	dir, err := os.OpenRoot(code)
	if err != nil {
		return evidenceRun{}, fmt.Errorf("reading the source -code names: %w", err)
	}
	defer func() { _ = dir.Close() }()
	if run.sites, err = evidence.Sites(dir.FS()); err != nil {
		return evidenceRun{}, fmt.Errorf("searching %s for the places that write: %w", code, err)
	}
	for _, site := range run.sites {
		if !cited[site.String()] {
			run.uncited = append(run.uncited, site)
		}
	}
	return run, nil
}

// citingRule is a rule of a write model as the evidence report names it.
type citingRule struct {
	name     string
	evidence []evidence.Citation
}

// rulesOf are the rules of a write model, a write rule named by its relation and a
// creation by what it creates.
func rulesOf(wm *zanzibar.WriteModel) []citingRule {
	out := make([]citingRule, 0, len(wm.Writes)+len(wm.Creates))
	for _, w := range wm.Writes {
		out = append(out, citingRule{name: w.Resource + "#" + w.Relation, evidence: w.Evidence})
	}
	for _, c := range wm.Creates {
		out = append(out, citingRule{name: "creating " + c.Creates, evidence: c.Evidence})
	}
	return out
}

// writeModelsOf are the write models of the schemas, each once, in the order of their
// paths.
func writeModelsOf(byDir map[string]*zanzibar.WriteModel) []*zanzibar.WriteModel {
	var out []*zanzibar.WriteModel
	for _, wm := range byDir {
		if !slices.Contains(out, wm) {
			out = append(out, wm)
		}
	}
	slices.SortFunc(out, func(a, b *zanzibar.WriteModel) int { return cmp.Compare(a.Path, b.Path) })
	return out
}

// shows says whether the run has anything to say about evidence: a rule cites a line, or
// -code named a source to search.
func (r evidenceRun) shows() bool {
	return r.cited > 0 || r.source != ""
}

// printEvidence says how many rules cite the source, which citations no longer hold, and
// the places that write that no rule cites. Quiet, it prints the citations that no longer
// hold alone, since they fail the run.
func printEvidence(out io.Writer, r evidenceRun, style render.Style, quiet bool) {
	if !r.shows() || (quiet && len(r.broken) == 0) {
		return
	}
	fmt.Fprintln(out)
	fmt.Fprintln(out, style.Bold("Evidence in the source"))
	if !quiet {
		verb := "cite"
		if r.cited == 1 {
			verb = "cites"
		}
		fmt.Fprintf(out, "  %d of %s %s the lines of the application that make the write\n", r.cited, render.Count(r.rules, "rule"), verb)
	}
	if len(r.broken) > 0 {
		fmt.Fprintf(out, "  %s no longer %s:\n", render.Count(len(r.broken), "citation"), holds(len(r.broken)))
		tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		for _, b := range r.broken {
			fmt.Fprintf(tw, "    %s\t%s\t%s\n", b.rule, b.citation, b.why)
		}
		tw.Flush()
	}
	if quiet || r.source == "" {
		return
	}
	fmt.Fprintf(out, "  %s in %s call a write of SpiceDB or OpenFGA, %d cited by a rule\n",
		render.Count(len(r.sites), "place"), filepath.ToSlash(r.source), len(r.sites)-len(r.uncited))
	if len(r.uncited) == 0 {
		return
	}
	fmt.Fprintln(out, "  not cited by any rule:")
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	for _, s := range r.uncited {
		fmt.Fprintf(tw, "    %s\t%s\t%s\n", s, s.Call, s.Product)
	}
	tw.Flush()
}

// holds is the verb for a count of citations.
func holds(n int) string {
	if n == 1 {
		return "holds"
	}
	return "hold"
}

// exitCode is the exit code the evidence asks for: a citation that no longer holds fails
// the run as a finding does, since the write model it is part of no longer says what the
// code does.
func (r evidenceRun) exitCode(failOn string) int {
	if len(r.broken) > 0 && failOn != failOnNone {
		return exitFound
	}
	return exitOK
}
