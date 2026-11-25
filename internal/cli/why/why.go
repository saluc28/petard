// Package why is the petard why command. It lays out one Zanzibar escalation
// finding as a readable chain: the writes a coalition makes to reach it, in
// order, with where each relation is declared and how to have the product's own
// checker confirm the raise.
//
// A report names a finding by its pattern id and says what it raises. why is the
// account of how: the attack path the engine already found, step by step, so a
// reader can follow it without -v and without a directory of proofs. It reads the
// schemas petard analyze reads and runs the same engine over them, so the chain
// it shows is the one a run reports rather than a second derivation of it.
package why

import (
	"context"
	"flag"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/saluc28/petard/internal/cli/render"
	"github.com/saluc28/petard/internal/cli/zanzibarsetup"
	"github.com/saluc28/petard/internal/taxonomy"
	"github.com/saluc28/petard/internal/zanzibar"
	registry "github.com/saluc28/petard/taxonomy-registry"
)

const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2
)

// Run is the subcommand, taking its arguments without the name and returning the
// exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("petard why", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprint(stderr, "usage: petard why <finding> <path>...\n\n"+
			"Lays out one SpiceDB or OpenFGA escalation finding as a readable chain: the writes a\n"+
			"coalition makes to reach it, in order, where each relation is declared, and how to have\n"+
			"the product's own checker confirm it. <finding> is a pattern id such as PTD-ZAN-007, a\n"+
			"pattern name, or the slug a report gives one escalation, as ptd-zan-007-document-edit.\n"+
			"The paths are the schemas, read the way petard analyze reads them.\n\n")
		flags.PrintDefaults()
	}
	writeModelPath := flags.String("write-model", "", "path to a write model; without it, and without one beside a schema, that schema has no escalations to explain")
	registryPath := flags.String("registry", "", registry.FlagUsage)
	noColor := flags.Bool("no-color", false, "never use escape sequences, whatever the terminal says")

	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	rest := flags.Args()
	if len(rest) < 2 {
		flags.Usage()
		return exitUsage
	}
	wanted, paths := rest[0], rest[1:]

	// Before the analysis: a registry that cannot be read would turn a finding's
	// title into its id, which is the one thing why is here to expand on.
	patterns, err := taxonomy.LoadRegistries(registry.Source(*registryPath))
	if err != nil {
		fmt.Fprintf(stderr, "petard why: %v\n", err)
		return exitFailure
	}

	ctx := context.Background()
	setup, err := zanzibarsetup.Load(ctx, paths, *writeModelPath)
	if err != nil {
		fmt.Fprintf(stderr, "petard why: %v\n", err)
		return exitFailure
	}

	found := escalations(setup, time.Now())
	if len(found) == 0 {
		fmt.Fprintln(stderr, "petard why: no escalation findings under the paths; a schema needs a write model beside it, or -write-model, for its escalations to be found")
		return exitUsage
	}
	matched := slices.DeleteFunc(slices.Clone(found), func(e escalation) bool {
		return !e.selects(wanted, patterns)
	})
	if len(matched) == 0 {
		fmt.Fprintf(stderr, "petard why: no escalation finding called %s under the paths; run petard analyze for what is there\n", wanted)
		return exitUsage
	}

	style := render.StyleFor(stdout, *noColor)
	nameSchema := spansSchemas(found)
	for i, e := range matched {
		if i > 0 {
			fmt.Fprintln(stdout)
		}
		printWhy(stdout, e, nameSchema, paths, patterns, style)
	}
	return exitOK
}

// escalation is one escalation finding why can explain: the match the engine
// produced, the schema it was found in, and the product that schema is of.
type escalation struct {
	match   zanzibar.Match
	schema  string
	product zanzibarsetup.Product
}

// escalations runs the Zanzibar engine over the loaded schemas and returns the
// escalation findings, deduplicated the way analyze deduplicates them so the two
// commands agree on the set. A match with no Raise is not an escalation and is
// left out.
func escalations(setup zanzibarsetup.Found, now time.Time) []escalation {
	productOf := make(map[string]zanzibarsetup.Product, len(setup.Files))
	for _, f := range setup.Files {
		productOf[f.SchemaPath] = f.Product
	}
	analyses, _ := setup.Analyses(now)
	seen := map[string]bool{}
	var out []escalation
	for _, a := range analyses {
		matches, _ := zanzibar.RunWithLimits(a.Sample, a.WriteModel)
		for _, m := range matches {
			if m.Raise == nil {
				continue
			}
			key := m.PatternID + "\x00" + a.SchemaPath + "\x00" + m.Subject
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, escalation{match: m, schema: a.SchemaPath, product: productOf[a.SchemaPath]})
		}
	}
	return out
}

// selects reports whether wanted names this finding: its pattern id, its pattern
// name, or the slug a report and -proofs give it, in any case.
func (e escalation) selects(wanted string, patterns []taxonomy.Pattern) bool {
	if strings.EqualFold(wanted, e.match.PatternID) || strings.EqualFold(wanted, e.slug()) {
		return true
	}
	p, ok := taxonomy.Find(patterns, e.match.PatternID)
	return ok && strings.EqualFold(wanted, p.Name)
}

// slug is the name a report and -proofs give this finding, the pattern id with
// the type and permission it raises.
func (e escalation) slug() string {
	return render.Slug(e.match.PatternID + "-" + e.match.Raise.Type + "-" + e.match.Raise.Permission)
}

// spansSchemas says whether the findings come from more than one schema, which
// is when each has to name the schema it is in.
func spansSchemas(es []escalation) bool {
	return slices.ContainsFunc(es, func(e escalation) bool { return e.schema != es[0].schema })
}

// printWhy lays out one finding: what it raises, the writes that reach it, and
// how to have the product confirm it.
func printWhy(out io.Writer, e escalation, nameSchema bool, paths []string, patterns []taxonomy.Pattern, style render.Style) {
	r := e.match.Raise
	fmt.Fprintln(out, style.Bold(fmt.Sprintf("%s  %s#%s  %s", e.match.PatternID, r.Type, r.Permission, r.Kind)))
	if p, ok := taxonomy.Find(patterns, e.match.PatternID); ok {
		fmt.Fprintln(out)
		render.Print(out, render.Plain(p.Title), "  ")
	}
	if nameSchema {
		fmt.Fprintf(out, "\n  in %s\n", e.schema)
	}
	fmt.Fprintf(out, "\n  raises %s on %s, from %s to %s\n", r.Permission, r.Type, r.Before, r.After)

	if len(r.Witness) > 0 {
		fmt.Fprintf(out, "\n  %s:\n", reaches(len(r.Witness)))
		for i, step := range r.Witness {
			printStep(out, i+1, step, style)
		}
	}
	fmt.Fprintln(out)
	printReplay(out, e, paths)
}

// reaches says in how many writes the coalition reaches the raise, in words, so
// a single write does not read as "1 writes".
func reaches(n int) string {
	if n == 1 {
		return "The coalition reaches it in a single write"
	}
	return fmt.Sprintf("The coalition reaches it in %d writes", n)
}

// printStep prints one write of the chain: what it writes and who the write
// model lets make it on one line, where the relation is declared on the next.
func printStep(out io.Writer, n int, step zanzibar.WitnessStep, style render.Style) {
	head := fmt.Sprintf("    %d  %s %s", n, step.Verb, step.Tuple)
	if step.Decisive {
		head += "  " + style.Bold("decisive")
	}
	fmt.Fprintln(out, head)
	if step.Who != "" {
		who := step.Who
		if step.Via != "" {
			who += ", through " + step.Via
		}
		render.Print(out, who, "         ")
	}
	if at := step.At.String(); at != "" {
		fmt.Fprintf(out, "         declared at %s\n", at)
	}
}

// printReplay says how to have the product's own checker confirm the raise. The
// proof is the finding as the product can be asked to show it, so this is where
// why points past itself to an answer petard did not give.
func printReplay(out io.Writer, e escalation, paths []string) {
	r := e.match.Raise
	if r.Proof == nil {
		render.Print(out, "petard cannot write a replayable proof for this one: "+r.NoProof, "  ")
		return
	}
	checker := "zed validate"
	if e.product == zanzibarsetup.OpenFGA {
		checker = "fga model test"
	}
	render.Print(out, fmt.Sprintf("Have %s confirm it: write the proof, then run %s on the files it leaves under the %s directory.",
		e.product, checker, e.slug()), "  ")
	fmt.Fprintf(out, "    petard analyze -proofs <dir> %s\n", strings.Join(paths, " "))
}
