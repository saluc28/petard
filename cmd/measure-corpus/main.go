// Command measure-corpus runs the analysis over a body of Rego written by
// other people and reports what it could do with it.
//
// The fixture answers whether the engine finds what we planted; this answers
// whether it survives contact with code nobody wrote for it. How many policies
// load and under which syntax, which of the Rego forms the resolver has to
// worry about actually occur and how often, how far the analysis gets and where
// it stops.
//
// The output is a set of numbers to write down, not an assertion. The corpus
// lives in somebody else's repository, so the numbers move when that repository
// does, and a test asserting them would go red for a change that is not ours.
// What the corpus reveals about the engine becomes an ordinary test instead,
// with the reproduction inlined, in the package that was wrong.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/saluc28/petard/internal/opaengine"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2
)

// testSuffix marks the files a corpus keeps next to its policies and does not
// deploy. They are left out: a test is not a decision, and counting one would
// inflate every number here with code the policy engine never runs. On the
// corpus this was written for the exclusion is not a judgment call, since the
// constraint template embeds the policy and its libraries and never the tests.
const testSuffix = "_test.rego"

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("measure-corpus", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprint(stderr, "usage: measure-corpus [flags] <corpus root>...\n\n"+
			"Every directory holding .rego files is measured as one policy.\n\n")
		flags.PrintDefaults()
	}

	entrypointRule := flags.String("entrypoint-rule", "violation",
		"rule name to declare as the decision of each policy, for corpora whose policies annotate none")
	regoV0 := flags.Bool("rego-v0", false, "parse as Rego v0, like opa --v0-compatible")
	regoV1 := flags.Bool("rego-v1", false, "parse as Rego v1 and do not fall back to v0")
	verbose := flags.Bool("verbose", false, "print one line per policy")

	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	roots := flags.Args()
	if len(roots) == 0 {
		flags.Usage()
		return exitUsage
	}
	if *regoV0 && *regoV1 {
		fmt.Fprintln(stderr, "measure-corpus: -rego-v0 and -rego-v1 ask for opposite things")
		return exitUsage
	}

	mode := opaengine.ParseModeAuto
	switch {
	case *regoV0:
		mode = opaengine.ParseModeV0
	case *regoV1:
		mode = opaengine.ParseModeV1
	}

	policies, err := collect(roots)
	if err != nil {
		fmt.Fprintf(stderr, "measure-corpus: %v\n", err)
		return exitFailure
	}
	if len(policies) == 0 {
		fmt.Fprintf(stderr, "measure-corpus: no .rego file under %s\n", strings.Join(roots, ", "))
		return exitFailure
	}

	results := make([]result, 0, len(policies))
	for _, policy := range policies {
		results = append(results, measure(policy, mode, *entrypointRule))
	}

	report(stdout, roots, *entrypointRule, results, *verbose)
	return exitOK
}

// policy is one unit of the corpus: the Rego that is deployed together.
type policy struct {
	// name is the directory, relative to the root it was found under, which is
	// how a reader of the report finds it again.
	name  string
	files []string
}

// result is what the engine could do with one policy.
type result struct {
	policy

	// version is the syntax the bundle parsed as, empty when it did not load.
	version string
	loadErr error

	// decisions are the entrypoints declared for this policy, from the rule
	// name the caller asked for.
	decisions []string
	readsErr  error

	constructs opaengine.Constructs
	reads      *opaengine.ReadSet
	shape      opaengine.Shape
}

// measure loads one policy and asks the engine everything it can answer about
// it, stopping at the first question that has no answer.
func measure(p policy, mode opaengine.ParseMode, entrypointRule string) result {
	measured := result{policy: p}

	bundle, err := opaengine.Load(p.files, mode)
	if err != nil {
		measured.loadErr = err
		return measured
	}
	measured.version = bundle.RegoVersion.String()
	measured.constructs = bundle.Constructs()

	// The engine never decides that a rule with a given name is a decision.
	// Which rules carry that name is a fact it can state, and turning that fact
	// into a declaration is the caller's move, made here because the corpus
	// runtime documents the convention.
	bundle.Entrypoints = bundle.RulesNamed(entrypointRule)
	measured.decisions = bundle.Entrypoints

	reads, err := opaengine.Reads(bundle, opaengine.Limits{})
	if err != nil {
		measured.readsErr = err
		return measured
	}
	measured.reads = reads
	measured.shape = opaengine.RecognizeShape(reads)
	return measured
}

// collect finds the policies under the given roots: every directory that
// directly holds at least one .rego file that is not a test.
//
// Directories rather than files, because Rego that is deployed together has to
// be compiled together: a policy that imports a library and its library are one
// unit, and loading them apart would report unresolved references that the
// deployed bundle does not have.
func collect(roots []string) ([]policy, error) {
	var policies []policy
	for _, root := range roots {
		found, err := collectUnder(root)
		if err != nil {
			return nil, err
		}
		policies = append(policies, found...)
	}
	slices.SortFunc(policies, byName)
	return policies, nil
}

func collectUnder(root string) ([]policy, error) {
	byDir := make(map[string][]string)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := entry.Name()
		if entry.IsDir() || filepath.Ext(name) != ".rego" || strings.HasSuffix(name, testSuffix) {
			return nil
		}
		dir := filepath.Dir(path)
		byDir[dir] = append(byDir[dir], path)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("measure-corpus: walking %s: %w", root, err)
	}

	policies := make([]policy, 0, len(byDir))
	for dir, files := range byDir {
		name, err := filepath.Rel(root, dir)
		if err != nil {
			name = dir
		}
		slices.Sort(files)
		policies = append(policies, policy{name: filepath.ToSlash(name), files: files})
	}
	return policies, nil
}

// byName orders two policies by the path they were found at, which is how the
// report is read and how a rerun stays comparable with the run before it.
func byName(a, b policy) int { return strings.Compare(a.name, b.name) }

// report prints the measurement, from what happened to every policy down to
// what the corpus is made of.
func report(out io.Writer, roots []string, entrypointRule string, results []result, verbose bool) {
	fmt.Fprintf(out, "corpus: %d policies under %s\n", len(results), strings.Join(roots, ", "))

	reportLoading(out, results)
	reportDecisions(out, entrypointRule, results)
	reportResolver(out, results)
	reportPaths(out, results)
	reportForms(out, results)
	reportShapes(out, results)
	reportFailures(out, results)
	if verbose {
		reportPolicies(out, results)
	}
}

// count prints one measured line. The alignment lives here rather than in
// thirty format strings, so that a label longer than the others cannot quietly
// break the column it belongs to.
func count(out io.Writer, label string, n int) {
	fmt.Fprintf(out, "  %-32s %4d\n", label, n)
}

func reportLoading(out io.Writer, results []result) {
	loaded, byVersion := 0, map[string]int{}
	failures := map[string]int{}
	for _, measured := range results {
		if measured.loadErr != nil {
			failures[loadErrorClass(measured.loadErr)]++
			continue
		}
		loaded++
		byVersion[measured.version]++
	}

	fmt.Fprintf(out, "\nloading\n")
	count(out, "loaded", loaded)
	for _, version := range sortedKeys(byVersion) {
		count(out, "  parsed as rego "+version, byVersion[version])
	}
	for _, class := range sortedKeys(failures) {
		count(out, class, failures[class])
	}
}

// loadErrorClass names why a policy did not load, in the words of the engine's
// own sentinels, so that a count of failures says which half of the pipeline
// gave up.
func loadErrorClass(err error) string {
	switch {
	case errors.Is(err, opaengine.ErrParse):
		return "parse failed"
	case errors.Is(err, opaengine.ErrCompile):
		return "compile failed"
	case errors.Is(err, opaengine.ErrNoModules):
		return "no rego file"
	default:
		return "did not load"
	}
}

func reportDecisions(out io.Writer, entrypointRule string, results []result) {
	withDecisions, declared, none := 0, 0, 0
	for _, measured := range results {
		if measured.loadErr != nil {
			continue
		}
		if len(measured.decisions) == 0 {
			none++
			continue
		}
		withDecisions++
		declared += len(measured.decisions)
	}

	fmt.Fprintf(out, "\ndecisions, declared as the rules named %q\n", entrypointRule)
	count(out, "policies with a decision", withDecisions)
	count(out, "decisions declared", declared)
	count(out, "policies with none", none)
}

// resolverCounts are the edge cases the walk actually met, as opposed to the
// forms the sources hold. The two are counted separately on purpose: a form
// present in a file the decisions never reach was never resolved.
type resolverCounts struct {
	analyzed  int
	reads     int
	paths     int
	negated   int
	traced    int
	callers   int
	closures  int
	taints    int
	withRules int
	warnings  int
	byOrigin  map[string]int
}

func reportResolver(out io.Writer, results []result) {
	counts := resolverCounts{byOrigin: map[string]int{}}
	failures := map[string]int{}

	for _, measured := range results {
		if measured.loadErr != nil {
			continue
		}
		if measured.readsErr != nil {
			failures[readsErrorClass(measured.readsErr)]++
			continue
		}
		counts.analyzed++
		counts.add(measured.reads)
	}

	fmt.Fprintf(out, "\nanalysis\n")
	count(out, "policies walked", counts.analyzed)
	for _, class := range sortedKeys(failures) {
		count(out, class, failures[class])
	}

	fmt.Fprintf(out, "\nwhat the walk found\n")
	count(out, "reads of data", counts.reads)
	count(out, "distinct data paths", counts.paths)
	for _, origin := range sortedKeys(counts.byOrigin) {
		count(out, "  chosen by "+origin, counts.byOrigin[origin])
	}
	count(out, "values from outside", counts.taints)
	count(out, "transitive closures", counts.closures)

	fmt.Fprintf(out, "\nedge cases the walk met\n")
	count(out, "reads under a negation", counts.negated)
	count(out, "reads resolved through a call", counts.traced)
	count(out, "deepest call chain", counts.callers)
	count(out, "rules left out under with", counts.withRules)
	count(out, "bounds reached", counts.warnings)
}

func (c *resolverCounts) add(reads *opaengine.ReadSet) {
	c.reads += len(reads.Reads)
	c.paths += len(reads.Paths())
	c.closures += len(reads.Closures)
	c.taints += len(reads.Taints)
	c.withRules += len(reads.SkippedUnderWith)
	c.warnings += len(reads.Warnings)

	for _, provenance := range []opaengine.Provenance{
		opaengine.ProvenanceInput,
		opaengine.ProvenanceData,
		opaengine.ProvenanceBuiltin,
		opaengine.ProvenanceStatic,
		opaengine.ProvenanceUnresolved,
	} {
		if count := reads.CountWithProvenance(provenance); count > 0 {
			c.byOrigin[provenance.String()] += count
		}
	}

	for _, read := range reads.Reads {
		if read.UnderNegation {
			c.negated++
		}
		if read.Trace != nil {
			c.traced++
			c.callers = max(c.callers, len(read.Trace.Callers))
		}
	}
}

// readsErrorClass names why the walk did not run.
func readsErrorClass(err error) string {
	switch {
	case errors.Is(err, opaengine.ErrNoDecisions):
		return "no decision to walk from"
	case errors.Is(err, opaengine.ErrNoSuchEntrypoint):
		return "declared entrypoint missing"
	case errors.Is(err, opaengine.ErrBadEntrypoint):
		return "entrypoint not a rule path"
	default:
		return "walk failed"
	}
}

// topPaths is how many paths of one kind a report shows before it stops being
// a list and starts being a dump.
const topPaths = 12

// reportPaths names what the corpus reads, of data and of the request.
//
// The two answer different questions and both are worth the space. The paths
// under data are the ones a write model would have to cover, so a corpus that
// reads almost none of them is telling us which half of the analysis it can
// exercise. The paths of the request are what a shape recognizer has to work
// with, and they are the evidence for whether one is worth writing.
func reportPaths(out io.Writer, results []result) {
	data, request := map[string]int{}, map[string]int{}
	for _, measured := range results {
		if measured.reads == nil {
			continue
		}
		for _, path := range measured.reads.Paths() {
			data[path]++
		}
		for _, path := range measured.reads.InputPaths {
			request[path]++
		}
	}

	printPaths(out, "paths under data the decisions read", data)
	printPaths(out, "paths of the request the decisions read", request)
}

// printPaths prints the paths most policies share first, since a path one
// policy reads is a policy and a path forty share is a convention.
func printPaths(out io.Writer, title string, counts map[string]int) {
	if len(counts) == 0 {
		return
	}

	paths := sortedKeys(counts)
	slices.SortStableFunc(paths, func(a, b string) int { return counts[b] - counts[a] })

	fmt.Fprintf(out, "\n%s: %d distinct\n", title, len(paths))
	table := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(table, "  PATH\tPOLICIES")
	for _, path := range paths[:min(len(paths), topPaths)] {
		fmt.Fprintf(table, "  %s\t%d\n", path, counts[path])
	}
	table.Flush()
	if len(paths) > topPaths {
		fmt.Fprintf(out, "  and %d more\n", len(paths)-topPaths)
	}
}

// reportForms counts the Rego forms the sources hold, and in how many policies
// each of them appears.
//
// The share of policies matters more than the total: one policy with forty
// negations says the corpus has a fond author, forty policies with one each say
// the form is unavoidable.
func reportForms(out io.Writer, results []result) {
	forms := []struct {
		name string
		of   func(opaengine.Constructs) int
	}{
		{"packages", func(c opaengine.Constructs) int { return c.Packages }},
		{"rules", func(c opaengine.Constructs) int { return c.Rules }},
		{"functions", func(c opaengine.Constructs) int { return c.Functions }},
		{"negations", func(c opaengine.Constructs) int { return c.Negations }},
		{"comprehensions", func(c opaengine.Constructs) int { return c.Comprehensions }},
		{"every", func(c opaengine.Constructs) int { return c.Every }},
		{"with", func(c opaengine.Constructs) int { return c.With }},
		{"defaults", func(c opaengine.Constructs) int { return c.Defaults }},
	}

	fmt.Fprintf(out, "\nforms in the sources\n")
	table := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(table, "  FORM\tTOTAL\tPOLICIES")
	for _, form := range forms {
		total, policies := 0, 0
		for _, measured := range results {
			count := form.of(measured.constructs)
			total += count
			if count > 0 {
				policies++
			}
		}
		fmt.Fprintf(table, "  %s\t%d\t%d\n", form.name, total, policies)
	}
	table.Flush()
}

func reportShapes(out io.Writer, results []result) {
	byLevel := map[string]int{}
	for _, measured := range results {
		if measured.reads == nil {
			continue
		}
		byLevel[measured.shape.Confidence.String()+", "+measured.shape.Recognizer]++
	}
	if len(byLevel) == 0 {
		return
	}

	fmt.Fprintf(out, "\nrequest shape recognized\n")
	for _, level := range sortedKeys(byLevel) {
		count(out, "level "+level, byLevel[level])
	}
}

// reportFailures names every policy the run could not finish, because a count
// of failures is a fact and a list of them is a lead.
func reportFailures(out io.Writer, results []result) {
	var failed []result
	for _, measured := range results {
		if measured.loadErr != nil || measured.readsErr != nil {
			failed = append(failed, measured)
		}
	}
	if len(failed) == 0 {
		return
	}

	fmt.Fprintf(out, "\npolicies the run could not finish\n")
	for _, measured := range failed {
		err := measured.loadErr
		if err == nil {
			err = measured.readsErr
		}
		fmt.Fprintf(out, "  %s: %s\n", measured.name, firstLine(err))
	}
}

func reportPolicies(out io.Writer, results []result) {
	fmt.Fprintln(out)
	table := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(table, "POLICY\tREGO\tDECISIONS\tREADS\tPATHS\tSHAPE")
	for _, measured := range results {
		if measured.reads == nil {
			fmt.Fprintf(table, "%s\t%s\t-\t-\t-\t-\n", measured.name, orDash(measured.version))
			continue
		}
		fmt.Fprintf(table, "%s\t%s\t%d\t%d\t%d\t%s\n",
			measured.name, measured.version, len(measured.reads.Decisions),
			len(measured.reads.Reads), len(measured.reads.Paths()), measured.shape.Confidence)
	}
	table.Flush()
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// firstLine keeps a failure to one line of the report. A parse error names
// every file it tried, which belongs in the run that fixes it and not in a
// table of fifty policies.
func firstLine(err error) string {
	message := err.Error()
	if i := strings.IndexByte(message, '\n'); i >= 0 {
		return message[:i] + " ..."
	}
	return message
}
