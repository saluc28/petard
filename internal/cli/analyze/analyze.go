// Command petard analyze reads Rego policies and reports what their decisions
// read from data, and who chooses the documents they land on.
//
// It exists so that the analysis can be looked at without running the tests.
// Flags are parsed with the standard library: four options do not justify a
// dependency, and the phase where this program grows a command tree is not
// this one.
package analyze

import (
	"context"
	"flag"
	"fmt"
	"io"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/saluc28/petard/internal/cli/render"
	"github.com/saluc28/petard/internal/graph"
	"github.com/saluc28/petard/internal/opaengine"
	"github.com/saluc28/petard/internal/opengraph"
	"github.com/saluc28/petard/internal/taxonomy"
	"github.com/saluc28/petard/internal/writemodel"
	registry "github.com/saluc28/petard/taxonomy-registry"
)

const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2
	exitFound   = 3
)

// repeatedString is a flag that may be given more than once, the way opa build
// takes its entrypoints. The standard library has no such flag, and the
// alternative, one comma separated string, would break on the first value that
// contains a comma.
type repeatedString []string

func (r *repeatedString) String() string { return strings.Join(*r, " ") }

func (r *repeatedString) Set(value string) error {
	*r = append(*r, value)
	return nil
}

// Run is the subcommand, taking its arguments without the name and returning
// the exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("petard analyze", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprint(stderr, "usage: petard analyze [flags] <path>...\n\n"+
			"Paths are Rego files or directories holding them.\n\n")
		flags.PrintDefaults()
	}

	regoV0 := flags.Bool("rego-v0", false, "parse as Rego v0, like opa --v0-compatible")
	regoV1 := flags.Bool("rego-v1", false, "parse as Rego v1 and do not fall back to v0")
	var entrypoints repeatedString
	flags.Var(&entrypoints, "entrypoint", "a rule the PEP queries, or a field of what it returns, as data.authz.allow or authz/allow; repeat for more")
	var denyEntrypoints repeatedString
	flags.Var(&denyEntrypoints, "deny-entrypoint", "a rule the PEP queries to refuse the request when it holds or collects anything, as k8sallowedrepos/violation; repeat for more")
	subject := flags.String("subject", "", "the part of the request that names who is asking, as input.user; without it, it is recognized")
	enforcementPoint := flags.String("pep", "", "the product that asks for the decisions: an id from pep-registry, as spacelift-login, or a declaration of your own ending in .yaml")
	maxCallDepth := flags.Int("max-call-depth", 0, "how many calls deep to follow an argument (0 for the default)")
	maxCallPaths := flags.Int("max-call-paths", 0, "how many call paths to explore per reference (0 for the default)")
	maxResiduals := flags.Int("max-residuals", 0, "how many residual conditions to report per decision (0 for the default)")
	writeModelPath := flags.String("write-model", "", "path to the write model; without it every match stays a candidate")
	dataPath := flags.String("data", "", "path to the concrete data; with it the decisions are also partially evaluated")
	registryPath := flags.String("registry", "", registry.FlagUsage)
	showGraph := flags.Bool("graph", false, "also build the internal graph model and report what it holds")
	verbose := flags.Bool("v", false, "print the evidence too: every read, the residual decisions and every place to look")
	quiet := flags.Bool("quiet", false, "print the escalations and the findings alone, and nothing at all when there are none")
	failOn := flags.String("fail-on", failOnFindings, "exit 3 on findings, on any match including candidates, or on neither: findings|any|none")
	noColor := flags.Bool("no-color", false, "never use escape sequences, whatever the terminal says")

	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	paths := flags.Args()
	if len(paths) == 0 {
		flags.Usage()
		return exitUsage
	}
	if *regoV0 && *regoV1 {
		fmt.Fprintln(stderr, "petard analyze: -rego-v0 and -rego-v1 ask for opposite things")
		return exitUsage
	}
	if *verbose && *quiet {
		fmt.Fprintln(stderr, "petard analyze: -v and -quiet ask for opposite things")
		return exitUsage
	}
	if !slices.Contains([]string{failOnFindings, failOnAny, failOnNone}, *failOn) {
		fmt.Fprintf(stderr, "petard analyze: -fail-on %s is none of %s, %s, %s\n",
			*failOn, failOnFindings, failOnAny, failOnNone)
		return exitUsage
	}

	mode := opaengine.ParseModeAuto
	switch {
	case *regoV0:
		mode = opaengine.ParseModeV0
	case *regoV1:
		mode = opaengine.ParseModeV1
	}

	// Before the analysis rather than after it: a registry that cannot be read
	// is the difference between a report and a list of codes, and finding that
	// out at the end means having waited for it.
	patterns, err := taxonomy.LoadRegistry(registry.Source(*registryPath))
	if err != nil {
		fmt.Fprintf(stderr, "petard analyze: %v\n", err)
		return exitFailure
	}

	bundle, err := opaengine.Load(paths, mode)
	if err != nil {
		fmt.Fprintf(stderr, "petard analyze: %v\n", err)
		return exitFailure
	}
	bundle.Entrypoints = entrypoints
	bundle.DenyEntrypoints = denyEntrypoints

	point, err := taxonomy.DeclareEnforcementPoint(bundle, *enforcementPoint)
	if err != nil {
		fmt.Fprintf(stderr, "petard analyze: %v\n", err)
		return exitFailure
	}

	limits := opaengine.Limits{
		MaxCallDepth: *maxCallDepth,
		MaxCallPaths: *maxCallPaths,
		MaxResiduals: *maxResiduals,
	}

	reads, err := opaengine.Reads(bundle, limits)
	if err != nil {
		fmt.Fprintf(stderr, "petard analyze: %v\n", err)
		return exitFailure
	}
	shape, err := taxonomy.ShapeOf(reads, *subject, point)
	if err != nil {
		fmt.Fprintf(stderr, "petard analyze: %v\n", err)
		return exitFailure
	}

	var model *writemodel.Model
	if *writeModelPath != "" {
		model, err = writemodel.Load(*writeModelPath)
		if err != nil {
			fmt.Fprintf(stderr, "petard analyze: %v\n", err)
			return exitFailure
		}
	}

	var data *opaengine.Data
	if *dataPath != "" {
		data, err = opaengine.LoadData([]string{*dataPath})
		if err != nil {
			fmt.Fprintf(stderr, "petard analyze: %v\n", err)
			return exitFailure
		}
	}

	ctx := context.Background()
	analyzed := taxonomy.Analysis{
		Bundle:           bundle,
		Reads:            reads,
		Shape:            shape,
		Model:            model,
		Data:             data,
		EnforcementPoint: point,
		Limits:           limits,
	}
	findings, err := taxonomy.Run(ctx, analyzed)
	if err != nil {
		fmt.Fprintf(stderr, "petard analyze: %v\n", err)
		return exitFailure
	}
	coverage, err := taxonomy.CoverageOf(reads, model)
	if err != nil {
		fmt.Fprintf(stderr, "petard analyze: %v\n", err)
		return exitFailure
	}

	found := summarize(findings, patterns)
	printSummary(stdout, analyzed, found, coverage, printing{
		style:   render.StyleFor(stdout, *noColor),
		quiet:   *quiet,
		verbose: *verbose,
	})

	if *verbose {
		fmt.Fprintln(stdout)
		report(stdout, bundle, reads, shape)
		if data != nil {
			if err := reportResiduals(ctx, stdout, bundle, data, reads, limits); err != nil {
				fmt.Fprintf(stderr, "petard analyze: %v\n", err)
				return exitFailure
			}
		}
		reportFindings(stdout, analyzed, findings, patterns, coverage)
	}

	if *showGraph {
		if err := reportGraph(ctx, stdout, analyzed, findings); err != nil {
			fmt.Fprintf(stderr, "petard analyze: %v\n", err)
			return exitFailure
		}
	}
	return exitCode(found, *failOn)
}

// How -fail-on is spelled, and what each spelling counts.
const (
	// failOnFindings is the default, and it is the default because a check
	// nobody can fail is a check nobody runs twice. A finding needs a write
	// model to exist at all for the patterns that ask for one, so a first run
	// against a policy with nothing declared does not fail on those: it fails
	// on the ones that read the policy alone, which are facts about the bundle
	// as it stands.
	//
	// Precedent: regal --fail-level defaults to error and exits 3
	// (cmd/lint.go:136 at v0.42.0), conftest and staticcheck fail on what they
	// find as well.
	failOnFindings = "findings"

	// failOnAny counts candidates too, for the run that wants to know about
	// everything the patterns matched, write model or no write model.
	failOnAny = "any"

	// failOnNone reports and exits 0 regardless, which is what a demonstration
	// wants, and a first look at somebody else's policy.
	failOnNone = "none"
)

// exitCode separates having found something from having broken down.
//
// A pipeline has to tell the two apart: a failing analysis is a bug to fix, and
// a finding is the tool doing its job. Hence 3 for what was found, 1 for what
// went wrong, 2 for a command line that made no sense.
func exitCode(found summary, failOn string) int {
	switch failOn {
	case failOnFindings:
		if found.findings() > 0 {
			return exitFound
		}
	case failOnAny:
		if found.findings()+found.candidates() > 0 {
			return exitFound
		}
	}
	return exitOK
}

// reportGraph assembles the internal model and says what it holds.
//
// It is behind a flag because the model is not the report: the report is what
// an analyst reads, and the model is what the exporter will serialize. Until
// there is an exporter, counting what the model holds is the only way to see
// that every kind the model declares has something in it, and that a kind
// nothing fills is a hole rather than a decision.
func reportGraph(ctx context.Context, out io.Writer, a taxonomy.Analysis, findings taxonomy.Findings) error {
	g, gaps, err := taxonomy.Assemble(ctx, a, findings)
	if err != nil {
		return err
	}
	printGraph(out, g, gaps)

	// The model is only worth what BloodHound will accept of it, and an ingest
	// job answers late and badly. Checking the payload against the schema here
	// costs nothing and is the difference between finding a mistake now and
	// finding it in a graph that quietly holds less than it should.
	if err := opengraph.Validate(opengraph.Payload(g)); err != nil {
		return err
	}
	fmt.Fprintf(out, "  the payload validates against schema/%s\n", opengraph.SchemaFile)
	return nil
}

func printGraph(out io.Writer, g *graph.Graph, gaps taxonomy.Gaps) {
	nodes := map[string]int{}
	for _, node := range g.Nodes() {
		nodes[string(node.Kind)]++
	}
	edges, traversable := map[string]int{}, 0
	for _, edge := range g.Edges() {
		edges[string(edge.Kind)]++
		if edge.Kind.IsTraversable() {
			traversable++
		}
	}

	fmt.Fprintf(out, "\ngraph model\n")
	table := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(table, "  KIND\tCOUNT")
	for _, kind := range append(sortedKeys(nodes), sortedKeys(edges)...) {
		fmt.Fprintf(table, "  %s\t%d\n", kind, nodes[kind]+edges[kind])
	}
	table.Flush()
	fmt.Fprintf(out, "  %d of %d edges are traversable\n", traversable, len(g.Edges()))

	for _, said := range []struct {
		count int
		text  string
	}{
		{gaps.DerivedWriters, "declared writers name a rule for finding somebody, not somebody, and have no edge"},
		{gaps.ConditionalWays, "ways of granting depend on something an edge cannot say, and are left out"},
		{gaps.UnmatchedFindings, "findings speak about something the graph does not hold"},
	} {
		if said.count > 0 {
			fmt.Fprintf(out, "  %d %s\n", said.count, said.text)
		}
	}
}

// sortedKeys returns the keys of a map in order, so that two runs of the same
// bundle print the same report.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

// reportFindings prints what the patterns made of the analysis, under the
// titles the registry gives them, and says what the write model could and could
// not answer for.
func reportFindings(out io.Writer, a taxonomy.Analysis, findings taxonomy.Findings, patterns []taxonomy.Pattern, coverage taxonomy.Coverage) {
	// In a closed world an undeclared path is an assumed safe path, so this
	// number is what keeps a clean run from looking like an empty model.
	fmt.Fprintf(out, "\nwrite model: %d of %d paths covered (%d%%)\n",
		len(coverage.Covered), len(coverage.Read), coverage.Percent())
	for _, path := range coverage.Uncovered {
		fmt.Fprintf(out, "  not covered: %s\n", path)
	}

	for _, reported := range []struct {
		id    string
		found []taxonomy.Finding
	}{
		{taxonomy.AttrSelfWrite, findings.SelfWrite},
		{taxonomy.DenyUndefinedOnMissingData, findings.MissingData},
		{taxonomy.TransitiveGrantViaOwnership, findings.Transitive},
		{taxonomy.ExternalSourceTaint, findings.Tainted},
		{taxonomy.FailOpenOnSourceUnavailable, findings.Unavailable},
		{taxonomy.EveryOverEmptyDomain, findings.EveryEmpty},
		{taxonomy.WriteAllowedByAnotherDecision, findings.SplitGrant},
		{taxonomy.GlobalDocumentDecides, findings.GlobalSwitch},
		{taxonomy.SelfAssertedExemption, findings.SelfAsserted},
	} {
		// Printing nothing for a pattern that could not run would read as "the
		// check covers everything", which is the one thing these patterns exist
		// to disprove.
		if why, skipped := findings.Skipped[reported.id]; skipped {
			reportSkipped(out, patterns, reported.id, why)
			continue
		}
		reportPattern(out, patterns, reported.id, reported.found)
	}
}

// reportResiduals asks every decision what is left of it once the data is
// concrete and the request is not.
//
// The whole request is the unknown here, which is the widest question and the
// one worth printing without being asked something narrower: what can anybody
// get out of this decision, given these documents. Narrowing the unknown to one
// part of the request is what turns the same call into a question about a
// single principal, and that belongs to a pattern rather than to a summary.
func reportResiduals(ctx context.Context, out io.Writer, bundle *opaengine.Bundle, data *opaengine.Data, reads *opaengine.ReadSet, limits opaengine.Limits) error {
	fmt.Fprintf(out, "\nagainst %d data documents, with the request unknown:\n", len(data.Files))

	table := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(table, "  DECISION\tRESIDUAL CONDITIONS\tDEFAULT")
	var warnings []string

	for _, decision := range reads.Decisions {
		residuals, err := opaengine.Residuals(ctx, bundle, data, opaengine.Request{Decision: decision}, limits)
		if err != nil {
			return err
		}

		fallback := residuals.Default
		if fallback == "" {
			fallback = "undefined"
		}
		fmt.Fprintf(table, "  %s\t%s\t%s\n", decision, describeResiduals(residuals), fallback)
		warnings = append(warnings, residuals.Warnings...)
	}
	table.Flush()

	for _, warning := range warnings {
		fmt.Fprintf(out, "warning: %s\n", warning)
	}
	return nil
}

// describeResiduals says how much of a decision is left to check. Holding
// always and holding under no condition at all are answers, not counts, and
// printing them as a number would lose the difference.
func describeResiduals(residuals *opaengine.ResidualSet) string {
	switch {
	case residuals.Always:
		return "holds on the data alone"
	case residuals.Never():
		return "nothing can make it hold"
	case residuals.Truncated:
		return fmt.Sprintf("%d, and the bound cut the rest", len(residuals.Conditions))
	default:
		return fmt.Sprintf("%d", len(residuals.Conditions))
	}
}

// reportPattern prints one pattern and what it matched, under the title the
// registry gives it: the id alone is a filename, and a report is read by
// somebody who has not opened the registry.
func reportPattern(out io.Writer, patterns []taxonomy.Pattern, id string, findings []taxonomy.Finding) {
	fmt.Fprintf(out, "\n%s\n", patternTitle(patterns, id))

	if len(findings) == 0 {
		fmt.Fprintln(out, "  nothing")
		return
	}
	for _, finding := range findings {
		fmt.Fprintf(out, "  %s\n", finding)
		for _, site := range finding.Reads {
			fmt.Fprintf(out, "    %s at %s:%d in %s\n", site.Ref, site.File, site.Line, site.Rule)
		}
		if finding.SubjectElement > 0 {
			fmt.Fprintf(out, "    the subject is found in it by value, at segment %d\n", finding.SubjectElement)
		}
		if finding.ViaWritePath != "" {
			fmt.Fprintf(out, "    declared writable at %s\n", finding.ViaWritePath)
		}
		if len(finding.UncoveredKeys) > 0 {
			fmt.Fprintf(out, "    absent for: %s\n", strings.Join(finding.UncoveredKeys, ", "))
			fmt.Fprintf(out, "    side that applies the check: %s\n", finding.EnforcingSide)
		}
		if finding.Note != "" {
			fmt.Fprintf(out, "    %s\n", finding.Note)
		}
	}
}

// reportSkipped prints a pattern the run could not apply, with what it would
// have taken. A pattern silently left out reads as a pattern that found
// nothing.
func reportSkipped(out io.Writer, patterns []taxonomy.Pattern, id, why string) {
	fmt.Fprintf(out, "\n%s\n  not applied: %s\n", patternTitle(patterns, id), why)
}

// patternTitle names a pattern the way a report should: the id plus the title
// the registry gives it, and the id alone when the registry could not be read.
func patternTitle(patterns []taxonomy.Pattern, id string) string {
	if pattern, found := taxonomy.Find(patterns, id); found {
		return pattern.ID + ", " + pattern.Title
	}
	return id
}

// describeSource names where a value came from: the builtin, and the
// destination when the policy writes it out. A computed destination is said to
// be computed rather than left blank, since that is the more interesting of the
// two and would otherwise look like something the engine failed to read.
func describeSource(taint opaengine.Taint) string {
	if taint.Endpoint == "" {
		return taint.Origin + ", destination computed"
	}
	return taint.Origin + " " + taint.Endpoint
}

// describeCheckSide says what a check holding does to one decision.
func describeCheckSide(decision opaengine.CheckedDecision) string {
	switch {
	case decision.Exception:
		return "lifts a refusal in " + decision.Name
	case decision.Grants:
		return "grants in " + decision.Name
	default:
		return "refuses in " + decision.Name
	}
}

// describeShape prints only the parts that were recognized. A field left out
// is not a gap to paper over: it is the recognizer declining to guess.
func describeShape(shape opaengine.Shape) string {
	parts := make([]string, 0, 3)
	for _, part := range []struct{ role, path string }{
		{"subject", shape.Subject},
		{"action", shape.Action},
		{"resource", shape.Resource},
	} {
		if part.path != "" {
			parts = append(parts, part.role+"="+part.path)
		}
	}
	if len(parts) == 0 {
		return "not recognized"
	}
	return strings.Join(parts, " ")
}

func report(out io.Writer, bundle *opaengine.Bundle, reads *opaengine.ReadSet, shape opaengine.Shape) {
	fmt.Fprintf(out, "bundle:    %d files, parsed as rego %s\n", len(bundle.Files), bundle.RegoVersion)
	fmt.Fprintf(out, "decisions: %d\n", len(reads.Decisions))
	for _, decision := range reads.Decisions {
		if reads.Denies(decision) {
			fmt.Fprintf(out, "  %s, to deny\n", decision)
			continue
		}
		fmt.Fprintf(out, "  %s\n", decision)
	}

	fmt.Fprintf(out, "\nrequest shape:  %s (level %s, %s)\n", describeShape(shape), shape.Confidence, shape.Recognizer)

	// The two measures stay apart, because one says what the engine can find
	// and the other what it can explain, and a single number would hide
	// whichever of the two is missing.
	fmt.Fprintf(out, "\ndata paths read by the decisions: %d\n", len(reads.Paths()))
	fmt.Fprintf(out, "reads:                            %d\n", len(reads.Reads))
	for _, provenance := range []opaengine.Provenance{
		opaengine.ProvenanceInput,
		opaengine.ProvenanceData,
		opaengine.ProvenanceBuiltin,
		opaengine.ProvenanceStatic,
		opaengine.ProvenanceUnresolved,
	} {
		if count := reads.CountWithProvenance(provenance); count > 0 {
			fmt.Fprintf(out, "  chosen by %-11s %14d\n", provenance.String()+":", count)
		}
	}

	fmt.Fprintln(out)
	table := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(table, "PATH\tCHOSEN BY\tWHERE\tRULE")
	for _, read := range reads.Reads {
		chosenBy := read.Provenance.String()
		switch {
		case read.Origin != "":
			chosenBy += " (" + read.Origin + ")"
		case read.Trace != nil && read.Trace.Term != "":
			chosenBy += " (" + read.Trace.Term + ")"
		}
		if read.UnderNegation {
			chosenBy += ", negated"
		}
		fmt.Fprintf(table, "%s\t%s\t%s:%d\t%s\n", read.Path, chosenBy, read.File, read.Line, read.Rule)
	}
	table.Flush()

	// Kept apart from the reads above, and counted apart, because these name no
	// document: whatever answered the call is what they read.
	if len(reads.Taints) > 0 {
		fmt.Fprintf(out, "\nvalues read from outside the policy: %d\n", len(reads.Taints))
		for _, taint := range reads.Taints {
			fmt.Fprintf(out, "  %s from %s at %s:%d\n", taint.Ref, describeSource(taint), taint.File, taint.Line)
			for _, decision := range taint.Decisions {
				reaches := "reaches " + decision.Name
				if decision.UnderNegation {
					reaches += ", to deny"
				}
				fmt.Fprintf(out, "    %s\n", reaches)
			}
		}
	}

	// The request held against values the policy writes. Who can put such a
	// value in the request is not in the policy, the same way who writes a
	// document is not, and the side says what putting it there does.
	if len(reads.Checks) > 0 {
		fmt.Fprintf(out, "\nchecks on the request against values the policy writes: %d\n", len(reads.Checks))
		for _, check := range reads.Checks {
			fmt.Fprintf(out, "  %s at %s:%d\n", check.Expression(), check.File, check.Line)
			for _, decision := range check.Decisions {
				fmt.Fprintf(out, "    %s\n", describeCheckSide(decision))
			}
		}
	}

	if indexed := opaengine.SubjectIndexedReads(shape, reads); len(indexed) > 0 {
		fmt.Fprintf(out, "\nreads the subject (%s) indexes itself:\n", shape.Subject)
		subjectTable := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		for _, read := range indexed {
			fmt.Fprintf(subjectTable, "  %s\t%s:%d\n", read.Path, read.File, read.Line)
		}
		subjectTable.Flush()
		fmt.Fprintln(out, "  whether any of these is a finding depends on who can write them,")
		fmt.Fprintln(out, "  which is not in the policy and has to be declared.")
	}

	if matched := opaengine.SubjectMatchedReads(shape, reads); len(matched) > 0 {
		fmt.Fprintf(out, "\nreads that look the subject (%s) up by value:\n", shape.Subject)
		matchedTable := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		for _, read := range matched {
			fmt.Fprintf(matchedTable, "  %s\t%s:%d\n", read.Path, read.File, read.Line)
		}
		matchedTable.Flush()
		fmt.Fprintln(out, "  whether any of these is a finding depends on who can add the subject to them,")
		fmt.Fprintln(out, "  which is not in the policy either.")
	}

	if len(reads.SkippedUnderWith) > 0 {
		fmt.Fprintf(out, "\nrules reached only under a with modifier, left out of the decisions:\n")
		for _, rule := range reads.SkippedUnderWith {
			fmt.Fprintf(out, "  %s\n", rule)
		}
	}
	for _, warning := range reads.Warnings {
		fmt.Fprintf(out, "\nwarning: %s\n", warning)
	}
}
