// Command export-opengraph turns a policy into a BloodHound OpenGraph.
//
// It runs the same analysis analyze-opa reports on, assembles the internal
// graph, and writes it as an ingest payload. Pointed at a BloodHound instance
// it can also install the extension definition schema, run the ingest job, and
// ask the server to walk the escalations it just uploaded, which is the only
// answer that says the round trip works rather than that every step returned
// 200.
//
// The credentials are read from the environment and cannot be passed as flags.
// A token on a command line ends up in the shell history and in the process
// list of every user on the machine, and this one signs requests that can write
// to the graph.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/saluc28/bhgraph"
	"github.com/saluc28/bhgraph/client"

	"github.com/saluc28/petard/internal/graph"
	"github.com/saluc28/petard/internal/opaengine"
	"github.com/saluc28/petard/internal/opengraph"
	"github.com/saluc28/petard/internal/taxonomy"
	"github.com/saluc28/petard/queries"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2
)

// The environment variables the credentials come from. They are named after
// the product rather than after this tool, so that one export in a shell serves
// however many commands learn to talk to the same instance.
const (
	envTokenID  = "BLOODHOUND_TOKEN_ID"
	envTokenKey = "BLOODHOUND_TOKEN_KEY"
)

// repeatedString is a flag that may be given more than once, the way opa build
// takes its entrypoints.
type repeatedString []string

func (r *repeatedString) String() string { return strings.Join(*r, " ") }

func (r *repeatedString) Set(value string) error {
	*r = append(*r, value)
	return nil
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("export-opengraph", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprint(stderr, "usage: export-opengraph [flags] <path>...\n\n"+
			"Paths are Rego files or directories holding them.\n"+
			"With -url, the credentials are read from "+envTokenID+" and "+envTokenKey+".\n\n")
		flags.PrintDefaults()
	}

	regoV0 := flags.Bool("rego-v0", false, "parse as Rego v0, like opa --v0-compatible")
	regoV1 := flags.Bool("rego-v1", false, "parse as Rego v1 and do not fall back to v0")
	var entrypoints repeatedString
	flags.Var(&entrypoints, "entrypoint", "a rule the PEP queries, or a field of what it returns, as data.authz.allow or authz/allow; repeat for more")
	var denyEntrypoints repeatedString
	flags.Var(&denyEntrypoints, "deny-entrypoint", "a rule the PEP queries to refuse the request when it holds or collects anything, as k8sallowedrepos/violation; repeat for more")
	subject := flags.String("subject", "", "the part of the request that names who is asking, as input.user; without it, it is recognized")
	dataPath := flags.String("data", "", "path to the concrete data; without it there are no principals and no capabilities")
	writeModelPath := flags.String("write-model", "", "path to the write model; without it every match stays a candidate")
	maxCallDepth := flags.Int("max-call-depth", 0, "how many calls deep to follow an argument (0 for the default)")
	maxCallPaths := flags.Int("max-call-paths", 0, "how many call paths to explore per reference (0 for the default)")
	maxResiduals := flags.Int("max-residuals", 0, "how many residual conditions to report per decision (0 for the default)")

	out := flags.String("out", "", "write the payload here; without it nothing is written to disk")
	url := flags.String("url", "", "base url of the BloodHound API; without it nothing is sent")
	install := flags.Bool("install", false, "install the extension definition schema and the saved queries before uploading")
	prune := flags.Bool("prune-queries", false, "delete the saved queries of Petard this build no longer has, such as one renamed since it was installed")
	upload := flags.Bool("upload", false, "upload the payload as an ingest job")
	verify := flags.Bool("verify", false, "ask the server to walk every escalation the payload declares")
	wait := flags.Duration("wait", 2*time.Minute, "how long to wait for the ingest to be processed")

	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	paths := flags.Args()
	if len(paths) == 0 {
		flags.Usage()
		return exitUsage
	}
	if *regoV0 && *regoV1 {
		fmt.Fprintln(stderr, "export-opengraph: -rego-v0 and -rego-v1 ask for opposite things")
		return exitUsage
	}
	if (*install || *prune || *upload || *verify) && *url == "" {
		fmt.Fprintln(stderr, "export-opengraph: -install, -prune-queries, -upload and -verify need -url")
		return exitUsage
	}
	if *out == "" && !*install && !*prune && !*upload && !*verify {
		fmt.Fprintln(stderr, "export-opengraph: nothing to do, give -out or -url with -install, -prune-queries, -upload or -verify")
		return exitUsage
	}

	mode := opaengine.ParseModeAuto
	switch {
	case *regoV0:
		mode = opaengine.ParseModeV0
	case *regoV1:
		mode = opaengine.ParseModeV1
	}

	ctx := context.Background()
	payload, err := build(ctx, taxonomy.Inputs{
		Paths:           paths,
		Mode:            mode,
		Entrypoints:     entrypoints,
		DenyEntrypoints: denyEntrypoints,
		Subject:         *subject,
		DataPath:        *dataPath,
		WriteModelPath:  *writeModelPath,
		Limits: opaengine.Limits{
			MaxCallDepth: *maxCallDepth,
			MaxCallPaths: *maxCallPaths,
			MaxResiduals: *maxResiduals,
		},
	})
	if err != nil {
		fmt.Fprintf(stderr, "export-opengraph: %v\n", err)
		return exitFailure
	}
	fmt.Fprintf(stdout, "graph: %d nodes, %d edges\n", len(payload.Nodes), len(payload.Edges))

	if *out != "" {
		if err := write(*out, payload); err != nil {
			fmt.Fprintf(stderr, "export-opengraph: %v\n", err)
			return exitFailure
		}
		fmt.Fprintf(stdout, "written to %s\n", *out)
	}

	if *install || *prune || *upload || *verify {
		steps := remote{install: *install, prune: *prune, upload: *upload, verify: *verify, wait: *wait}
		if err := send(ctx, stdout, *url, payload, steps); err != nil {
			fmt.Fprintf(stderr, "export-opengraph: %v\n", err)
			return exitFailure
		}
	}
	return exitOK
}

// remote is what the run is asked to do against the instance, kept together
// because the steps have an order and a caller that passes three booleans in
// the wrong slots gets a plausible looking run that proves nothing.
type remote struct {
	install bool
	prune   bool
	upload  bool
	verify  bool
	wait    time.Duration
}

// build runs the analysis and turns what it found into a payload BloodHound
// would accept.
//
// The ids are uppercased before anything else looks at them. BloodHound
// uppercases object ids during ingest, so a payload that keeps its own case
// describes nodes under ids the server will not have: the next lookup, the next
// saved query and the next ingest would all miss. The readable form survives in
// the name property, which is what the UI shows.
func build(ctx context.Context, inputs taxonomy.Inputs) (bhgraph.Graph, error) {
	analysis, err := taxonomy.Load(inputs)
	if err != nil {
		return bhgraph.Graph{}, err
	}

	findings, err := taxonomy.Run(ctx, analysis)
	if err != nil {
		return bhgraph.Graph{}, err
	}
	g, _, err := taxonomy.Assemble(ctx, analysis, findings)
	if err != nil {
		return bhgraph.Graph{}, err
	}

	payload := opengraph.Payload(g)
	payload.UppercaseIDs()
	if err := opengraph.Validate(payload); err != nil {
		return bhgraph.Graph{}, err
	}
	return payload, nil
}

// write puts the payload where it was asked for, indented, because a payload
// somebody keeps is a payload somebody reads and diffs.
func write(path string, payload bhgraph.Graph) error {
	encoded, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Errorf("writing the payload: %w", err)
	}
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("creating %s: %w", dir, err)
		}
	}
	return os.WriteFile(path, append(encoded, '\n'), 0o600)
}

// send installs the schema, runs the ingest job and checks the result, in that
// order.
//
// The order is the whole point rather than a preference: a payload whose kinds
// no installed schema declares is accepted and then shows up as nodes the UI
// cannot classify and edges pathfinding will not walk. Installing first is what
// makes the graph structured instead of generic.
func send(ctx context.Context, out io.Writer, url string, payload bhgraph.Graph, steps remote) error {
	tokenID, tokenKey := os.Getenv(envTokenID), os.Getenv(envTokenKey)
	if tokenID == "" || tokenKey == "" {
		return fmt.Errorf("set %s and %s: a token on a command line ends up in the shell history", envTokenID, envTokenKey)
	}

	api, err := client.New(url, tokenID, tokenKey)
	if err != nil {
		return err
	}

	// confirmed says the extension flag was read and is on. It stays false when
	// the token could not read it, which changes nothing about what runs and
	// everything about what a later "does not walk" is allowed to claim.
	confirmed := false
	if steps.install || steps.verify {
		on, err := requireExtensions(ctx, out, api)
		if err != nil {
			return err
		}
		confirmed = on
	}

	if steps.install {
		schema := opengraph.Schema()
		if err := api.InstallExtension(ctx, schema); err != nil {
			return fmt.Errorf("installing the schema: %w", err)
		}
		// The traversable count is the whole difference between a graph the UI
		// walks and one it only draws, so it is worth saying out loud once the
		// schema is in.
		fmt.Fprintf(out, "schema installed, %d of %d relationship kinds are traversable\n",
			len(schema.TraversableKinds()), len(schema.RelationshipKinds))

		added, present, err := installQueries(ctx, api)
		if err != nil {
			return fmt.Errorf("saving the queries: %w", err)
		}
		fmt.Fprintf(out, "saved queries: %d added, %d already there\n", added, present)
	}

	// After installing, so that a run asked to do both never leaves the owner
	// with the old queries deleted and the new ones not saved.
	if steps.prune {
		if err := pruneQueries(ctx, out, api); err != nil {
			return fmt.Errorf("pruning the queries: %w", err)
		}
	}

	if steps.upload {
		job, err := api.Ingest(ctx, payload)
		if err != nil {
			return fmt.Errorf("uploading: %w", err)
		}
		fmt.Fprintf(out, "ingest job %d started\n", job)
		if err := awaitJob(ctx, out, api, job, steps.wait); err != nil {
			return err
		}
	}

	if steps.verify {
		return walkEscalations(ctx, out, api, payload, confirmed)
	}
	return nil
}

// installQueries saves the queries that come with Petard for the owner of the
// token, and reports how many it added and how many were there already.
//
// A query is left alone when the owner already has one under its name:
// BloodHound refuses a second query with a name the user has (CreateSavedQuery,
// cmd/api/src/api/v2/saved_queries.go:481 at v9.7.0), and one saved by an
// earlier version keeps its text until it is deleted.
func installQueries(ctx context.Context, api *client.Client) (added, present int, err error) {
	saved, err := savedQueries(ctx, api)
	if err != nil {
		return 0, 0, err
	}
	have := make(map[string]bool, len(saved))
	for _, query := range saved {
		have[query.Name] = true
	}

	all, err := queries.All()
	if err != nil {
		return 0, 0, err
	}
	for _, query := range all {
		if have[query.Name] {
			present++
			continue
		}
		body, err := json.Marshal(map[string]string{
			"name":        query.Name,
			"query":       query.Query,
			"description": query.Description,
		})
		if err != nil {
			return added, present, err
		}
		if _, err := api.Post(ctx, "/api/v2/saved-queries", body); err != nil {
			return added, present, fmt.Errorf("%s: %w", query.Name, err)
		}
		added++
	}
	return added, present, nil
}

// savedQuery is a query the owner of the token has, as the list endpoint
// returns it.
type savedQuery struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

// savedQueries lists what the owner of the token has saved.
//
// The endpoint defaults to the queries the caller owns and to a limit of ten
// thousand (saved_queries.go:134 at v9.7.1), so this neither pages nor reaches
// a query somebody else shared.
func savedQueries(ctx context.Context, api *client.Client) ([]savedQuery, error) {
	raw, err := api.Get(ctx, "/api/v2/saved-queries")
	if err != nil {
		return nil, err
	}
	var saved struct {
		Data []savedQuery `json:"data"`
	}
	if err := json.Unmarshal(raw, &saved); err != nil {
		return nil, fmt.Errorf("reading the saved queries: %w", err)
	}
	return saved.Data, nil
}

// pruneQueries deletes the saved queries that came from Petard and that this
// build no longer has, naming each one as it goes.
//
// Installing never deletes anything, and BloodHound keys a saved query by its
// name, so a query renamed between two versions of Petard is a second query
// rather than the same one: the owner keeps the old text, with the old
// question, next to the new one. Which is why this is a flag of its own and
// not part of -install. It removes what somebody may have come to rely on, and
// that is a decision for whoever runs it.
//
// A query counts as Petard's when the part of its name before the colon is one
// this build uses, which is a pattern id or "Petard". Anything else the owner
// saved is left alone, including a query about Petard's graph that they wrote
// and named themselves.
func pruneQueries(ctx context.Context, out io.Writer, api *client.Client) error {
	all, err := queries.All()
	if err != nil {
		return err
	}
	current, prefixes := make(map[string]bool, len(all)), map[string]bool{}
	for _, query := range all {
		current[query.Name] = true
		if prefix, _, found := strings.Cut(query.Name, ": "); found {
			prefixes[prefix] = true
		}
	}

	saved, err := savedQueries(ctx, api)
	if err != nil {
		return err
	}

	removed := 0
	for _, query := range saved {
		prefix, _, found := strings.Cut(query.Name, ": ")
		if !found || !prefixes[prefix] || current[query.Name] {
			continue
		}
		path := fmt.Sprintf("/api/v2/saved-queries/%d", query.ID)
		if _, err := api.Delete(ctx, path); err != nil {
			return fmt.Errorf("%s: %w", query.Name, err)
		}
		fmt.Fprintf(out, "  deleted %s\n", query.Name)
		removed++
	}
	fmt.Fprintf(out, "saved queries: %d deleted, %d left from this build\n", removed, len(all))
	return nil
}

// requireExtensions refuses to go on when the extension management flag is off.
//
// It governs two things, and the second is the one that bites. The extensions
// route is not registered without it, which fails loudly. Pathfinding also
// ignores the kinds of an installed schema without it, and that fails quietly:
// a shortest path query answers from the built-in AD and Azure kinds alone and
// returns "path not found", which is indistinguishable from an escalation that
// really is not walkable. A check that can answer no for the wrong reason is
// worse than no check, so this is a refusal.
//
// It reports whether the flag was read and is on. A flag that could not be read
// at all is not a refusal: reading the flags needs a role that can read the
// application configuration, and a token without it gets a 403 here, which is a
// weaker credential rather than a broken instance.
func requireExtensions(ctx context.Context, out io.Writer, api *client.Client) (bool, error) {
	on, err := api.FeatureEnabled(ctx, client.FeatureFlagExtensions)
	if err != nil {
		fmt.Fprintf(out, "could not read the %s flag, carrying on: %v\n", client.FeatureFlagExtensions, err)
		return false, nil
	}
	if !on {
		return false, fmt.Errorf("the %s feature flag is off: the extensions route is not registered and pathfinding "+
			"would ignore these kinds. Turn it on under Administration, Early Access Features", client.FeatureFlagExtensions)
	}
	return true, nil
}

// awaitJob waits for the ingest to be processed.
//
// Ingest returning means the payload was accepted, not that the graph holds it:
// processing is asynchronous, and a job that failed halfway looks exactly like
// one that succeeded until somebody asks. The completed tasks endpoint lists a
// task once it is done, with whatever errors it collected, so an empty list is
// "still working" and a non-empty one is the answer.
func awaitJob(ctx context.Context, out io.Writer, api *client.Client, job client.JobID, wait time.Duration) error {
	deadline := time.Now().Add(wait)
	for {
		raw, err := api.JobStatus(ctx, job)
		if err != nil {
			return fmt.Errorf("asking about job %d: %w", job, err)
		}

		var body struct {
			Data []struct {
				FileName string   `json:"file_name"`
				Errors   []string `json:"errors"`
			} `json:"data"`
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			return fmt.Errorf("reading the status of job %d: %w", job, err)
		}

		if len(body.Data) > 0 {
			var failed []string
			for _, task := range body.Data {
				failed = append(failed, task.Errors...)
			}
			if len(failed) > 0 {
				return fmt.Errorf("job %d finished with %d error(s): %s", job, len(failed), strings.Join(failed, "; "))
			}
			fmt.Fprintf(out, "job %d processed %d file(s) with no errors\n", job, len(body.Data))
			return nil
		}

		if time.Now().After(deadline) {
			return fmt.Errorf("job %d has not been processed after %s: raise -wait, or ask BloodHound directly", job, wait)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(jobPollInterval):
		}
	}
}

// jobPollInterval is how often awaitJob asks again. It is a variable rather
// than a constant so that the test which exercises the waiting can shrink it:
// a test that really slept two seconds to prove a loop works would be paid for
// on every run forever.
var jobPollInterval = 2 * time.Second

// walkEscalations asks the server to walk every escalation the payload declares.
//
// This is the criterion the whole export exists for. Everything before it can
// succeed on an instance where the graph is present and unwalkable: the schema
// installs, the ingest is accepted, the nodes appear, and pathfinding still
// refuses to cross an edge it was not told it may cross. Only asking for the
// path answers that, and asking with only_traversable is what makes the answer
// mean anything, since without it the server would happily walk edges the UI
// never will.
//
// The ids come from the payload, which build already uppercased. BloodHound
// uppercases object ids on the generic ingest path unless use_raw_object_id is
// on, so ids that are already uppercase match either way.
func walkEscalations(ctx context.Context, out io.Writer, api *client.Client, payload bhgraph.Graph, flagConfirmed bool) error {
	escalation := string(graph.EdgeKindCanEscalateTo)

	var edges []bhgraph.Edge
	for _, edge := range payload.Edges {
		if edge.Kind == escalation {
			edges = append(edges, edge)
		}
	}
	if len(edges) == 0 {
		fmt.Fprintf(out, "no %s to walk: the analysis found no escalation to check\n", escalation)
		return nil
	}

	walked := 0
	for _, edge := range edges {
		from, to := edge.Start.Value, edge.End.Value
		switch _, err := api.ShortestPath(ctx, from, to, true); {
		case err == nil:
			walked++
			fmt.Fprintf(out, "  %s -> %s: pathfinding walks it\n", from, to)
		case isNotFound(err):
			// A 404 here is an answer and not a failure: the server looked and
			// found nothing between those two nodes.
			fmt.Fprintf(out, "  %s -> %s: pathfinding does not walk it\n", from, to)
		default:
			return fmt.Errorf("asking for the path %s -> %s: %w", from, to, err)
		}
	}

	fmt.Fprintf(out, "%d of %d escalations are walkable in BloodHound\n", walked, len(edges))
	if walked == len(edges) {
		return nil
	}

	failure := fmt.Sprintf("%d escalation(s) the analysis emitted cannot be walked, so the graph says something the server does not",
		len(edges)-walked)
	if !flagConfirmed {
		// The flag could not be read, and with it off pathfinding answers from
		// the built-in kinds alone. Naming that here is the difference between
		// a finding and a wrong finding.
		failure += fmt.Sprintf(" (the %s flag could not be read, and with it off this is what the server answers "+
			"whether or not the path exists)", client.FeatureFlagExtensions)
	}
	return errors.New(failure)
}

// isNotFound reports whether the server answered 404.
//
// The shortest path endpoint returns 404 "path not found" when there is no
// path, rather than an empty graph, so this is how a result is told from a
// transport or credential problem.
func isNotFound(err error) bool {
	var apiErr *client.APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound
}
