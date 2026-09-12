// Command export-opengraph turns a policy into a BloodHound OpenGraph.
//
// It runs the same analysis analyze-opa reports on, assembles the internal
// graph, and writes it as an ingest payload. Pointed at a BloodHound instance
// it can also install the extension definition schema and run the ingest job,
// which is what turns a set of findings into a path somebody can walk in the
// UI.
//
// The credentials are read from the environment and cannot be passed as flags.
// A token on a command line ends up in the shell history and in the process
// list of every user on the machine, and this one signs requests that can write
// to the graph.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/saluc28/bhgraph"
	"github.com/saluc28/bhgraph/client"

	"github.com/saluc28/petard/internal/opaengine"
	"github.com/saluc28/petard/internal/opengraph"
	"github.com/saluc28/petard/internal/taxonomy"
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
	flags.Var(&entrypoints, "entrypoint", "a rule the PEP queries, as data.authz.allow or authz/allow; repeat for more")
	dataPath := flags.String("data", "", "path to the concrete data; without it there are no principals and no capabilities")
	writeModelPath := flags.String("write-model", "", "path to the write model; without it every match stays a candidate")
	maxCallDepth := flags.Int("max-call-depth", 0, "how many calls deep to follow an argument (0 for the default)")
	maxCallPaths := flags.Int("max-call-paths", 0, "how many call paths to explore per reference (0 for the default)")
	maxResiduals := flags.Int("max-residuals", 0, "how many residual conditions to report per decision (0 for the default)")

	out := flags.String("out", "", "write the payload here; without it nothing is written to disk")
	url := flags.String("url", "", "base url of the BloodHound API; without it nothing is sent")
	install := flags.Bool("install", false, "install the extension definition schema before uploading")
	upload := flags.Bool("upload", false, "upload the payload as an ingest job")

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
	if (*install || *upload) && *url == "" {
		fmt.Fprintln(stderr, "export-opengraph: -install and -upload need -url")
		return exitUsage
	}
	if *out == "" && !*install && !*upload {
		fmt.Fprintln(stderr, "export-opengraph: nothing to do, give -out or -url with -install or -upload")
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
		Paths:          paths,
		Mode:           mode,
		Entrypoints:    entrypoints,
		DataPath:       *dataPath,
		WriteModelPath: *writeModelPath,
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

	if *install || *upload {
		if err := send(ctx, stdout, *url, payload, *install, *upload); err != nil {
			fmt.Fprintf(stderr, "export-opengraph: %v\n", err)
			return exitFailure
		}
	}
	return exitOK
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

// send installs the schema and runs the ingest job, in that order.
//
// The order is the whole point rather than a preference: a payload whose kinds
// no installed schema declares is accepted and then shows up as nodes the UI
// cannot classify and edges pathfinding will not walk. Installing first is what
// makes the graph structured instead of generic.
func send(ctx context.Context, out io.Writer, url string, payload bhgraph.Graph, install, upload bool) error {
	tokenID, tokenKey := os.Getenv(envTokenID), os.Getenv(envTokenKey)
	if tokenID == "" || tokenKey == "" {
		return fmt.Errorf("set %s and %s: a token on a command line ends up in the shell history", envTokenID, envTokenKey)
	}

	api, err := client.New(url, tokenID, tokenKey)
	if err != nil {
		return err
	}

	if install {
		schema := opengraph.Schema()
		if err := api.InstallExtension(ctx, schema); err != nil {
			return fmt.Errorf("installing the schema: %w", err)
		}
		// The traversable count is the whole difference between a graph the UI
		// walks and one it only draws, so it is worth saying out loud once the
		// schema is in.
		fmt.Fprintf(out, "schema installed, %d of %d relationship kinds are traversable\n",
			len(schema.TraversableKinds()), len(schema.RelationshipKinds))
	}

	if upload {
		job, err := api.Ingest(ctx, payload)
		if err != nil {
			return fmt.Errorf("uploading: %w", err)
		}
		// The job id is the only handle on what happens next: ingest is
		// asynchronous, and what went wrong surfaces later or not at all.
		fmt.Fprintf(out, "ingest job %d started; ask BloodHound for its status\n", job)
	}
	return nil
}
