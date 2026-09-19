package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/saluc28/bhgraph/client"
)

func fixture(name string) string {
	return filepath.Join("..", "..", "fixtures", "vulnerable-bundle", name)
}

// analysisArgs are the fixture with everything it takes to reach every kind of
// the model: without the data there are no principals, without the write model
// the escalation stays a candidate.
func analysisArgs(extra ...string) []string {
	return append(extra,
		"-write-model", fixture("write-model.yaml"),
		"-data", fixture("data"),
		fixture("policy-v1"),
	)
}

func TestRunWritesAPayloadBloodHoundWouldAccept(t *testing.T) {
	path := filepath.Join(t.TempDir(), "graph", "petard.json")

	var stdout, stderr bytes.Buffer
	if code := run(analysisArgs("-out", path), &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the payload: %v", err)
	}

	var payload struct {
		Graph struct {
			Nodes []struct {
				ID         string         `json:"id"`
				Kinds      []string       `json:"kinds"`
				Properties map[string]any `json:"properties"`
			} `json:"nodes"`
			Edges []struct {
				Kind  string `json:"kind"`
				Start struct {
					Value   string `json:"value"`
					MatchBy string `json:"match_by"`
				} `json:"start"`
			} `json:"edges"`
		} `json:"graph"`
	}
	if err := json.Unmarshal(content, &payload); err != nil {
		t.Fatalf("the payload is not the shape BloodHound ingests: %v", err)
	}
	if len(payload.Graph.Nodes) == 0 || len(payload.Graph.Edges) == 0 {
		t.Fatalf("nodes = %d, edges = %d, want a graph", len(payload.Graph.Nodes), len(payload.Graph.Edges))
	}

	// BloodHound uppercases object ids on ingest. Sending them any other way
	// describes nodes under ids the server will not have, and every later
	// lookup misses. The readable form has to survive somewhere, and that
	// somewhere is the name property.
	for _, node := range payload.Graph.Nodes {
		if node.ID != strings.ToUpper(node.ID) {
			t.Errorf("node id %q is not the id the server will store", node.ID)
		}
		if name, ok := node.Properties["name"].(string); !ok || name == "" {
			t.Errorf("node %q has no readable name", node.ID)
		}
	}
	for _, edge := range payload.Graph.Edges {
		if edge.Start.Value != strings.ToUpper(edge.Start.Value) {
			t.Errorf("edge %s starts at %q, which is not an id the server will have", edge.Kind, edge.Start.Value)
		}
	}
}

// instance is a stand in for BloodHound, answering the endpoints this command
// uses the way the real one does.
//
// It exists because every claim this command makes is about what a server
// answers, and a test that asserted on requests alone would pass against a
// server that accepts everything and holds nothing.
type instance struct {
	// calls is every request in the order it arrived, as "METHOD /path".
	calls []string

	// extensionsFlag is what GET /api/v2/features reports for the flag that
	// governs both the extensions route and whether pathfinding sees these
	// kinds.
	extensionsFlag bool

	// featuresStatus, when set, is returned by the features endpoint instead of
	// the flags, which is how a token that cannot read the configuration looks.
	featuresStatus int

	// tasks is what completed-tasks answers, one entry per call, so that a test
	// can hand back an empty list first and a finished job afterwards.
	tasks [][]task

	// pathFound decides whether the shortest path endpoint finds a path.
	pathFound bool

	// pathQueries is the raw query string of every shortest path request.
	pathQueries []string
}

type task struct {
	FileName string   `json:"file_name"`
	Errors   []string `json:"errors"`
}

func (i *instance) start(t *testing.T) string {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		i.calls = append(i.calls, r.Method+" "+r.URL.Path)

		switch {
		case r.URL.Path == "/api/v2/features":
			if i.featuresStatus != 0 {
				w.WriteHeader(i.featuresStatus)
				return
			}
			_, _ = fmt.Fprintf(w, `{"data":[{"key":%q,"enabled":%t}]}`,
				client.FeatureFlagExtensions, i.extensionsFlag)

		case strings.HasSuffix(r.URL.Path, "/file-upload/start"):
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"data":{"id":7}}`))

		case strings.HasSuffix(r.URL.Path, "/completed-tasks"):
			var next []task
			if len(i.tasks) > 0 {
				next, i.tasks = i.tasks[0], i.tasks[1:]
			}
			body, err := json.Marshal(map[string]any{"data": next})
			if err != nil {
				t.Errorf("encoding the tasks: %v", err)
			}
			_, _ = w.Write(body)

		case r.URL.Path == "/api/v2/graphs/shortest-path":
			i.pathQueries = append(i.pathQueries, r.URL.RawQuery)
			if !i.pathFound {
				// The real server answers 404 "path not found" rather than an
				// empty graph, which is why this is a status and not a body.
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"errors":[{"message":"path not found"}]}`))
				return
			}
			_, _ = w.Write([]byte(`{"data":{"nodes":{"1":{}},"edges":[{"kind":"PTD_CanEscalateTo"}]}}`))

		default:
			w.WriteHeader(http.StatusAccepted)
		}
	}))
	t.Cleanup(server.Close)

	t.Setenv(envTokenID, "token-id")
	t.Setenv(envTokenKey, "token-key")
	return server.URL
}

// done is a job whose single file was processed without errors.
func done() [][]task { return [][]task{{{FileName: "petard.json"}}} }

// The three calls of an ingest job and the schema install have an order, and it
// is not a preference: a payload whose kinds no installed schema declares is
// accepted and then produces nodes the UI cannot classify.
func TestRunInstallsTheSchemaBeforeUploading(t *testing.T) {
	server := &instance{extensionsFlag: true, tasks: done()}
	base := server.start(t)

	var stdout, stderr bytes.Buffer
	args := analysisArgs("-url", base, "-install", "-upload")
	if code := run(args, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}

	expected := []string{
		"GET /api/v2/features",
		"PUT /api/v2/extensions",
		"POST /api/v2/file-upload/start",
		"POST /api/v2/file-upload/7",
		"POST /api/v2/file-upload/7/end",
		"GET /api/v2/file-upload/7/completed-tasks",
	}
	if len(server.calls) != len(expected) {
		t.Fatalf("calls = %v, want %v", server.calls, expected)
	}
	for i, call := range expected {
		if server.calls[i] != call {
			t.Errorf("call %d = %q, want %q", i, server.calls[i], call)
		}
	}

	if out := stdout.String(); !strings.Contains(out, "ingest job 7") {
		t.Errorf("the report does not name the job, which is the only handle on what happens next:\n%s", out)
	}
}

// Ingest returning means the payload was accepted, not that the graph holds it.
// A run that stopped there would report success on a job that failed a second
// later, so it waits, and waiting means asking more than once.
func TestRunWaitsForTheIngestToBeProcessed(t *testing.T) {
	jobPollInterval = time.Millisecond
	t.Cleanup(func() { jobPollInterval = 2 * time.Second })

	server := &instance{extensionsFlag: true, tasks: [][]task{{}, {}, {{FileName: "petard.json"}}}}
	base := server.start(t)

	var stdout, stderr bytes.Buffer
	if code := run(analysisArgs("-url", base, "-upload"), &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}

	asked := 0
	for _, call := range server.calls {
		if strings.HasSuffix(call, "/completed-tasks") {
			asked++
		}
	}
	if asked != 3 {
		t.Errorf("asked for the status %d times, want 3: an empty task list means still working", asked)
	}
	if out := stdout.String(); !strings.Contains(out, "no errors") {
		t.Errorf("the report does not say the job finished cleanly:\n%s", out)
	}
}

// A job that finished badly is the case worth catching: every call before it
// returned a success, and the errors are the only place the failure shows.
func TestRunReportsWhatTheIngestRejected(t *testing.T) {
	server := &instance{
		extensionsFlag: true,
		tasks:          [][]task{{{FileName: "petard.json", Errors: []string{"unknown kind PTD_Nonsense"}}}},
	}
	base := server.start(t)

	var stdout, stderr bytes.Buffer
	if code := run(analysisArgs("-url", base, "-upload"), &stdout, &stderr); code != exitFailure {
		t.Fatalf("exit code = %d, want %d: a job with errors is not a success", code, exitFailure)
	}
	if !strings.Contains(stderr.String(), "PTD_Nonsense") {
		t.Errorf("stderr does not carry what the server rejected: %s", stderr.String())
	}
}

// The criterion the whole export exists for. Everything else can pass on an
// instance where the graph is present and unwalkable, and only asking the
// server for the path answers that.
func TestRunVerifiesTheEscalationIsWalkable(t *testing.T) {
	server := &instance{extensionsFlag: true, tasks: done(), pathFound: true}
	base := server.start(t)

	var stdout, stderr bytes.Buffer
	if code := run(analysisArgs("-url", base, "-install", "-upload", "-verify"), &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}

	// The fixture emits two escalations, the 001 to 003 chain and the split
	// grant, and every one of them has to be asked about: a query missing means
	// the check silently skipped a path it claims is walkable.
	if len(server.pathQueries) != 2 {
		t.Fatalf("shortest path queries = %v, want the two escalations the fixture emits", server.pathQueries)
	}
	for _, raw := range server.pathQueries {
		query, err := url.ParseQuery(raw)
		if err != nil {
			t.Fatalf("parsing the query: %v", err)
		}

		// Without only_traversable the server walks edges the UI never will, and
		// the answer stops meaning what the report says it means.
		if query.Get("only_traversable") != "true" {
			t.Errorf("query = %v, want only_traversable=true", raw)
		}
		for _, param := range []string{"start_node", "end_node"} {
			value := query.Get(param)
			if value == "" {
				t.Errorf("%s is empty in %q", param, raw)
				continue
			}
			// BloodHound uppercases object ids on ingest, so asking in any other
			// case looks for a node the server does not have and answers 404 for
			// the wrong reason.
			if value != strings.ToUpper(value) {
				t.Errorf("%s = %q, which is not an id the server will have", param, value)
			}
		}
	}

	if out := stdout.String(); !strings.Contains(out, "2 of 2 escalations are walkable") {
		t.Errorf("the report does not say both paths were walked:\n%s", out)
	}
}

// An escalation the server will not walk is a failure and not a note. The graph
// would be claiming a path that nobody can take, which is the one thing this
// tool must not do.
func TestRunFailsWhenAnEscalationDoesNotWalk(t *testing.T) {
	server := &instance{extensionsFlag: true, tasks: done(), pathFound: false}
	base := server.start(t)

	var stdout, stderr bytes.Buffer
	if code := run(analysisArgs("-url", base, "-upload", "-verify"), &stdout, &stderr); code != exitFailure {
		t.Fatalf("exit code = %d, want %d", code, exitFailure)
	}
	if !strings.Contains(stdout.String(), "does not walk it") {
		t.Errorf("the report does not name the escalation that failed:\n%s", stdout.String())
	}
}

// With the flag off, pathfinding answers from the built-in kinds alone and
// says "path not found" whether or not the path exists. A verification that can
// answer no for the wrong reason is worse than none, so this is a refusal.
func TestRunRefusesWhenTheExtensionFlagIsOff(t *testing.T) {
	server := &instance{extensionsFlag: false, tasks: done()}
	base := server.start(t)

	var stdout, stderr bytes.Buffer
	if code := run(analysisArgs("-url", base, "-verify"), &stdout, &stderr); code != exitFailure {
		t.Fatalf("exit code = %d, want %d", code, exitFailure)
	}
	if !strings.Contains(stderr.String(), client.FeatureFlagExtensions) {
		t.Errorf("stderr does not name the flag to turn on: %s", stderr.String())
	}
	for _, call := range server.calls {
		if strings.Contains(call, "shortest-path") {
			t.Error("it asked for a path anyway, and that answer would have meant nothing")
		}
	}
}

// A token that cannot read the feature flags is a weaker credential and not a
// broken instance, so the run goes on. What it must not do is report a missing
// path as if the reason were known.
func TestRunSaysWhenItCouldNotReadTheFlag(t *testing.T) {
	server := &instance{featuresStatus: http.StatusForbidden, tasks: done()}
	base := server.start(t)

	var stdout, stderr bytes.Buffer
	if code := run(analysisArgs("-url", base, "-verify"), &stdout, &stderr); code != exitFailure {
		t.Fatalf("exit code = %d, want %d", code, exitFailure)
	}
	if !strings.Contains(stdout.String(), "could not read") {
		t.Errorf("the report does not say the flag was unreadable:\n%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), client.FeatureFlagExtensions) {
		t.Errorf("the failure does not offer the flag as a cause, so it reads as a settled no: %s", stderr.String())
	}
}

// A token on a command line ends up in the shell history and in the process
// list. Refusing to run without the environment is the whole of the protection,
// so it has to be a refusal and not a warning.
func TestRunRefusesToSendWithoutCredentials(t *testing.T) {
	t.Setenv(envTokenID, "")
	t.Setenv(envTokenKey, "")

	var stdout, stderr bytes.Buffer
	args := analysisArgs("-url", "https://bloodhound.invalid", "-upload")
	if code := run(args, &stdout, &stderr); code != exitFailure {
		t.Fatalf("exit code = %d, want %d", code, exitFailure)
	}
	if !strings.Contains(stderr.String(), envTokenID) {
		t.Errorf("stderr does not say where the credentials come from: %s", stderr.String())
	}
}

func TestRunRefusesInvocationsThatAskForNothing(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "no paths", args: nil},
		{name: "install without a url", args: analysisArgs("-install")},
		{name: "neither a file nor a url", args: analysisArgs()},
		{name: "both syntaxes forced", args: analysisArgs("-rego-v0", "-rego-v1", "-out", "x.json")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(tt.args, &stdout, &stderr); code != exitUsage {
				t.Errorf("exit code = %d, want %d (stderr: %s)", code, exitUsage, stderr.String())
			}
		})
	}
}

// The subject declared on the command line reaches the analysis, and one no
// decision reads is refused before anything is written.
func TestRunRefusesASubjectNothingReads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "petard.json")

	var stdout, stderr bytes.Buffer
	if code := run(analysisArgs("-out", path, "-subject", "input.requester"), &stdout, &stderr); code != exitFailure {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitFailure, stderr.String())
	}
	if !strings.Contains(stderr.String(), "no decision reads the declared subject: input.requester") {
		t.Errorf("stderr does not say the subject is read by nothing: %s", stderr.String())
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("a payload was written for an analysis that was refused (stat: %v)", err)
	}
}

// A decision declared to deny on the command line reaches the analysis, and one
// that names no rule is refused like any other declaration.
func TestRunRefusesADecisionToDenyThatNamesNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "petard.json")

	var stdout, stderr bytes.Buffer
	if code := run(analysisArgs("-out", path, "-deny-entrypoint", "quill/violation"), &stdout, &stderr); code != exitFailure {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitFailure, stderr.String())
	}
	if !strings.Contains(stderr.String(), "no rule has the declared entrypoint path: quill/violation") {
		t.Errorf("stderr does not name the declaration: %s", stderr.String())
	}
}
