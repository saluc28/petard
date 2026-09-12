package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
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

// The three calls of an ingest job and the schema install have an order, and it
// is not a preference: a payload whose kinds no installed schema declares is
// accepted and then produces nodes the UI cannot classify.
func TestRunInstallsTheSchemaBeforeUploading(t *testing.T) {
	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		if strings.HasSuffix(r.URL.Path, "/file-upload/start") {
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"data":{"id":7}}`))
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	t.Setenv(envTokenID, "token-id")
	t.Setenv(envTokenKey, "token-key")

	var stdout, stderr bytes.Buffer
	args := analysisArgs("-url", server.URL, "-install", "-upload")
	if code := run(args, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}

	expected := []string{
		"PUT /api/v2/extensions",
		"POST /api/v2/file-upload/start",
		"POST /api/v2/file-upload/7",
		"POST /api/v2/file-upload/7/end",
	}
	if len(calls) != len(expected) {
		t.Fatalf("calls = %v, want %v", calls, expected)
	}
	for i, call := range expected {
		if calls[i] != call {
			t.Errorf("call %d = %q, want %q", i, calls[i], call)
		}
	}

	if out := stdout.String(); !strings.Contains(out, "ingest job 7") {
		t.Errorf("the report does not name the job, which is the only handle on what happens next:\n%s", out)
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
