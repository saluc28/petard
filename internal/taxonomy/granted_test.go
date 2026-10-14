package taxonomy

import (
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const grantedPolicy = `package app

# METADATA
# entrypoint: true
default allow := false

allow if {
	input.method == "GET"
	split(input.path, "/")[1] == "public"
}

# METADATA
# entrypoint: true
default allow_admin := false

allow_admin if data.admins[input.user]
`

// A request given as granted is read, and each decision that grants it is
// named with it, against the data of the analysis. One no decision grants stops
// the run, and the error says what is known about why.
func TestLoadTakesTheRequestsGivenAsGranted(t *testing.T) {
	dir := t.TempDir()
	policy := filepath.Join(dir, "policy")
	writeCaseFile(t, filepath.Join(policy, "app.rego"), grantedPolicy)
	writeCaseFile(t, filepath.Join(dir, "data", "data.json"), `{"admins": {"alice": true}}`)

	file := func(name, content string) string {
		path := filepath.Join(dir, name)
		writeCaseFile(t, path, content)
		return path
	}
	public := file("public.json", `{"method": "GET", "path": "/public/docs/intro"}`)
	alice := file("alice.yaml", "user: alice\nmethod: GET\npath: /public/index\n")
	admin := file("admin.json", `{"user": "alice", "method": "POST", "path": "/private"}`)
	refused := file("refused.json", `{"method": "POST", "path": "/private"}`)
	list := file("list.json", `["GET", "/public"]`)

	tests := []struct {
		name      string
		inputs    Inputs
		decisions [][]string
		err       error
		says      string
	}{
		{
			name:      "one decision grants it",
			inputs:    Inputs{Paths: []string{policy}, DataPath: filepath.Join(dir, "data"), Granted: []string{public}},
			decisions: [][]string{{"data.app.allow"}},
		},
		{
			name:      "two requests, one of them granted by both decisions",
			inputs:    Inputs{Paths: []string{policy}, DataPath: filepath.Join(dir, "data"), Granted: []string{alice, admin}},
			decisions: [][]string{{"data.app.allow", "data.app.allow_admin"}, {"data.app.allow_admin"}},
		},
		{
			name:   "no decision grants it",
			inputs: Inputs{Paths: []string{policy}, DataPath: filepath.Join(dir, "data"), Granted: []string{public, refused}},
			err:    ErrNotGranted,
			says:   "refused.json",
		},
		{
			// The decision that would grant it reads the admins, and there are
			// none to read.
			name:   "no decision grants it without the data",
			inputs: Inputs{Paths: []string{policy}, Granted: []string{admin}},
			err:    ErrNotGranted,
			says:   "no data was given",
		},
		{
			name:   "every decision is declared to deny",
			inputs: Inputs{Paths: []string{policy}, DenyEntrypoints: []string{"app/allow", "app/allow_admin"}, Granted: []string{public}},
			err:    ErrNotGranted,
			says:   "declared to deny",
		},
		{
			name:   "a file that holds no object",
			inputs: Inputs{Paths: []string{policy}, Granted: []string{list}},
			says:   "a request has to be an object",
		},
		{
			name:   "a file that is not there",
			inputs: Inputs{Paths: []string{policy}, Granted: []string{filepath.Join(dir, "missing.json")}},
			says:   "missing.json",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := Load(t.Context(), tt.inputs)
			if tt.says != "" {
				if err == nil || !strings.Contains(err.Error(), tt.says) || (tt.err != nil && !errors.Is(err, tt.err)) {
					t.Fatalf("Load() error = %v, want one that says %q", err, tt.says)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			var decisions [][]string
			for i, request := range a.Granted {
				if request.File != tt.inputs.Granted[i] || len(request.Input) == 0 {
					t.Errorf("request %d = %+v, want the one read from %s", i, request, tt.inputs.Granted[i])
				}
				decisions = append(decisions, request.Decisions)
			}
			if !slices.EqualFunc(decisions, tt.decisions, slices.Equal[[]string]) {
				t.Errorf("granted by %v, want %v", decisions, tt.decisions)
			}
		})
	}
}

// The request given is where the fourth signal of PTD-OPA-012 starts, from the
// command line down to the finding: a decision that holds the path against a
// component it computes is asked, and proven to grant a traversal.
func TestRunStartsFromARequestGivenAsGranted(t *testing.T) {
	dir := t.TempDir()
	policy := filepath.Join(dir, "policy")
	writeCaseFile(t, filepath.Join(policy, "app.rego"), grantedPolicy)
	gateway := filepath.Join(dir, "gateway.yaml")
	writeCaseFile(t, gateway, canonicalGateway("input.path", "dot-segments"))
	request := filepath.Join(dir, "public.json")
	writeCaseFile(t, request, `{"method": "GET", "path": "/public/docs/intro"}`)

	for name, tt := range map[string]struct {
		granted  []string
		expected []string
	}{
		"without the request": {nil, []string{"candidate input.path"}},
		"with it":             {[]string{request}, []string{`finding input.path "/public/docs/intro/../../../petard-beyond"`}},
	} {
		t.Run(name, func(t *testing.T) {
			a, err := Load(t.Context(), Inputs{Paths: []string{policy}, EnforcementPoint: gateway, Granted: tt.granted})
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			found, err := Run(t.Context(), a)
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			if got := summaries(found.LooseMatch); !slices.Equal(got, tt.expected) {
				t.Errorf("results = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestInputValue(t *testing.T) {
	request := map[string]any{
		"method":  "GET",
		"request": map[string]any{"path": "/public", "headers": map[string]any{}},
	}
	tests := []struct {
		part  string
		value any
		found bool
	}{
		{"input.method", "GET", true},
		{"input.request.path", "/public", true},
		{"input.request.query", nil, false},
		{"input.method.verb", nil, false},
		{"input.missing.path", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.part, func(t *testing.T) {
			value, found := inputValue(request, tt.part)
			if found != tt.found || value != tt.value {
				t.Errorf("inputValue(%s) = %v, %t, want %v, %t", tt.part, value, found, tt.value, tt.found)
			}
		})
	}
}
