package opaengine

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
)

// The fixture of phase 2 holds the same policy written twice, once in Rego v1
// and once in v0. It is the dual parsing test from day one, and it is real
// Rego rather than a snippet written to make the loader look good.
func fixtureDir(t *testing.T, version string) string {
	t.Helper()
	return filepath.Join("..", "..", "fixtures", "vulnerable-bundle", version)
}

func TestParseModeString(t *testing.T) {
	modes := map[ParseMode]string{
		ParseModeAuto: "auto",
		ParseModeV1:   "v1",
		ParseModeV0:   "v0",
		ParseMode(9):  "unknown",
	}
	for mode, expected := range modes {
		if got := mode.String(); got != expected {
			t.Errorf("ParseMode(%d).String() = %q, want %q", mode, got, expected)
		}
	}
}

// TestLoadFixtureSyntaxes is the table EXPECTED.md declares: each bundle
// parses under its own syntax, fails under the other, and is recognized under
// auto. A tool that reads other people's policies lives or dies on this.
func TestLoadFixtureSyntaxes(t *testing.T) {
	tests := []struct {
		name            string
		version         string
		mode            ParseMode
		expectedVersion ast.RegoVersion
		expectedErr     error
	}{
		{
			name:            "v1 sources, v1 parser",
			version:         "policy-v1",
			mode:            ParseModeV1,
			expectedVersion: ast.RegoV1,
		},
		{
			name:        "v1 sources, v0 parser",
			version:     "policy-v1",
			mode:        ParseModeV0,
			expectedErr: ErrParse,
		},
		{
			name:            "v1 sources, auto",
			version:         "policy-v1",
			mode:            ParseModeAuto,
			expectedVersion: ast.RegoV1,
		},
		{
			name:            "v0 sources, v0 parser",
			version:         "policy-v0",
			mode:            ParseModeV0,
			expectedVersion: ast.RegoV0,
		},
		{
			name:        "v0 sources, v1 parser",
			version:     "policy-v0",
			mode:        ParseModeV1,
			expectedErr: ErrParse,
		},
		{
			name:            "v0 sources, auto falls back",
			version:         "policy-v0",
			mode:            ParseModeAuto,
			expectedVersion: ast.RegoV0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bundle, err := Load([]string{fixtureDir(t, tt.version)}, tt.mode)

			if !errors.Is(err, tt.expectedErr) {
				t.Fatalf("Load() error = %v, want %v", err, tt.expectedErr)
			}
			if tt.expectedErr != nil {
				if bundle != nil {
					t.Error("Load() returned a bundle together with an error")
				}
				return
			}
			if bundle.RegoVersion != tt.expectedVersion {
				t.Errorf("RegoVersion = %s, want %s", bundle.RegoVersion, tt.expectedVersion)
			}
		})
	}
}

func TestLoadRecordsFiles(t *testing.T) {
	dir := fixtureDir(t, "policy-v1")
	bundle, err := Load([]string{dir}, ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	expected := []string{"admin.rego", "authz.rego", "enrichment.rego", "platform.rego", "publish.rego", "review.rego", "risk.rego", "tenant_policy.rego"}
	if len(bundle.Files) != len(expected) {
		t.Fatalf("Files = %v, want %d files", bundle.Files, len(expected))
	}
	for i, name := range expected {
		if want := filepath.ToSlash(filepath.Join(dir, name)); bundle.Files[i] != want {
			t.Errorf("Files[%d] = %q, want %q", i, bundle.Files[i], want)
		}
	}

	// Provenance travels into the exported graph, so a run on Windows and a run
	// on macOS have to name the same file the same way.
	for _, file := range bundle.Files {
		if strings.Contains(file, `\`) {
			t.Errorf("file %q holds a backslash, paths must be slash separated", file)
		}
	}
}

// The annotations are what tells the analysis which rules are decisions. They
// are read while parsing or not at all, so this test guards a parser option
// that nothing else would notice until phase 3.
func TestLoadProcessesAnnotations(t *testing.T) {
	bundle, err := Load([]string{fixtureDir(t, "policy-v1")}, ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	var entrypoints []string
	for _, ref := range bundle.Compiler.GetAnnotationSet().Flatten() {
		if ref.Annotations != nil && ref.Annotations.Entrypoint {
			entrypoints = append(entrypoints, ref.Path.String())
		}
	}

	expected := []string{
		"data.quill.admin.allow",
		"data.quill.authz.allow",
		"data.quill.enrichment.allow",
		"data.quill.platform.allow_console",
		"data.quill.platform.allow_reading_room",
		"data.quill.publish.allow",
		"data.quill.review.allow_guarded",
		"data.quill.review.allow_unguarded",
		"data.quill.risk.allow_default_option",
		"data.quill.risk.allow_defensive",
		"data.quill.risk.allow_positive_side",
		"data.quill.risk.allow_vulnerable",
		"data.quill.tenant_policy.allow",
	}
	if len(entrypoints) != len(expected) {
		t.Fatalf("entrypoints = %v, want %v", entrypoints, expected)
	}
	for i, path := range expected {
		if entrypoints[i] != path {
			t.Errorf("entrypoint[%d] = %q, want %q", i, entrypoints[i], path)
		}
	}
}

func TestLoadAcceptsSingleFiles(t *testing.T) {
	file := filepath.Join(fixtureDir(t, "policy-v1"), "authz.rego")
	bundle, err := Load([]string{file, file}, ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(bundle.Files) != 1 {
		t.Errorf("Files = %v, want the repeated path collapsed into one", bundle.Files)
	}
}

func TestLoadErrors(t *testing.T) {
	tests := []struct {
		name        string
		files       map[string]string
		paths       []string
		expectedErr error
	}{
		{
			name:        "no rego file in the directory",
			files:       map[string]string{"data.json": `{"users": {}}`},
			expectedErr: ErrNoModules,
		},
		{
			name:        "path does not exist",
			paths:       []string{filepath.Join("does", "not", "exist")},
			expectedErr: os.ErrNotExist,
		},
		{
			// OPA calls an empty module a parse error, and Petard reports what
			// OPA decides rather than inventing a friendlier rule.
			name:        "empty rego file",
			files:       map[string]string{"empty.rego": ""},
			expectedErr: ErrParse,
		},
		{
			name: "a bundle cannot be half v1 and half v0",
			files: map[string]string{
				"new.rego": "package new\n\nallow if input.user == \"alice\"\n",
				"old.rego": "package old\n\nallow {\n\tinput.user == \"alice\"\n}\n",
			},
			expectedErr: ErrParse,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paths := tt.paths
			if paths == nil {
				paths = []string{writeSources(t, tt.files)}
			}

			_, err := Load(paths, ParseModeAuto)
			if !errors.Is(err, tt.expectedErr) {
				t.Fatalf("Load() error = %v, want %v", err, tt.expectedErr)
			}
		})
	}
}

// A mixed bundle is the one failure a reader has to be able to act on, so the
// message names every file that broke, not just the first one.
func TestLoadMixedBundleNamesEveryFile(t *testing.T) {
	dir := writeSources(t, map[string]string{
		"new.rego": "package new\n\nallow if input.user == \"alice\"\n",
		"old.rego": "package old\n\nallow {\n\tinput.user == \"alice\"\n}\n",
	})

	_, err := Load([]string{dir}, ParseModeAuto)
	if err == nil {
		t.Fatal("Load() error = nil, want a parse error")
	}
	for _, name := range []string{"new.rego", "old.rego"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error does not name %s:\n%v", name, err)
		}
	}
	for _, version := range []string{"rego v1", "rego v0"} {
		if !strings.Contains(err.Error(), version) {
			t.Errorf("error does not say which syntax was tried (%s):\n%v", version, err)
		}
	}
}

// writeSources writes files into a temporary directory and returns it.
func writeSources(t *testing.T, files map[string]string) string {
	t.Helper()

	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
	return dir
}
