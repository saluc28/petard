package analyze

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// evidenceCase is a schema with a write model whose share rule cites the source, in a
// directory of its own beside an app directory that holds the source. It returns the
// directory of the schema and the source.
func evidenceCase(t *testing.T, citations string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	authz := filepath.Join(dir, "authz")
	app := filepath.Join(dir, "app", "api")
	for _, d := range []string{authz, app} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"schema.zed", "validation.yaml"} {
		raw, err := os.ReadFile(filepath.Join(spicedbFixture, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(authz, name), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writes, err := os.ReadFile(filepath.Join(spicedbFixture, "writes.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	via := `    via: "POST /api/v1/documents/{id}/viewers"`
	if !bytes.Contains(writes, []byte(via)) {
		t.Fatal("the fixture's share rule has moved")
	}
	writes = bytes.Replace(writes, []byte(via), []byte(via+"\n    evidence:\n"+citations), 1)
	files := map[string]string{
		filepath.Join(authz, "writes.yaml"): string(writes),
		filepath.Join(app, "share.go"):      "package api\n\nfunc share() {\n\tclient.WriteRelationships(ctx, req)\n}\n",
		filepath.Join(app, "admin.go"):      "package api\n\nfunc grant() {\n\tclient.WriteRelationships(ctx, req)\n}\n",
		filepath.Join(app, "share_test.go"): "package api\n\nfunc TestShare() { client.WriteRelationships(ctx, req) }\n",
	}
	for name, content := range files {
		if err := os.WriteFile(name, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return authz, filepath.Join(dir, "app")
}

// The lines a rule cites are held to the source -code names: one that holds passes, one
// past the end of its file fails the run, and the place that writes no rule cites is
// listed, a test left out.
func TestEvidenceIsHeldToTheSource(t *testing.T) {
	authz, app := evidenceCase(t, "      - {at: api/share.go:4, text: WriteRelationships}\n      - api/share.go:40\n")
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-no-color", "-fail-on", failOnNone, "-code", app, authz}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{
		"Evidence in the source",
		"1 of 7 rules cites the lines of the application that make the write",
		"1 citation no longer holds:",
		"document#viewer  api/share.go:40  the file has fewer than 40 lines",
		"2 places in " + filepath.ToSlash(app) + " call a write of SpiceDB or OpenFGA, 1 cited by a rule",
		"api/admin.go:4  WriteRelationships  SpiceDB",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the report does not say %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "share_test.go") {
		t.Errorf("a test is listed as a place that writes:\n%s", out)
	}

	stdout.Reset()
	if code := Run([]string{"-quiet", "-code", app, authz}, &stdout, &stderr); code != exitFound {
		t.Errorf("a citation that no longer holds: exit code %d, want %d", code, exitFound)
	}
	if !strings.Contains(stdout.String(), "api/share.go:40") || strings.Contains(stdout.String(), "api/admin.go") {
		t.Errorf("quiet, the run prints the citations that fail it alone:\n%s", stdout.String())
	}
}

// Without -code a citation is read beside the write model, and never outside it: one of a
// file there holds, and one that climbs out of the directory is refused with the write
// model.
func TestEvidenceIsReadBesideTheWriteModel(t *testing.T) {
	authz, _ := evidenceCase(t, "      - api/share.go:4\n      - api/admin.go:4\n")
	if err := os.MkdirAll(filepath.Join(authz, "api"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(authz, "api", "share.go"), []byte("package api\n\nfunc share() {\n\twrite()\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	Run([]string{"-no-color", "-fail-on", failOnNone, authz}, &stdout, &stderr)
	out := stdout.String()
	if !strings.Contains(out, "1 citation no longer holds:") || !strings.Contains(out, "document#viewer  api/admin.go:4  the file is not there") {
		t.Errorf("the citations are not read beside the write model:\n%s", out)
	}
	if strings.Contains(out, "call a write of") {
		t.Errorf("without -code the source is not searched:\n%s", out)
	}

	escape, _ := evidenceCase(t, "      - ../app/api/share.go:4\n")
	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"-no-color", escape}, &stdout, &stderr); code != exitFailure || !strings.Contains(stderr.String(), "not a path inside the source") {
		t.Errorf("a citation out of the directory: exit %d, stderr %q", code, stderr.String())
	}
}

// A run whose write models cite nothing and that names no source says nothing of evidence.
func TestNoEvidenceSaysNothing(t *testing.T) {
	var stdout, stderr bytes.Buffer
	Run([]string{"-no-color", "-fail-on", failOnNone, spicedbFixture}, &stdout, &stderr)
	if strings.Contains(stdout.String(), "Evidence in the source") {
		t.Errorf("the report speaks of evidence nobody gave:\n%s", stdout.String())
	}
}

// On a schema with nothing to find, the evidence alone decides the run: citations that
// hold pass it and, quiet, print nothing at all; one that no longer holds fails it and,
// quiet, is all the run prints.
func TestEvidenceAloneDecidesTheRun(t *testing.T) {
	write := func(t *testing.T, line string) (string, string) {
		t.Helper()
		dir := t.TempDir()
		files := map[string]string{
			"authz/schema.zed": "definition user {}\n\ndefinition document {\n\trelation viewer: user\n\tpermission view = viewer\n}\n",
			"authz/writes.yaml": "schema_version: 1\nmodel: relationship-writes\nwrites:\n  - resource: document\n    relation: viewer\n" +
				"    operations: [create]\n    gate: { service: sharing }\n    subject: any\n    evidence:\n      - " + line + "\n",
			"app/share.go": "package app\n\nfunc share() {\n\tclient.WriteRelationships(ctx, req)\n}\n",
		}
		for name, content := range files {
			full := filepath.Join(dir, filepath.FromSlash(name))
			if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return filepath.Join(dir, "authz"), filepath.Join(dir, "app")
	}

	t.Run("it holds", func(t *testing.T) {
		authz, app := write(t, "{at: share.go:4, text: WriteRelationships}")
		var stdout, stderr bytes.Buffer
		if code := Run([]string{"-quiet", "-code", app, authz}, &stdout, &stderr); code != exitOK {
			t.Errorf("exit code = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
		}
		if stdout.Len() != 0 {
			t.Errorf("quiet, a run whose evidence holds printed:\n%s", stdout.String())
		}
	})
	t.Run("it no longer holds", func(t *testing.T) {
		authz, app := write(t, "{at: share.go:3, text: WriteRelationships}")
		var stdout, stderr bytes.Buffer
		if code := Run([]string{"-quiet", "-code", app, authz}, &stdout, &stderr); code != exitFound {
			t.Errorf("exit code = %d, want %d (stderr: %s)", code, exitFound, stderr.String())
		}
		out := stdout.String()
		if !strings.Contains(out, "document#viewer  share.go:3") || strings.Contains(out, "the lines of the application") || strings.Contains(out, "call a write") {
			t.Errorf("quiet, the run prints the citation that fails it alone:\n%s", out)
		}
	})
}
