package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// squeezed collapses the padding the report aligns its columns with, so that a
// test asserts on what a line says and not on how wide the widest name in it
// happened to be.
func squeezed(report string) string {
	return strings.Join(strings.Fields(report), " ")
}

// writeCorpus lays out a corpus the way a real one is laid out: one directory
// per policy, the library it needs beside it, and the tests of the policy in
// the same place without being part of it.
func writeCorpus(t *testing.T, files map[string]string) string {
	t.Helper()

	root := t.TempDir()
	for name, content := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatalf("creating %s: %v", filepath.Dir(path), err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
	return root
}

// The corpus this measures is written in the shape of the one it was built for:
// Rego v0, a partial set called violation, a library beside the policy, and a
// test file that is not part of what gets deployed.
const (
	corpusPolicy = `package allowedrepos

import data.lib.exempt.is_exempt

violation[{"msg": msg}] {
	container := input.review.object.spec.containers[_]
	not is_exempt(container)
	not data.settings.allowed[container.image]
	msg := "repo not allowed"
}
`

	corpusLib = `package lib.exempt

is_exempt(container) {
	container.image == "kube-system/pause"
}
`

	corpusTest = `package allowedrepos

test_violation {
	violation with input as {"review": {"object": {"spec": {"containers": [{"image": "evil"}]}}}}
}
`

	corpusLibraryOnly = `package lib.shared

is_admin(user) {
	user == "root"
}
`
)

func TestRunMeasuresACorpus(t *testing.T) {
	root := writeCorpus(t, map[string]string{
		"general/allowedrepos/src.rego":      corpusPolicy,
		"general/allowedrepos/lib.rego":      corpusLib,
		"general/allowedrepos/src_test.rego": corpusTest,
		"rego/shared/shared.rego":            corpusLibraryOnly,
	})

	var stdout, stderr bytes.Buffer
	if code := run([]string{"-verbose", root}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}

	out := stdout.String()
	for _, expected := range []string{
		"corpus: 2 policies",
		"parsed as rego v0 2",
		// The policy has a decision to declare and the shared library does not,
		// and a library that yields nothing is not a failure of the engine.
		"policies with a decision 1",
		"policies with none 1",
		"no decision to walk from 1",
		// The one read of data survives, and the fields of the container do not:
		// the container comes from the request, not from the store.
		"distinct data paths 1",
		"data.settings.allowed[_] 1",
		// The shape is the domain convention, not a guess about field names.
		"level C, kubernetes admission review 1",
	} {
		if !strings.Contains(squeezed(out), expected) {
			t.Errorf("the report does not contain %q:\n%s", expected, out)
		}
	}
}

// A test file sits next to the policy and is not part of it. Counting it would
// put the mocked decisions of the test suite into every number of the report,
// which is the one thing a measurement must not do.
func TestRunLeavesTestFilesOutOfThePolicy(t *testing.T) {
	root := writeCorpus(t, map[string]string{
		"allowedrepos/src.rego":      corpusPolicy,
		"allowedrepos/lib.rego":      corpusLib,
		"allowedrepos/src_test.rego": corpusTest,
	})

	var stdout, stderr bytes.Buffer
	if code := run([]string{root}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}

	out := squeezed(stdout.String())
	// Two rules, the violation and the exemption of the library. The third one,
	// the test, is not part of the policy.
	if !strings.Contains(out, "rules 2 1") {
		t.Errorf("the rule count includes the test file, or misses the library:\n%s", stdout.String())
	}
	// And the with the test mocks the request with is the giveaway: the policy
	// itself has none.
	if !strings.Contains(out, "with 0 0") {
		t.Errorf("a with modifier was counted, so the test file was loaded:\n%s", stdout.String())
	}
}

func TestRunRejectsAnEmptyCorpus(t *testing.T) {
	var stdout, stderr bytes.Buffer

	if code := run([]string{t.TempDir()}, &stdout, &stderr); code != exitFailure {
		t.Errorf("exit code = %d, want %d", code, exitFailure)
	}
	if !strings.Contains(stderr.String(), "no .rego file") {
		t.Errorf("stderr does not say what is missing: %s", stderr.String())
	}
}

func TestRunWithoutARoot(t *testing.T) {
	var stdout, stderr bytes.Buffer

	if code := run(nil, &stdout, &stderr); code != exitUsage {
		t.Errorf("exit code = %d, want %d", code, exitUsage)
	}
}
