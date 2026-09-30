package analyze

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"

	"github.com/saluc28/petard/internal/cli/render"
	"github.com/saluc28/petard/internal/opaengine"
	"github.com/saluc28/petard/internal/taxonomy"
)

// This file writes the escalations out as opa tests, one for each escalation
// that came with a witness.
//
// A test states what should hold, that the principal cannot reach the other
// one's position, so it fails while the escalation is open and passes once it
// is closed, and then stays in the suite as a regression test. That is how go
// test treats a failing fuzz input kept under testdata/fuzz: it runs as a seed
// and fails until the bug is fixed (src/testing/fuzz.go:59 at go1.27.1). A test
// that passed while the policy was open would be a green check that means the
// opposite of what a green check means in CI.

// testsPackage is the package the tests are written in. It sits under petard so
// that it cannot collide with a package of the policy, and ends in _test, which
// is where regal wants a test (test-outside-test-package).
const testsPackage = "petard.escalations_test"

// writeTests writes the tests to path, and returns how many it wrote.
func writeTests(ctx context.Context, path string, a taxonomy.Analysis, escalations []taxonomy.Finding) (int, error) {
	module, written, err := regoTests(ctx, a, escalations)
	if err != nil {
		return 0, err
	}
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return 0, fmt.Errorf("creating %s: %w", dir, err)
		}
	}
	if err := os.WriteFile(path, []byte(module), 0o600); err != nil {
		return 0, fmt.Errorf("writing the tests: %w", err)
	}
	return written, nil
}

// regoTests writes the module: for each escalation with a witness, a test that
// collects the escalation into a set and holds when the set is empty. The set
// is how a test says that a conjunction does not hold with every with modifier
// inside the test itself, where regal wants one (with-outside-test-context).
//
// The conjunction is the whole escalation and not the grant alone. When the
// policy authorizes the write, the fix PTD-OPA-006 names is the decision that
// allows the write refusing the value, and a test that forced the write with a
// with modifier and asked only the granting decision would go on failing after
// that fix. So the test asks the authorizing decision about the write too, and
// the granting decision about the request before the write and after it.
//
// The module imports rego.v1, which Rego v1 accepts and Rego v0 needs for if,
// so it loads next to a policy in either syntax.
func regoTests(ctx context.Context, a taxonomy.Analysis, escalations []taxonomy.Finding) (string, int, error) {
	var b strings.Builder
	b.WriteString(testsHeader(a.Bundle))

	taken := map[string]bool{}
	written := 0
	for _, escalation := range escalations {
		w := escalation.Witness
		if w == nil || a.Data == nil {
			continue
		}
		body, err := escalationBody(ctx, a, w)
		if err != nil {
			return "", 0, err
		}

		b.WriteString("\n")
		comment(&b, escalation.PatternID+": "+escalation.Summary)
		if w.AuthorizedBy == "" && escalation.Via != "" {
			comment(&b, "The write goes through "+escalation.Via+", which no decision of this policy "+
				"guards, so the test passes only once the policy stops granting on what is written.")
		}
		fmt.Fprintf(&b, "%s if {\n\topen := {true |\n%s\t}\n\tcount(open) == 0\n}\n",
			testName(taken, escalation.Principal, escalation.Target), body)
		written++
	}
	if written == 0 {
		b.WriteString("\n# No escalation came with a request that proves it, so there is nothing to test.\n")
	}
	return b.String(), written, nil
}

// escalationBody writes the expressions that hold together while the
// escalation is open, one per line, indented for the set they go in.
func escalationBody(ctx context.Context, a taxonomy.Analysis, w *taxonomy.Witness) (string, error) {
	target, held, err := a.Data.WithTarget(ctx, w.Document, w.Value)
	if err != nil {
		return "", err
	}
	request, err := regoValue(w.Request)
	if err != nil {
		return "", err
	}
	value, err := regoValue(held)
	if err != nil {
		return "", err
	}

	var b strings.Builder
	if w.AuthorizedBy != "" {
		writeRequest, err := regoValue(w.WriteRequest)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "\t\t%s with input as %s\n", grants(a.Bundle, w.AuthorizedBy), writeRequest)
	}
	fmt.Fprintf(&b, "\t\t%s with input as %s\n", refuses(a.Bundle, w.Decision), request)
	fmt.Fprintf(&b, "\t\t%s with input as %s\n\t\t\twith %s as %s\n", grants(a.Bundle, w.Decision), request, target, value)
	return b.String(), nil
}

// testsHeader says what the file is and how to run it.
func testsHeader(bundle *opaengine.Bundle) string {
	run := "opa test <policy> <data> <this file>"
	if bundle.RegoVersion == ast.RegoV0 {
		run = "opa test --v0-compatible <policy> <data> <this file>"
	}
	return "# Written by petard analyze, one test for each escalation it proved by asking\n" +
		"# the decision about a request. A test fails while its escalation is open and\n" +
		"# passes once it is closed. Run it with the policy and the data the analysis\n" +
		"# read:\n" +
		"#\n" +
		"#   " + run + "\n" +
		"package " + testsPackage + "\n" +
		"\n" +
		"import rego.v1\n"
}

// comment writes prose as Rego comment lines that fit the width of a report.
func comment(b *strings.Builder, text string) {
	for _, line := range render.Wrap(text, "# ") {
		b.WriteString(line + "\n")
	}
}

// grants writes the expression that holds when a decision grants the request it
// is asked about, and refuses the one that holds when it does not. A decision
// that collects grants when what it collected is not empty.
func grants(bundle *opaengine.Bundle, decision string) string {
	if bundle.Collects(decision) {
		return "count(" + decision + ") > 0"
	}
	return decision
}

func refuses(bundle *opaengine.Bundle, decision string) string {
	if bundle.Collects(decision) {
		return "count(" + decision + ") == 0"
	}
	return "not " + decision
}

// regoValue writes a value of a request or of the data as a Rego term.
func regoValue(value any) (string, error) {
	term, err := ast.InterfaceToValue(value)
	if err != nil {
		return "", fmt.Errorf("writing %v as rego: %w", value, err)
	}
	return term.String(), nil
}

// testName names the test of an escalation after the two principals, as
// test_mallory_cannot_reach_dave, with a number after it when the same two
// principals come up again.
func testName(taken map[string]bool, principal, target string) string {
	base := "test_" + identifier(principal) + "_cannot_reach_" + identifier(target)
	name := base
	for n := 2; taken[name]; n++ {
		name = fmt.Sprintf("%s_%d", base, n)
	}
	taken[name] = true
	return name
}

// identifier turns a principal's name into something a rule name can hold:
// user:bob is user_bob.
func identifier(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}
