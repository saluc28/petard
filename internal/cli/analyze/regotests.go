package analyze

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
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

// regalLineLength is where regal's line-length rule starts to complain by
// default. A test that would run past it gets its long lines broken the way
// opa fmt keeps them, one key or one argument to a line.
const regalLineLength = 120

// writeTests writes the tests to path, and returns how many it wrote.
func writeTests(path string, a taxonomy.Analysis, escalations []taxonomy.Finding) (int, error) {
	module, written, err := regoTests(a, escalations)
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
func regoTests(a taxonomy.Analysis, escalations []taxonomy.Finding) (string, int, error) {
	var b strings.Builder
	b.WriteString(testsHeader(a.Bundle))

	taken := map[string]bool{}
	written := 0
	for _, escalation := range escalations {
		w := escalation.Witness
		if w == nil {
			continue
		}
		test, err := escalationTest(a.Bundle, w, testName(taken, escalation.Principal, escalation.Target))
		if err != nil {
			return "", 0, err
		}

		b.WriteString("\n")
		comment(&b, escalation.PatternID+": "+escalation.Summary)
		if w.AuthorizedBy == "" && escalation.Via != "" {
			comment(&b, "The write goes through "+escalation.Via+", which no decision of this policy "+
				"guards, so the test passes only once the policy stops granting on what is written.")
		}
		b.WriteString(test)
		written++
	}
	if written == 0 {
		b.WriteString("\n# No escalation came with a request that proves it, so there is nothing to test.\n")
	}
	return b.String(), written, nil
}

// escalationTest writes the test of one escalation. The requests are bound
// first, and the lines of the set refer to them by name.
//
// A write into an element of a list cannot be named by a with modifier, so the
// list is patched at the place written, with json.patch on the list as it
// stands, and the test shows only the change.
func escalationTest(bundle *opaengine.Bundle, w *taxonomy.Witness, name string) (string, error) {
	target, pointer, err := opaengine.WithTarget(w.Document)
	if err != nil {
		return "", err
	}
	// value is what the with modifier puts in place of the target.
	value, err := regoValue(w.Value)
	if err != nil {
		return "", err
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s if {\n", name)
	if w.AuthorizedBy != "" {
		if err := bind(&b, "write", w.WriteRequest); err != nil {
			return "", err
		}
	}
	if err := bind(&b, "request", w.Request); err != nil {
		return "", err
	}
	if pointer != "" {
		patch, err := regoValue([]any{map[string]any{"op": patchOp(pointer), "path": pointer, "value": w.Value}})
		if err != nil {
			return "", err
		}
		call := fmt.Sprintf("\twritten := json.patch(%s, %s)\n", target, patch)
		if len(call) > regalLineLength {
			call = fmt.Sprintf("\twritten := json.patch(\n\t\t%s,\n\t\t%s,\n\t)\n", target, patch)
		}
		b.WriteString(call)
		value = "written"
	}

	b.WriteString("\topen := {true |\n")
	if w.AuthorizedBy != "" {
		fmt.Fprintf(&b, "\t\t%s with input as write\n", grants(bundle, w.AuthorizedBy))
	}
	fmt.Fprintf(&b, "\t\t%s with input as request\n", refuses(bundle, w.Decision))
	fmt.Fprintf(&b, "\t\t%s with input as request\n\t\t\twith %s as %s\n", grants(bundle, w.Decision), target, value)
	b.WriteString("\t}\n\tcount(open) == 0\n}\n")
	return b.String(), nil
}

// bind writes one binding of a test, name := value, with an object that would
// run past regalLineLength broken into one key to a line.
func bind(b *strings.Builder, name string, value any) error {
	text, err := regoValue(value)
	if err != nil {
		return err
	}
	line := "\t" + name + " := " + text
	object, isObject := value.(map[string]any)
	if len(line) <= regalLineLength || !isObject {
		b.WriteString(line + "\n")
		return nil
	}

	b.WriteString("\t" + name + " := {\n")
	for _, key := range slices.Sorted(maps.Keys(object)) {
		element, err := regoValue(object[key])
		if err != nil {
			return err
		}
		fmt.Fprintf(b, "\t\t%s: %s,\n", strconv.Quote(key), element)
	}
	b.WriteString("\t}\n")
	return nil
}

// patchOp is the JSON Patch operation that writes at a pointer: replace for an
// element of a list, which add would insert before, and add for a key of an
// object, which sets it whether it was there or not (RFC 6902, 4.1).
func patchOp(pointer string) string {
	last := pointer[strings.LastIndex(pointer, "/")+1:]
	if _, err := strconv.Atoi(last); err == nil {
		return "replace"
	}
	return "add"
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
