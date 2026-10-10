package analyze

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	yaml "go.yaml.in/yaml/v3"

	"github.com/saluc28/petard/internal/opaengine"
	"github.com/saluc28/petard/internal/taxonomy"
)

// This file writes the open questions out as a write model to fill in, one entry
// per question, so a reader answers them in the file rather than building it from
// scratch.
//
// It refuses to overwrite an existing file, since a write model somebody has
// already filled in is the last thing to clobber.

// writeQuestions writes the skeleton to path and returns how many entries it
// holds. It refuses a path that already exists.
func writeQuestions(path, subject string, questions []taxonomy.Question, endpoints []opaengine.WriteEndpoint) (int, error) {
	if _, err := os.Stat(path); err == nil {
		return 0, fmt.Errorf("%s already exists, and a write model is not something to overwrite", path)
	} else if !os.IsNotExist(err) {
		return 0, fmt.Errorf("checking %s: %w", path, err)
	}

	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return 0, fmt.Errorf("creating %s: %w", dir, err)
		}
	}
	if err := os.WriteFile(path, []byte(skeleton(subject, questions, endpoints)), 0o600); err != nil {
		return 0, fmt.Errorf("writing the write model: %w", err)
	}
	return len(questions), nil
}

// skeleton renders the write model: a header that says what to do with it, then
// one entry per question with the path to declare, the principal to confirm, and
// a via to fill in, and last the writes the bundle authorizes to attach where
// one of them is what makes a write allowed.
func skeleton(subject string, questions []taxonomy.Question, endpoints []opaengine.WriteEndpoint) string {
	var b strings.Builder
	b.WriteString("# Write model skeleton written by petard analyze -questions.\n")
	b.WriteString("#\n")
	b.WriteString("# Fill in each via, the endpoint or form that makes the write, and change the\n")
	b.WriteString("# principal when it is not the one suggested. Then rerun with -write-model and\n")
	b.WriteString("# this file. A path nobody can write is one to delete rather than leave open.\n")
	if subject != "" {
		fmt.Fprintf(&b, "# The subject is %s.\n", subject)
	}
	b.WriteString("schema_version: 1\n")
	b.WriteString("model: write-paths\n")
	b.WriteString("entries:\n")

	for _, question := range questions {
		fmt.Fprintf(&b, "  # %s (%s)\n", question.Asks(), strings.Join(question.Patterns, ", "))
		fmt.Fprintf(&b, "  - path: %s\n", yamlScalar(question.Writable))
		b.WriteString("    writable_by:\n")
		fmt.Fprintf(&b, "      - principal: %q\n", question.Writer)
		b.WriteString("        via: \"\"\n")
	}

	writeEndpoints(&b, endpoints)
	return b.String()
}

// yamlScalar writes a string the way YAML reads it back whole. A data path is
// written bare, and one whose key would read as something else, a mapping
// after ": " or a comment after " #", is quoted.
func yamlScalar(s string) string {
	out, err := yaml.Marshal(s)
	scalar := strings.TrimSuffix(string(out), "\n")
	if err != nil || strings.Contains(scalar, "\n") {
		// A key that holds a line break comes out as a block over several
		// lines, which does not fit after "path:". Go quotes a string with the
		// escapes YAML reads between double quotes.
		return strconv.Quote(s)
	}
	return scalar
}

// writeEndpoints appends, as a comment, the writes the bundle authorizes, each as
// an authorized_by block ready to attach to the writer of the document it changes.
// It is how the write allowed by another decision (PTD-OPA-006) gets declared
// without writing the block from scratch: uncomment one and move it under a
// writer.
func writeEndpoints(b *strings.Builder, endpoints []opaengine.WriteEndpoint) {
	if len(endpoints) == 0 {
		return
	}
	b.WriteString("\n# Writes this bundle authorizes. Attach one as an authorized_by to the writer of\n")
	b.WriteString("# the document it changes, to declare a write allowed by another decision:\n")
	for _, endpoint := range endpoints {
		where := endpoint.Method
		if endpoint.Path != "" {
			where += " " + endpoint.Path
		}
		fmt.Fprintf(b, "#   # %s, at %s:%d\n", where, endpoint.File, endpoint.Line)
		b.WriteString("#   authorized_by:\n")
		fmt.Fprintf(b, "#     decision: %s\n", endpoint.Decision)
		b.WriteString("#     request:\n")
		fmt.Fprintf(b, "#       input.method: %q\n", endpoint.Method)
		switch {
		case endpoint.Path != "":
			fmt.Fprintf(b, "#       input.path: %s\n", endpoint.Path)
		default:
			fmt.Fprintf(b, "#       # input.path at %s:%d fixes variables; fill it in, as [a, b, \"{id}\"]\n", endpoint.File, endpoint.Line)
		}
	}
}
