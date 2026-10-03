package analyze

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/saluc28/petard/internal/taxonomy"
)

// This file writes the open questions out as a write model to fill in, one entry
// per question, so a reader answers them in the file rather than building it from
// scratch.
//
// It refuses to overwrite an existing file, the way terraform plan
// -generate-config-out does, since a write model somebody has already filled in
// is the last thing to clobber.

// writeQuestions writes the skeleton to path and returns how many entries it
// holds. It refuses a path that already exists.
func writeQuestions(path, subject string, questions []taxonomy.Question) (int, error) {
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
	if err := os.WriteFile(path, []byte(skeleton(subject, questions)), 0o600); err != nil {
		return 0, fmt.Errorf("writing the write model: %w", err)
	}
	return len(questions), nil
}

// skeleton renders the write model: a header that says what to do with it, then
// one entry per question with the path to declare, the principal to confirm, and
// a via to fill in.
func skeleton(subject string, questions []taxonomy.Question) string {
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
		fmt.Fprintf(&b, "  - path: %s\n", question.Writable)
		b.WriteString("    writable_by:\n")
		fmt.Fprintf(&b, "      - principal: %q\n", question.Writer)
		b.WriteString("        via: \"\"\n")
	}
	return b.String()
}
