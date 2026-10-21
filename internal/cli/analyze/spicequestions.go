package analyze

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// This file writes the safe gates out as a relationship-writes write model to
// fill in, one entry per relation the schema leaves without a rule, so the
// author confirms the gate in the file rather than building it from scratch. It
// is the Zanzibar half of -questions, written when the run is SpiceDB alone; a
// run with a policy writes the write-paths skeleton instead.
//
// It refuses to overwrite an existing file, since a write model somebody has
// already filled in is the last thing to clobber.

// writeSpiceQuestions writes the skeleton to path and returns how many entries it
// holds. It refuses a path that already exists.
func writeSpiceQuestions(path string, groups []schemaProposals) (int, error) {
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
	content, entries := spiceSkeleton(groups)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return 0, fmt.Errorf("writing the write model: %w", err)
	}
	return entries, nil
}

// spiceSkeleton renders the write model: a header that says what to do with it,
// then one entry per relation without a rule, gated by a safe permission petard
// proposes, with the subject and the via to fill in. A relation with no safe
// gate is written as a comment, since proposing an unsafe gate would be wrong.
func spiceSkeleton(groups []schemaProposals) (string, int) {
	var b strings.Builder
	b.WriteString("# Write model skeleton written by petard analyze -questions.\n")
	b.WriteString("#\n")
	b.WriteString("# Each relation below has no write rule. petard proposes the permission that is a\n")
	b.WriteString("# safe gate; confirm the gate the application really uses, fill in the via and the\n")
	b.WriteString("# subject, then rerun with -write-model and this file. A relation nobody can write\n")
	b.WriteString("# is one to leave out rather than open.\n")
	b.WriteString("schema_version: 1\n")
	b.WriteString("model: relationship-writes\n")
	b.WriteString("writes:\n")

	entries := 0
	for _, g := range groups {
		if len(groups) > 1 {
			fmt.Fprintf(&b, "  # %s\n", g.schema)
		}
		for _, p := range g.proposals {
			entries++
			if len(p.Safe) == 0 {
				fmt.Fprintf(&b, "  # %s#%s has no safe gate: every permission on %s lets a coalition escalate.\n", p.Type, p.Relation, p.Type)
				fmt.Fprintf(&b, "  # Leave it out, or gate it on a service no end user can drive.\n")
				continue
			}
			fmt.Fprintf(&b, "  - resource: %s\n", p.Type)
			fmt.Fprintf(&b, "    relation: %s\n", p.Relation)
			b.WriteString("    operations: [create, touch]\n")
			fmt.Fprintf(&b, "    gate: { holds: %s }   # safe gate", p.Safe[0])
			if len(p.Safe) > 1 {
				fmt.Fprintf(&b, "; also %s", strings.Join(p.Safe[1:], ", "))
			}
			b.WriteString("\n")
			b.WriteString("    subject: self\n")
			b.WriteString("    via: \"\"\n")
		}
	}
	return b.String(), entries
}
