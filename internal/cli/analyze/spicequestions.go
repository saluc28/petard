package analyze

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/saluc28/petard/internal/zanzibar"
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
// then one entry per relation without a rule, with the subjects the schema
// allows, the wildcard and the caveats it admits filled in, and a safe
// permission petard proposes as the gate. The author confirms the gate, narrows
// the subjects, and fills the via. A relation with no safe gate is written as a
// comment, since proposing an unsafe gate would be wrong.
func spiceSkeleton(groups []schemaProposals) (string, int) {
	var b strings.Builder
	b.WriteString("# Write model skeleton written by petard analyze -questions.\n")
	b.WriteString("#\n")
	b.WriteString("# Each relation below has no write rule. petard fills in the subjects the schema\n")
	b.WriteString("# allows and the permission that is a safe gate; confirm the gate the application\n")
	b.WriteString("# really uses, narrow the subjects to the ones it writes, fill in the via, then\n")
	b.WriteString("# rerun with -write-model and this file. For a caveat, mark a parameter application\n")
	b.WriteString("# when the check supplies it rather than the writer. A relation nobody can write is\n")
	b.WriteString("# one to leave out rather than open.\n")
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
			writeSkeletonSubject(&b, g.model, relationOf(g.model, p.Type, p.Relation))
			b.WriteString("    via: \"\"\n")
		}
	}
	return b.String(), entries
}

// relationOf looks a relation up in a model, nil when the model or the type is
// missing, so the skeleton falls back rather than panicking.
func relationOf(model *zanzibar.Model, typ, relation string) *zanzibar.Relation {
	if model == nil {
		return nil
	}
	t := model.Type(typ)
	if t == nil {
		return nil
	}
	return t.Relation(relation)
}

// writeSkeletonSubject writes the subject, wildcard and caveat lines for a
// relation from the subjects its schema allows. The subjects are the schema's
// upper bound, which the author narrows; the caveat parameters default to the
// writer, since the written context wins over the check's. With no relation to
// read, it falls back to self, the one subject that needs no schema.
func writeSkeletonSubject(b *strings.Builder, model *zanzibar.Model, r *zanzibar.Relation) {
	if r == nil {
		b.WriteString("    subject: self\n")
		return
	}

	var forms []string
	wildcard := false
	seenForm := map[string]bool{}
	seenCaveat := map[string]bool{}
	var caveats []string
	for _, a := range r.Allowed {
		if a.Wildcard {
			wildcard = true
		} else {
			form := a.Type
			if a.Relation != "" {
				form = a.Type + "#" + a.Relation
			}
			// The same type appears twice when one form carries a caveat and one
			// does not (user | user with ip_allowlist); the subject is the type,
			// and the caveat is its own field, so the form is listed once.
			if !seenForm[form] {
				seenForm[form] = true
				forms = append(forms, form)
			}
		}
		if a.Caveat != "" && !seenCaveat[a.Caveat] {
			seenCaveat[a.Caveat] = true
			caveats = append(caveats, a.Caveat)
		}
	}

	switch {
	case len(forms) > 0:
		fmt.Fprintf(b, "    subject: %s\n", yamlList(forms))
	case !wildcard:
		// A relation with no form and no wildcard cannot come from a schema, but a
		// rule needs a subject to be a rule, so fall back to self.
		b.WriteString("    subject: self\n")
	}
	if wildcard {
		b.WriteString("    wildcard: true   # admits a wildcard: writing it grants to every subject of the type\n")
	}
	if len(caveats) > 0 {
		b.WriteString("    caveat:\n")
		for _, name := range caveats {
			fmt.Fprintf(b, "      - name: %s\n", name)
			c := model.Caveat(name)
			if c == nil || len(c.Parameters) == 0 {
				continue
			}
			b.WriteString("        parameters:\n")
			for _, p := range c.Parameters {
				fmt.Fprintf(b, "          %s: writer\n", p.Name)
			}
		}
	}
}

// yamlList renders a YAML flow sequence, quoting a form that holds a character
// YAML would read as a comment or a key, so a userset subject stays one value.
func yamlList(forms []string) string {
	out := make([]string, len(forms))
	for i, f := range forms {
		if strings.ContainsAny(f, "#:") {
			out[i] = `"` + f + `"`
		} else {
			out[i] = f
		}
	}
	return "[" + strings.Join(out, ", ") + "]"
}
