package analyze

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/saluc28/petard/internal/cli/zanzibarsetup"
	"github.com/saluc28/petard/internal/evidence"
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

// writeSchemaQuestions writes the skeleton to path and returns how many entries it
// holds. It refuses a path that already exists.
func writeSchemaQuestions(path string, groups []schemaProposals, sites []evidence.Site) (int, error) {
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
	content, entries := schemaSkeleton(groups, sites)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return 0, fmt.Errorf("writing the write model: %w", err)
	}
	return entries, nil
}

// schemaSkeleton renders the write model: a header that says what to do with it,
// then one entry per relation without a rule, with the subjects the schema
// allows, the wildcard and the caveats it admits filled in, and a safe
// permission petard proposes as the gate. The author confirms the gate, narrows
// the subjects, and fills the via. A relation with no safe gate is written as a
// comment, since proposing an unsafe gate would be wrong.
func schemaSkeleton(groups []schemaProposals, sites []evidence.Site) (string, int) {
	var b strings.Builder
	b.WriteString("# Write model skeleton written by petard analyze -questions.\n")
	b.WriteString("#\n")
	b.WriteString("# Each relation below has no write rule. petard fills in the subjects the schema\n")
	b.WriteString("# allows and the permission that is a safe gate; confirm the gate the application\n")
	b.WriteString("# really uses, narrow the subjects to the ones it writes, fill in the via and cite\n")
	b.WriteString("# the lines that make the write in evidence, then rerun with -write-model and this\n")
	b.WriteString("# file. For a caveat, mark a parameter application when the check supplies it\n")
	b.WriteString("# rather than the writer. A relation nobody can write is one to leave out rather\n")
	b.WriteString("# than open. The relations whose writes can raise the most permissions come first,\n")
	b.WriteString("# each with what it can raise, and the relations that raise nothing gathered at the end.\n")
	writeSitesHeader(&b, sites)
	b.WriteString("schema_version: 1\n")
	b.WriteString("model: relationship-writes\n")
	b.WriteString("writes:\n")

	entries := 0
	for _, g := range groups {
		if len(groups) > 1 {
			fmt.Fprintf(&b, "  # %s\n", g.schema)
		}
		var quiet []string
		for _, p := range g.proposals {
			entries++
			if len(p.Safe) == 0 {
				switch {
				case len(p.Unsafe) > 0:
					fmt.Fprintf(&b, "  # %s#%s has no safe gate: every permission on %s lets a coalition escalate.\n", p.Type, p.Relation, p.Type)
					fmt.Fprintf(&b, "  # Leave it out, or gate it on a service no end user can drive.\n")
				case len(p.Raises) > 0:
					fmt.Fprintf(&b, "  # %s#%s has no permission on %s to gate on; writing it raises %s.\n", p.Type, p.Relation, p.Type, strings.Join(p.Raises, ", "))
					fmt.Fprintf(&b, "  # Leave it out, or gate it on a service no end user can drive.\n")
				default:
					quiet = append(quiet, p.Type+"#"+p.Relation)
				}
				continue
			}
			writeReach(&b, p.Raises)
			fmt.Fprintf(&b, "  - resource: %s\n", p.Type)
			fmt.Fprintf(&b, "    relation: %s\n", p.Relation)
			b.WriteString(operationsLine(g.product))
			fmt.Fprintf(&b, "    gate: { holds: %s }   # safe gate", p.Safe[0])
			if len(p.Safe) > 1 {
				fmt.Fprintf(&b, "; also %s", strings.Join(p.Safe[1:], ", "))
			}
			b.WriteString("\n")
			writeSkeletonSubject(&b, g.model, relationOf(g.model, p.Type, p.Relation))
			b.WriteString("    via: \"\"\n")
			b.WriteString("    # evidence: [path:line]   the lines of the application that make the write\n")
		}
		writeQuietGroup(&b, quiet)
	}
	return b.String(), entries
}

// writeSitesHeader lists the write sites -code found above the skeleton, for the
// author to assign to a rule's via and cite in evidence. petard finds where a
// write happens, not which relation it writes, so the author makes the match;
// without -code there are no sites and the block is left out, so the skeleton is
// what it was before.
func writeSitesHeader(b *strings.Builder, sites []evidence.Site) {
	if len(sites) == 0 {
		return
	}
	b.WriteString("#\n")
	b.WriteString("# -code found these write sites. Assign each to a rule's via below and cite it in\n")
	b.WriteString("# evidence; petard found where a write happens, not which relation it writes.\n")
	for _, s := range sites {
		fmt.Fprintf(b, "#   %s  %s  %s\n", s, s.Call, s.Product)
	}
}

// writeReach writes, above an entry, the permissions writing the relation can raise,
// the reason it comes where it does. A few names go on a line, and past a cap only a
// count of the rest follows, so a relation that can raise a whole model stays a few
// lines rather than dozens.
func writeReach(b *strings.Builder, raises []string) {
	if len(raises) == 0 {
		return
	}
	const perLine, shown = 4, 8
	list := raises
	extra := 0
	if len(list) > shown {
		list, extra = raises[:shown], len(raises)-shown
	}
	for i := 0; i < len(list); i += perLine {
		lead := "  # can raise "
		if i > 0 {
			lead = "  #   "
		}
		end := min(i+perLine, len(list))
		line := strings.Join(list[i:end], ", ")
		if end < len(list) || extra > 0 {
			line += ","
		}
		b.WriteString(lead + line + "\n")
	}
	if extra > 0 {
		fmt.Fprintf(b, "  #   and %d more\n", extra)
	}
}

// writeQuietGroup gathers the relations whose writes raise no permission into one
// note that names them, rather than a line each: a schema with many leaf relations
// would otherwise bury the few that need a gate. They are safe to write and need no
// gate, so the note is all they warrant.
func writeQuietGroup(b *strings.Builder, names []string) {
	if len(names) == 0 {
		return
	}
	head := fmt.Sprintf("%d relations raise no permission and need no gate:", len(names))
	if len(names) == 1 {
		head = "1 relation raises no permission and needs no gate:"
	}
	fmt.Fprintf(b, "  # %s\n", head)
	const perLine = 4
	for i := 0; i < len(names); i += perLine {
		end := min(i+perLine, len(names))
		line := strings.Join(names[i:end], ", ")
		if end < len(names) {
			line += ","
		}
		b.WriteString("  #   " + line + "\n")
	}
}

// operationsLine is the writes a skeleton proposes. OpenFGA has no write that also
// sets a new condition on a tuple already written: a tuple written twice is an error
// or is ignored (pkg/server/write.go:58-66 at v1.23.0).
func operationsLine(product zanzibarsetup.Product) string {
	if product == zanzibarsetup.OpenFGA {
		return "    operations: [create]\n"
	}
	return "    operations: [create, touch]\n"
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
