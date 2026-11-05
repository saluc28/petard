package analyze

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/saluc28/petard/internal/cli/render"
	"github.com/saluc28/petard/internal/cli/zanzibarsetup"
	"github.com/saluc28/petard/internal/zanzibar"
)

// This file writes the escalations of a Zanzibar schema out as proofs, the files the
// test runner of the product reads: zed validate for SpiceDB, fga model test for
// OpenFGA. A proof holds the schema, the store at each point of the witness and the
// checks petard expects the product to answer there, so the product itself shows the
// escalation without petard.
//
// A proof is not a regression test the way the opa tests of -tests are. It carries the
// schema it was written from, so it passes while the escalation is open in that schema
// and goes on passing after the schema in the repository is fixed. That is why -proofs
// takes a directory with nothing in it: a proof left from an earlier run would read as
// a finding of this one.

// provable is an escalation, the schema it was found in and what writes its proof in the
// files of the schema's product.
type provable struct {
	schema string
	match  zanzibar.Match
	prove  zanzibarsetup.Prover
}

// errProofsDir is returned for a directory -proofs cannot write into.
var errProofsDir = errors.New("-proofs")

// checkProofsDir says whether dir can take the proofs: it does not exist yet, or it is
// an empty directory. It is asked before the analysis, so a run does not wait for the
// analysis to be told where it cannot write.
func checkProofsDir(dir string) error {
	entries, err := os.ReadDir(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		return fmt.Errorf("%w: %w", errProofsDir, err)
	case len(entries) > 0:
		return fmt.Errorf("%w: %s holds files already; a proof carries the schema it was written from, so one left from an earlier run would go on passing: name an empty directory", errProofsDir, dir)
	}
	return nil
}

// writeProofs writes the proof of each escalation under dir, in files named after its
// pattern, type and permission, and returns how many it wrote and, for each escalation
// it could not prove, why.
func writeProofs(dir string, escalations []provable) (int, []string, error) {
	taken := map[string]bool{}
	written := 0
	var without []string
	for _, e := range escalations {
		raise := e.match.Raise
		heading := e.match.PatternID + ": " + e.match.Subject
		if raise.Proof == nil {
			without = append(without, heading+": "+raise.NoProof)
			continue
		}
		name := proofName(taken, e.match)
		title := []string{heading + ".", "Written by petard analyze from " + e.schema + "."}
		files, err := e.prove(filepath.ToSlash(dir), name, title, raise.Proof)
		if err != nil {
			without = append(without, heading+": "+err.Error())
			continue
		}
		taken[name] = true
		for _, f := range files {
			full := filepath.Join(dir, filepath.FromSlash(f.Path))
			if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
				return written, without, fmt.Errorf("%w: %w", errProofsDir, err)
			}
			if err := os.WriteFile(full, f.Content, 0o600); err != nil {
				return written, without, fmt.Errorf("%w: %w", errProofsDir, err)
			}
		}
		written++
	}
	return written, without, nil
}

// reportProofs says how many proofs were written and where, and why the others were not.
func reportProofs(out io.Writer, dir string, written int, without []string) {
	fmt.Fprintf(out, "\n%s written to %s\n", render.Count(written, "proof"), dir)
	if len(without) == 0 {
		return
	}
	fmt.Fprintf(out, "%s without a proof:\n", render.Count(len(without), "escalation"))
	for _, line := range without {
		fmt.Fprintf(out, "  %s\n", line)
	}
}

// proofName names the proof of an escalation after its pattern, type and permission, as
// ptd-zan-007-document-edit, with a number after it when the same three come up again in
// another schema.
func proofName(taken map[string]bool, m zanzibar.Match) string {
	base := slug(m.PatternID + "-" + m.Raise.Type + "-" + m.Raise.Permission)
	name := base
	for n := 2; taken[name]; n++ {
		name = base + "-" + strconv.Itoa(n)
	}
	return name
}

// slug turns a name into one a file can take on every system: lower case letters and
// digits, with a hyphen for whatever runs of anything else stand between them.
func slug(name string) string {
	var b strings.Builder
	gap := false
	for _, r := range strings.ToLower(name) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			if gap && b.Len() > 0 {
				b.WriteByte('-')
			}
			b.WriteRune(r)
			gap = false
			continue
		}
		gap = true
	}
	return b.String()
}
