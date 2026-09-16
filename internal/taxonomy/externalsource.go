package taxonomy

import (
	"fmt"
	"net/url"
	"slices"

	"github.com/saluc28/petard/internal/opaengine"
)

// ExternalSourceTaint is the id of the OPA instance of the external source
// category.
const ExternalSourceTaint = "PTD-OPA-004"

// taintConfidence is the level this pattern reaches, on the scale of the
// design.
//
// It is written here rather than taken from the shape recognizers, and that is
// the point of it: every other pattern is worth what the recognition of the
// subject is worth, because the claim is about who is being decided about.
// This one makes no claim about the subject. A chain from a builtin to a
// decision is structure in the compiled AST, so the level is the highest on the
// scale for a reason of its own.
const taintConfidence = "A"

// externalSourceBuiltins are the builtins that bring data in from somewhere
// else.
//
// Every builtin the engine reports here is nondeterministic, which is what
// makes its value something the policy did not compute. Not all of them talk
// to anybody, though: time.now_ns and rand.intn are nondeterministic and have
// no other end, and a decision that depends on the clock is not one somebody
// controls.
//
// The list is open by design. A host that embeds OPA can register builtins of
// its own that read whatever it likes, and until the analysis is told about
// them they cannot be recognized. That is a declared limit of the pattern, not
// an oversight to fix by widening the list to every nondeterministic builtin.
var externalSourceBuiltins = []string{"http.send", "net.lookup_ip_addr"}

// TaintedByExternalSource finds the decisions that depend on a value fetched
// from outside the policy.
//
// The signals of the pattern, in order:
//
//  1. a builtin that brings in outside data is called in a rule that
//     contributes to a decision;
//  2. the value reaches the decision, which is the signal that separates this
//     from "the policy calls http.send" and is the only one a linter cannot
//     compute;
//  3. the destination is read from the call when the policy writes it as a
//     constant.
//
// The side of the decision the value reaches is not among them. Whoever answers
// picks the answer, so a source that decides a denial decides who is not
// denied: a blocklist is written by whoever serves it. Where a value sits
// decides what its absence does, which is PTD-OPA-005's question, and not what
// the party behind it can do.
//
// One finding per fact, and the fact is that a named decision depends on a
// named source. A source read in three rules that all feed the same decision
// is one finding with three places to look, because widening the trust
// perimeter of that decision happened once.
func TaintedByExternalSource(reads *opaengine.ReadSet) []Finding {
	// fact is what the findings are grouped by: one decision depending on one
	// party, however many rules carry the value there.
	type fact struct {
		decision string
		source   string
		origin   string
	}

	var findings []Finding
	at := make(map[fact]int, len(reads.Taints))

	for _, taint := range reads.Taints {
		if !slices.Contains(externalSourceBuiltins, taint.Origin) {
			continue
		}

		site := ReadSite{Ref: taint.Ref, Rule: taint.Rule, File: taint.File, Line: taint.Line}
		source := hostOf(taint.Endpoint)

		for _, decision := range taint.Decisions {
			key := fact{decision: decision.Name, source: source, origin: taint.Origin}
			if grouped, found := at[key]; found {
				findings[grouped].Reads = append(findings[grouped].Reads, site)
				continue
			}

			at[key] = len(findings)
			findings = append(findings, Finding{
				PatternID: ExternalSourceTaint,
				Verdict:   VerdictFinding,
				Summary: fmt.Sprintf("%s depends on %s, reached with %s",
					decision.Name, named(source), taint.Origin),
				Decision:   decision.Name,
				Source:     source,
				Origin:     taint.Origin,
				Reads:      []ReadSite{site},
				Confidence: taintConfidence,
			})
		}
	}
	return findings
}

// hostOf reduces an endpoint to whoever answers it.
//
// The host is the identity of the actor, not the URL: two paths on the same
// host are the same party, and it is the party that belongs in a graph of
// authorization next to the users. An endpoint that does not parse is reported
// as it was written, since inventing a host would be worse than an ugly one.
func hostOf(endpoint string) string {
	if endpoint == "" {
		return ""
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Hostname() == "" {
		return endpoint
	}
	return parsed.Hostname()
}
