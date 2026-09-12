package taxonomy

import (
	"fmt"
	"slices"
	"strings"

	"github.com/saluc28/petard/internal/opaengine"
)

// FailOpenOnSourceUnavailable is the id of the OPA instance of the fail open
// category whose absence comes from the network.
const FailOpenOnSourceUnavailable = "PTD-OPA-005"

// unavailableConfidence is the level this pattern reaches here, and it is the
// same claim as in the missing data pattern: the chain from the call to the
// decision is structure in the compiled AST, and the side that applies the
// check is declared by the policy rather than guessed. The registry files the
// pattern at B for the general case, where decisions are recognized instead of
// annotated.
const unavailableConfidence = "A"

// failureFields are the fields of a response that say the call failed rather
// than what it answered.
//
// Reading one of them is the defensive form: where the vulnerable rule goes
// quiet because the body never arrived, a rule that reads the error fires
// exactly then. It is also why a read of one of these is never itself reported.
var failureFields = []string{"error", "status_code"}

// GrantsWhenSourceFails finds the decisions that let a request through when an
// external source does not answer.
//
// The signals of the pattern, in order:
//
//  1. a builtin that depends on the network is called in a rule that
//     contributes to a decision, which is the same signal the external source
//     pattern starts from and is computed once for both;
//  2. the value reaches the decision only in a position that denies, so a
//     failure that leaves the expression undefined lets the request through.
//     The side that denies is the negated edge of a walk that starts at the
//     entrypoints the policy declares;
//  3. the value is needed for the body to hold, which holds by construction:
//     the expressions of a body are conjunctions, so a value read in it is a
//     value the body cannot do without;
//  4. no branch of the same rule reads the error or the status of the response,
//     which is what separates a rule that goes quiet on failure from one that
//     was written to notice it.
//
// The option raise_error decides none of this, and that is the point of the
// pattern rather than a detail of it: the fixture holds the same vulnerable
// shape with the option and without it, and both fail open. What the option
// changes is whether the deployment has a switch left, which travels with the
// finding as the note.
//
// One finding per fact, and the fact is that one decision goes quiet when one
// party stops answering.
func GrantsWhenSourceFails(reads *opaengine.ReadSet) []Finding {
	defended := rulesThatNoticeFailure(reads)

	type fact struct {
		decision string
		source   string
	}

	var findings []Finding
	at := make(map[fact]int, len(reads.Taints))

	for _, taint := range reads.Taints {
		if !slices.Contains(externalSourceBuiltins, taint.Origin) {
			continue
		}
		// A read of the failure itself marked its own rule as defended, so it is
		// already out: there is no second check for it here.
		if defended[taint.Rule] {
			continue
		}

		site := ReadSite{Ref: taint.Ref, Rule: taint.Rule, File: taint.File, Line: taint.Line}
		source := hostOf(taint.Endpoint)

		for _, decision := range taint.Decisions {
			if !decision.UnderNegation {
				// The value reaches this decision in a position to grant, so a
				// source that stops answering closes the door instead of
				// opening it. That is availability, not authorization, and it
				// is the counter case the fixture holds twice.
				continue
			}

			key := fact{decision: decision.Name, source: source}
			if grouped, found := at[key]; found {
				findings[grouped].Reads = append(findings[grouped].Reads, site)
				continue
			}

			at[key] = len(findings)
			findings = append(findings, Finding{
				PatternID: FailOpenOnSourceUnavailable,
				Verdict:   VerdictFinding,
				Summary: fmt.Sprintf("%s lets the request through when %s does not answer, and nothing in %s notices",
					decision.Name, named(source), taint.Rule),
				Decision:   decision.Name,
				Source:     source,
				Origin:     taint.Origin,
				Reads:      []ReadSite{site},
				Note:       mitigation(taint.Errors),
				Confidence: unavailableConfidence,
			})
		}
	}
	return findings
}

// rulesThatNoticeFailure marks the rules where some branch reads the failure of
// the call.
//
// It looks across the whole rule rather than one body at a time, because the
// defensive form is written as a second branch: one body denies when the score
// is too high, another denies when the call came back with an error. Seen one
// body at a time, the first branch looks exactly like the vulnerable rule.
func rulesThatNoticeFailure(reads *opaengine.ReadSet) map[string]bool {
	defended := make(map[string]bool)
	for _, taint := range reads.Taints {
		if readsFailure(taint.Ref) {
			defended[taint.Rule] = true
		}
	}
	return defended
}

// readsFailure reports whether a read is of the failure of a call rather than
// of what it answered.
//
// The field has to sit directly on the response, because that is where the
// builtin puts it. A body carrying an error of its own is the service reporting
// something, not the call failing to happen, and treating enrichment.body.error
// as a defence would silence a rule that never looks at whether the call
// arrived.
func readsFailure(ref string) bool {
	segments := strings.Split(ref, ".")
	return len(segments) > 1 && slices.Contains(failureFields, segments[1])
}

// mitigation says whether anybody outside the policy can still make the failure
// visible.
//
// It is what the finding is worth acting on with, and it is not what makes it a
// finding: a decision that goes quiet is one whether or not a switch exists for
// noticing it.
func mitigation(errors opaengine.ErrorHandling) string {
	switch errors {
	case opaengine.ErrorHandlingSuppressed:
		return "raise_error is false, so there is no error left for strict-builtin-errors to make fatal"
	case opaengine.ErrorHandlingUnknown:
		return "the request is computed, so whether an error would be raised cannot be read from the policy"
	default:
		return "the caller can still make the failure fatal by asking for strict-builtin-errors"
	}
}
