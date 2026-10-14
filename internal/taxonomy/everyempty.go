package taxonomy

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/saluc28/petard/internal/opaengine"
)

// EveryOverEmptyDomain is the id of the OPA instance of the fail-open category
// that rests on a quantifier rather than on a missing document.
const EveryOverEmptyDomain = "PTD-OPA-007"

// everyConfidence is the level this pattern reaches: the same B as the other
// two fail-open instances. The signal that decides whether a vacuous truth
// grants or denies is the side the check applies on, and that depends on the
// PEP, which is the shared weak point of the family.
const everyConfidence = "B"

// maxEmptiedDocuments bounds the documents a domain in the data is emptied one
// at a time for. Past it the question is not asked: answering for some of the
// documents would say nothing of the rest.
const maxEmptiedDocuments = 16

// maxEverysAsked bounds the every expressions of one match the question is
// asked for. Each way of choosing among them is a copy of the policy to compile,
// and there are fifteen for four.
const maxEverysAsked = 4

// GrantsOnEmptyEvery finds the checks written with `every` that stop applying
// when their domain is empty, and leaves out the ones whose vacuous truth
// changes nothing.
//
// FailOpenOnEmptyEvery reads the body, and recognizes one guard: a count of the
// domain next to the every. A guard is as often an iteration of the domain, a
// `some` that binds one of its elements, or a count in another rule the
// decision also asks for, and next to a guarded every another rule of the same
// decision may grant whatever the domain holds. No list of shapes covers them,
// so each match is put to the policy. The decision is asked with the domain
// empty, of the policy as it is and of a copy where the every expressions of
// the match cannot hold over an empty domain (opaengine.Bundle.WithGuardedEvery).
// Where the decision says the same both times, value included, no request with
// the domain empty is answered differently because of them, and the match is
// dropped. It makes no difference how the decision answers, with yes or no,
// with a score, or with the violations it collects.
//
// A decision may hold more than one every over the same domain, and they are
// one match. A copy is then made for each way of choosing among them, and the
// match is dropped when none says anything else than the policy. Taking the
// vacuous truth from all of them at once is what shows two rules that each
// grant on it, where either alone leaves the other to grant. Taking it from one
// alone is what shows an every whose guard would hand the grant to another
// rule, one that holds only where a second every does not.
//
// The domain is emptied in the request when it is a part of it named whole, and
// in the data when it is a document, one document at a time. A domain the
// policy computes is emptied by nobody but a request, so it is asked as it is,
// with the whole request left open. A match the question cannot be asked about
// stays as the body reads: a domain under an element of a list of the request,
// a decision that reads documents when none were given, a domain over more
// documents than the bound, more every expressions than the bound, and a
// decision OPA panics on.
func GrantsOnEmptyEvery(ctx context.Context, a Analysis) ([]Finding, error) {
	var kept []Finding
	for _, finding := range FailOpenOnEmptyEvery(a.Reads) {
		idle, err := vacuousTruthChangesNothing(ctx, a, finding)
		if err != nil {
			return nil, err
		}
		if !idle {
			kept = append(kept, finding)
		}
	}
	return kept, nil
}

// vacuousTruthChangesNothing reports whether the decision of a match says the
// same, with the domain empty, whether or not its every expressions can hold
// over it, and false when that cannot be asked or could not be shown.
func vacuousTruthChangesNothing(ctx context.Context, a Analysis, finding Finding) (bool, error) {
	places := everyPlaces(finding.Reads)
	if len(places) == 0 || len(places) > maxEverysAsked {
		return false, nil
	}
	if a.Data == nil {
		if decisionReadsData(a.Reads, finding.Decision) {
			return false, nil
		}
		a.Data = opaengine.NoData()
	}
	emptied, askable, err := emptyDomains(ctx, a, finding.Decision, finding.Path)
	if err != nil || !askable {
		return false, err
	}

	// Every way of choosing among the places, all of them first: that is the
	// copy most often told from the policy, and one difference settles it.
	for chosen := 1<<len(places) - 1; chosen > 0; chosen-- {
		var guardedPlaces []opaengine.EveryPlace
		for i, place := range places {
			if chosen&(1<<i) != 0 {
				guardedPlaces = append(guardedPlaces, place)
			}
		}
		guarded, err := a.Bundle.WithGuardedEvery(guardedPlaces...)
		if errors.Is(err, opaengine.ErrNoSuchEvery) || errors.Is(err, opaengine.ErrCompile) {
			// With no copy to compare with, the match stays as the body reads.
			return false, nil
		}
		if err != nil {
			return false, err
		}
		for _, ask := range emptied {
			same, err := ask.same(ctx, a.Bundle, guarded)
			var panicked *opaengine.EvaluatorPanicError
			if errors.As(err, &panicked) {
				// A decision OPA panics on is one nothing could be shown about.
				return false, nil
			}
			if err != nil || !same {
				return false, err
			}
		}
	}
	return true, nil
}

// everyPlaces returns where the every expressions of a match sit, each place
// once.
func everyPlaces(sites []ReadSite) []opaengine.EveryPlace {
	var places []opaengine.EveryPlace
	for _, site := range sites {
		place := opaengine.EveryPlace{File: site.File, Line: site.Line}
		if !slices.Contains(places, place) {
			places = append(places, place)
		}
	}
	return places
}

// emptyDomain is one way of asking a decision with a domain empty: the data to
// ask against, and the request, with what is left open of it.
type emptyDomain struct {
	data    *opaengine.Data
	request opaengine.Request

	// whole is true when the request leaves nothing open, because the decisions
	// read nothing of it but the domain. It is then asked as it stands: partial
	// evaluation reads an empty set of unknowns as the whole request unknown.
	whole bool
}

// same reports whether the decision says the same in the policy and in its
// guarded copy, for this way of asking it.
func (e emptyDomain) same(ctx context.Context, asIs, guarded *opaengine.Bundle) (bool, error) {
	if e.whole {
		return opaengine.SameAnswer(ctx, asIs, guarded, e.data, e.request.Decision, e.request.Input)
	}
	return opaengine.SameResiduals(ctx, asIs, guarded, e.data, e.request)
}

// emptyDomains returns the questions that, together, ask a decision with a
// domain empty in every way it can be: as an empty list and as an empty object,
// in the request or in each document the domain names. A domain the policy
// computes is asked once, as it is. It reports false when the domain cannot be
// emptied in any of these ways.
func emptyDomains(ctx context.Context, a Analysis, decision, domain string) ([]emptyDomain, bool, error) {
	empties := []any{[]any{}, map[string]any{}}

	if strings.HasPrefix(domain, "input.") {
		if strings.Contains(domain, "[") {
			// One element of a list cannot be given an empty domain without
			// saying what the rest of that element holds.
			return nil, false, nil
		}
		unknowns := unknownsExcept(a.Reads.InputPaths, domain)
		var asks []emptyDomain
		for _, empty := range empties {
			request := map[string]any{}
			setInput(request, domain, empty)
			asks = append(asks, emptyDomain{
				data:    a.Data,
				request: opaengine.Request{Decision: decision, Unknowns: unknowns, Input: request},
				whole:   len(unknowns) == 0,
			})
		}
		return asks, true, nil
	}

	if a.Bundle.Computes(domain) {
		return []emptyDomain{{data: a.Data, request: opaengine.Request{Decision: decision}}}, true, nil
	}

	documents := []string{domain}
	if strings.Contains(domain, "[") {
		resolved, err := a.Data.Documents(ctx, domain)
		if err != nil {
			return nil, false, err
		}
		documents = resolved
	}
	if len(documents) == 0 || len(documents) > maxEmptiedDocuments {
		return nil, false, nil
	}
	var asks []emptyDomain
	for _, document := range documents {
		for _, empty := range empties {
			data, err := a.Data.With(ctx, document, empty)
			if err != nil {
				return nil, false, err
			}
			asks = append(asks, emptyDomain{data: data, request: opaengine.Request{Decision: decision}})
		}
	}
	return asks, true, nil
}

// FailOpenOnEmptyEvery finds the checks written with `every` that stop applying
// when their domain is empty.
//
// `every x in xs { cond }` holds when nothing in `xs` breaks `cond`, and an
// empty `xs` breaks nothing, so the quantifier is vacuously true. On the side
// that grants, that is a check whose domain of application shrinks to nothing
// exactly when the request brings an empty collection.
//
// The signals, in order:
//
//  1. an entrypoint reaches an every expression, which the walk collects as a
//     quantifier with the decisions that depend on it;
//  2. the every is on the granting side: a decision reaches it with an even
//     number of negations, or an odd one when it is declared to deny, so its
//     vacuous truth lets the request through rather than stopping it;
//  3. the domain derives from input or data, so the request or the documents
//     can make it empty, rather than being a literal that never is;
//  4. no guard in the body forces the domain non-empty first, which is the
//     counter case the fixture pairs it with.
//
// It emits a finding, not an escalation: like the other fail-open patterns it
// reports a check that does not apply, not a principal reaching another. No
// write model is needed, because nothing is written; the defect is that a
// collection can be empty.
func FailOpenOnEmptyEvery(reads *opaengine.ReadSet) []Finding {
	var findings []Finding
	at := map[string]int{}

	for _, quantifier := range reads.Quantifiers {
		if quantifier.Domain == "" || quantifier.Guarded {
			// A literal domain cannot be emptied by the request, and a guarded
			// one is the counter case: neither leaves a vacuous grant.
			continue
		}
		site := ReadSite{Ref: quantifier.Domain, Rule: quantifier.Rule, File: quantifier.File, Line: quantifier.Line}
		for _, decision := range quantifier.Decisions {
			if decision.UnderNegation {
				// A vacuous truth reached through a negation denies, which is
				// fail-closed and not a defect.
				continue
			}
			// One decision and one domain are one match, with every place the
			// decision reaches an every over that domain.
			key := decision.Name + "\x00" + quantifier.Domain
			if i, seen := at[key]; seen {
				if !slices.Contains(findings[i].Reads, site) {
					findings[i].Reads = append(findings[i].Reads, site)
				}
				continue
			}
			at[key] = len(findings)

			findings = append(findings, Finding{
				PatternID: EveryOverEmptyDomain,
				Verdict:   VerdictFinding,
				Summary: fmt.Sprintf("%s lets the request through when %s is empty, because the every over it is vacuously true",
					decision.Name, quantifier.Domain),
				Decision:   decision.Name,
				Path:       quantifier.Domain,
				Reads:      []ReadSite{site},
				Confidence: everyConfidence,
			})
		}
	}
	return sortedFindings(findings)
}
