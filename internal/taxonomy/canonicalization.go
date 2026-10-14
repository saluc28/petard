package taxonomy

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/saluc28/petard/internal/opaengine"
	"github.com/saluc28/petard/internal/pep"
)

// This file is the second way PTD-OPA-012 is found: the decision reads a part
// of the request as the caller wrote it, and the enforcement point acts on what
// that value resolves to.

// The values a request is built with. They are synthetic, so the test rests on
// how the decision treats a path and not on any path a policy writes: a place
// the decision grants, and a place outside it.
const (
	canonicalRoot   = "petard-root"
	canonicalLeaf   = "petard-leaf"
	canonicalBeyond = "petard-beyond"
)

// maxCanonicalBaselines bounds the values a part of the request is first set
// to, each of which costs a partial evaluation of the decision.
const maxCanonicalBaselines = 6

// GrantsBeforeCanonicalization finds the decisions that grant a value the
// enforcement point resolves to something they refuse.
//
// The enforcement point declares a part of the request canonicalized after the
// decision: the path a gateway hands on to an HTTP client that collapses its
// dot segments. The policy judged /do/../admin, and /admin is what is served.
// Whether that matters is in the policy, in a guard that refuses a traversal or
// in a match no traversal passes, and the pattern does not look for either. It
// asks the decision:
//
//  1. a request the decision grants is built, with the part set to a value the
//     decision accepts;
//  2. the same request is asked again with the part leaving that value by dot
//     segments, or by their percent-encoded form, for a place outside it;
//  3. and once more with the part set to that place, written plainly.
//
// Granting the second and refusing the third is the finding: the decision lets
// through a value that resolves to one it refuses. A decision that refuses the
// second is guarded, however the guard is written, and one that grants the
// third grants the place anyway, so nothing was bypassed.
//
// It needs a request the decision grants to start from. The ones given from
// outside come first (see GrantedRequest), then the ones it builds from the
// conditions partial evaluation leaves: with the part set to a value the
// decision may accept, and with the part left open, where the conditions say
// what it has to be. A decision that cannot be asked is a candidate saying so:
// it reads documents and none were given, OPA panics on it, or no request it
// grants was built or given. That last one is a decision that holds the part
// against something it computes, split(input.path, "/")[1] == "public", which
// leaves no condition to build from.
func GrantsBeforeCanonicalization(ctx context.Context, a Analysis) ([]Finding, error) {
	if a.EnforcementPoint == nil {
		return nil, nil
	}

	var findings []Finding
	for _, field := range a.EnforcementPoint.Fields {
		if len(field.CanonicalizedAfterDecision) == 0 {
			continue
		}
		for _, decision := range grantingDecisions(a.Reads) {
			sites := delegationSites(a.Reads, decision, field.Path)
			if len(sites) == 0 {
				continue
			}
			finding, err := canonicalizationFinding(ctx, a, decision, field, sites)
			if err != nil {
				return nil, err
			}
			if finding != nil {
				findings = append(findings, *finding)
			}
		}
	}
	return sortedFindings(findings), nil
}

// canonicalizationFinding asks one decision about one part of the request, and
// returns what it makes of the answers, or nil when the decision is guarded or
// no request it grants could be built.
func canonicalizationFinding(ctx context.Context, a Analysis, decision string, field pep.Field, sites []ReadSite) (*Finding, error) {
	// The claim rests on the declaration of the enforcement point, as for
	// PTD-OPA-009 to PTD-OPA-011 and PTD-OPA-013.
	finding := Finding{
		PatternID:  GrantOnLooseMatch,
		Decision:   decision,
		Path:       field.Path,
		Reads:      sites,
		Subject:    a.Shape.Subject,
		Confidence: opaengine.ConfidenceDeclared.String(),
	}
	unasked := func(why string) *Finding {
		finding.Verdict = VerdictCandidate
		finding.Summary = fmt.Sprintf("%s reads %s, which is canonicalized after the decision, and could not be asked "+
			"whether it grants a value that resolves elsewhere: %s", decision, field.Path, why)
		return &finding
	}

	if a.Data == nil {
		if decisionReadsData(a.Reads, decision) {
			return unasked("it reads the concrete data, and none was given"), nil
		}
		a.Data = opaengine.NoData()
	}

	proof, asked, err := traversalGranted(ctx, a, decision, field)
	var panicked *opaengine.EvaluatorPanicError
	switch {
	case errors.As(err, &panicked):
		return unasked(fmt.Sprintf("OPA panicked evaluating it (%s)", panicked.Cause)), nil
	case err != nil:
		return nil, err
	case !asked:
		return unasked("no request it grants could be built to start from, and none was given"), nil
	case proof == nil:
		return nil, nil
	}
	finding.Verdict = VerdictFinding
	finding.Value = strconv.Quote(proof.written)
	finding.Summary = fmt.Sprintf("%s grants %s as it is written and refuses what it resolves to: %q is "+
		"granted, and %q is refused", decision, field.Path, proof.written, proof.resolved)
	finding.Note = fmt.Sprintf("proven by %s, refused once %s is %q", JSON(proof.request), field.Path, proof.resolved)
	return &finding, nil
}

// traversal is what proves a decision grants a value that resolves to one it
// refuses: the request it grants, the value that request carries as written,
// and the value it resolves to, which the same request is refused with.
type traversal struct {
	request  map[string]any
	written  string
	resolved string
}

// traversalGranted looks for that proof: over every request the decision
// grants that was given or could be built, and every form the enforcement point
// collapses. It returns nil when it finds none, and reports whether there was
// any request to ask about.
func traversalGranted(ctx context.Context, a Analysis, decision string, field pep.Field) (*traversal, bool, error) {
	asked := false
	// from asks about requests the decision grants, one at a time. The value a
	// request carries in the part is the place the traversal leaves, and one
	// that carries no string there has none.
	from := func(requests []map[string]any) (*traversal, error) {
		for _, request := range requests {
			value, found := inputValue(request, field.Path)
			baseline, isString := value.(string)
			if !found || !isString {
				continue
			}
			asked = true
			for _, form := range field.CanonicalizedAfterDecision {
				written, resolved := leaving(baseline, form)
				bypassed, err := grantsAndRefuses(ctx, a, decision, request, field.Path, written, resolved)
				if err != nil {
					return nil, err
				}
				if bypassed {
					proof := copyInput(request)
					setInput(proof, field.Path, written)
					return &traversal{request: proof, written: written, resolved: resolved}, nil
				}
			}
		}
		return nil, nil
	}

	if proof, err := from(a.grantedBy(decision)); err != nil || proof != nil {
		return proof, asked, err
	}

	baselines, err := canonicalBaselines(ctx, a, decision, field.Path)
	if err != nil {
		return nil, asked, err
	}
	for _, baseline := range baselines {
		granted, err := requestsGranting(ctx, a, decision, field.Path, baseline)
		if err != nil {
			return nil, asked, err
		}
		if proof, err := from(granted); err != nil || proof != nil {
			return proof, asked, err
		}
	}
	if asked {
		return nil, true, nil
	}

	// No value the part was set to is one the decision grants. Left open with
	// the rest of the request, the part is whatever the conditions hold it to:
	// the path a rule compares it with, or the ones a document lists.
	granted, err := requestsGrantingAnyValue(ctx, a, decision)
	if err != nil {
		return nil, asked, err
	}
	proof, err := from(granted)
	return proof, asked, err
}

// withCanonicalized joins what the two ways of finding PTD-OPA-012 made of one
// analysis. A decision proven to grant a value that resolves elsewhere is one
// fact about that decision and that part of the request, so a candidate the
// form of the match left on the same two is dropped: the question it asked,
// whether the looseness matters at this enforcement point, has its answer.
func withCanonicalized(matched, canonicalized []Finding) []Finding {
	proven := map[[2]string]bool{}
	for _, finding := range canonicalized {
		if finding.Verdict == VerdictFinding {
			proven[[2]string{finding.Decision, finding.Path}] = true
		}
	}
	var joined []Finding
	for _, finding := range matched {
		if finding.Verdict == VerdictCandidate && proven[[2]string{finding.Decision, finding.Path}] {
			continue
		}
		joined = append(joined, finding)
	}
	return sortedFindings(append(joined, canonicalized...))
}

// decisionReadsData reports whether a decision reads any document.
func decisionReadsData(reads *opaengine.ReadSet, decision string) bool {
	for _, read := range reads.Reads {
		if reachesDecision(read.Decisions, decision) {
			return true
		}
	}
	return false
}

// canonicalBaselines returns values to set a part of the request to, among
// which one the decision grants may be found: a path of two segments of its
// own, one under each value the decision matches the part against loosely,
// written in the policy or held in the data, and each value the policy writes
// and holds the part against whole.
//
// The first is for a decision that takes what it matches against from the
// request too, as a gateway that sends the paths an agent accepts next to the
// path asked for: any value is then one some request grants. The second are for
// a decision that grants under /public/ and nowhere else. The last are for one
// that grants a list of paths and no other, which lets no traversal through and
// has to be asked to say so.
func canonicalBaselines(ctx context.Context, a Analysis, decision, part string) ([]string, error) {
	baselines := []string{"/" + canonicalRoot + "/" + canonicalLeaf}
	keep := func(written string) {
		if !slices.Contains(baselines, written) {
			baselines = append(baselines, written)
		}
	}
	under := func(operator opaengine.CheckOperator, value string) {
		if written, found := valueUnder(operator, value); found {
			keep(written)
		}
	}

	for _, check := range looseGrants(a.Reads.Checks, decision, part) {
		// A value that is not a string is not a path to stand under.
		if value, err := strconv.Unquote(check.Value); err == nil {
			under(check.Operator, value)
		}
	}
	for _, match := range looseGrants(a.Reads.DataMatches, decision, part) {
		held, err := a.Data.Values(ctx, match.Value)
		if err != nil {
			return nil, err
		}
		for _, value := range held {
			if text, isString := value.(string); isString {
				under(match.Operator, text)
			}
		}
	}

	for _, check := range a.Reads.Checks {
		whole := check.Operator == opaengine.CheckEqual || check.Operator == opaengine.CheckIn
		if !whole || !partUnder(check.Request, part) || !grantsIn(check, decision) {
			continue
		}
		for _, value := range check.Strings() {
			keep(value)
		}
	}

	if len(baselines) > maxCanonicalBaselines {
		baselines = baselines[:maxCanonicalBaselines]
	}
	return baselines, nil
}

// looseGrants keeps the checks that match a part of the request loosely and
// grant in a decision when they hold.
func looseGrants(checks []opaengine.Check, decision, part string) []opaengine.Check {
	var kept []opaengine.Check
	for _, check := range checks {
		if partUnder(check.Request, part) && check.Operator.Loose() && grantsIn(check, decision) {
			kept = append(kept, check)
		}
	}
	return kept
}

// grantsIn reports whether a check holding grants in a decision.
func grantsIn(check opaengine.Check, decision string) bool {
	for _, reached := range check.Decisions {
		if reached.Name == decision && reached.Grants {
			return true
		}
	}
	return false
}

// valueUnder returns a value a loose match on what the policy holds lets
// through, one segment below it: /public/petard-leaf for a prefix /public/, and
// the same with a root of its own in front for a value searched as a substring.
// A glob is filled in where it has wildcards. A suffix says nothing of where a
// path is, and a regex is not a value to stand under, so neither gives one.
func valueUnder(operator opaengine.CheckOperator, value string) (string, bool) {
	switch operator {
	case opaengine.CheckPrefix:
		return strings.TrimSuffix(value, "/") + "/" + canonicalLeaf, true
	case opaengine.CheckSubstring:
		return "/" + canonicalRoot + "/" + strings.Trim(value, "/") + "/" + canonicalLeaf, true
	case opaengine.CheckGlob, opaengine.CheckGlobEmbedded:
		filled := strings.NewReplacer("**", canonicalLeaf, "*", canonicalLeaf, "?", "p").Replace(value)
		if strings.ContainsAny(filled, "[]{}\\") {
			// A class or an alternation is not filled in by replacing wildcards.
			return "", false
		}
		return filled, true
	default:
		return "", false
	}
}

// requestsGranting returns requests the decision grants with one part set to a
// value, built from the conditions partial evaluation leaves once that part is
// known and each of them asked of the decision.
func requestsGranting(ctx context.Context, a Analysis, decision, part, value string) ([]map[string]any, error) {
	request := map[string]any{}
	setInput(request, part, value)

	// With nothing else read of the request there is nothing to leave open, and
	// the request is asked as it stands: an empty set of unknowns would be read
	// as the whole request unknown.
	candidates := []map[string]any{request}
	if unknowns := unknownsExcept(a.Reads.InputPaths, part); len(unknowns) > 0 {
		residuals, err := opaengine.Residuals(ctx, a.Bundle, a.Data, opaengine.Request{
			Decision: decision,
			Unknowns: unknowns,
			Input:    request,
		}, a.Limits)
		if err != nil {
			return nil, err
		}
		candidates = append(opaengine.GrantContentOf(residuals).Examples(request), request)
	}

	var granted []map[string]any
	for _, candidate := range candidates {
		holds, err := opaengine.Holds(ctx, a.Bundle, a.Data, decision, candidate)
		if err != nil {
			return nil, err
		}
		if holds {
			granted = append(granted, candidate)
		}
	}
	return granted, nil
}

// requestsGrantingAnyValue returns requests the decision grants, built from the
// conditions partial evaluation leaves with the whole request open.
func requestsGrantingAnyValue(ctx context.Context, a Analysis, decision string) ([]map[string]any, error) {
	residuals, err := opaengine.Residuals(ctx, a.Bundle, a.Data, opaengine.Request{
		Decision: decision,
		Unknowns: unknownsExcept(a.Reads.InputPaths),
	}, a.Limits)
	if err != nil {
		return nil, err
	}

	var granted []map[string]any
	for _, candidate := range opaengine.GrantContentOf(residuals).Examples(map[string]any{}) {
		holds, err := opaengine.Holds(ctx, a.Bundle, a.Data, decision, candidate)
		if err != nil {
			return nil, err
		}
		if holds {
			granted = append(granted, candidate)
		}
	}
	return granted, nil
}

// leaving returns a value that starts at a baseline and leaves it for a place
// outside, in the form one canonicalization collapses, and the value it
// resolves to: /public/petard-leaf/../../petard-beyond and /petard-beyond for
// the dot segments, and the same with each segment written %2e%2e for the
// percent-encoding.
func leaving(baseline string, form pep.Canonicalization) (written, resolved string) {
	up := ".."
	if form == pep.CanonicalPercentEncoding {
		up = "%2e%2e"
	}
	written = strings.TrimSuffix(baseline, "/")
	for range strings.FieldsFunc(baseline, func(r rune) bool { return r == '/' }) {
		written += "/" + up
	}
	written += "/" + canonicalBeyond

	decoded, err := url.PathUnescape(written)
	if err != nil {
		// The value was built here, so it decodes; if it did not, the form as
		// written is what there is to resolve.
		decoded = written
	}
	return written, path.Clean(decoded)
}

// grantsAndRefuses reports whether the decision grants a request with one part
// set to a value as written, and refuses the same request with that part set to
// what the value resolves to.
func grantsAndRefuses(ctx context.Context, a Analysis, decision string, request map[string]any, part, written, resolved string) (bool, error) {
	asWritten := copyInput(request)
	setInput(asWritten, part, written)
	granted, err := opaengine.Holds(ctx, a.Bundle, a.Data, decision, asWritten)
	if err != nil || !granted {
		return false, err
	}

	asResolved := copyInput(request)
	setInput(asResolved, part, resolved)
	served, err := opaengine.Holds(ctx, a.Bundle, a.Data, decision, asResolved)
	if err != nil {
		return false, err
	}
	return !served, nil
}
