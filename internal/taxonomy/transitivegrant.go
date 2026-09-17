package taxonomy

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/saluc28/petard/internal/opaengine"
)

// TransitiveGrantViaOwnership is the id of the OPA instance of the transitive
// grant category.
const TransitiveGrantViaOwnership = "PTD-OPA-003"

// transitiveConfidence is the level this pattern reaches.
//
// The measurement is exact: it is what OPA answers against the concrete data,
// twice. What is a guess is who the principals are, since naming them means
// taking the collection the subject of the request indexes for the list of
// people, and the subject itself comes from the shape recognizers. The level
// therefore travels with the shape rather than being written here, and this
// constant is only what it falls back to when the shape says nothing.
const transitiveConfidence = "E"

// TransitiveGrant measures what a position in a hierarchy is worth.
//
// The signals of the pattern, in order:
//
//  1. a rule that contributes to a decision follows a relation as far as it
//     goes, which in Rego means a call to graph.reachable, to
//     graph.reachable_paths, or to walk, since recursion between rules is
//     forbidden;
//  2. the relation is named by what the rule building it reads;
//  3. for every principal, the decision is evaluated against the concrete data
//     twice, once as it stands and once against data with that relation cut,
//     and the difference is what the propagation was granting;
//  4. a position is reported when it grants nothing on its own and something
//     through the relation.
//
// The third signal is the reason this pattern does not compute reachability of
// its own. A graph walk written here would answer the mathematical question,
// and the fixture proves the two answers differ: an adjacency list that omits
// the root makes graph.reachable stop a level short, so a position that a graph
// library would call worth eighteen documents is worth none. OPA evaluates the
// construct the policy really uses, and a difference between two of its answers
// cannot inherit a semantics we never wrote.
//
// It emits a candidate and not a finding, and the distinction is the registry's:
// a hierarchy that propagates access is doing its job. What the pattern says is
// that a position is worth a lot, which is a target rather than a defect. It
// becomes a path only together with a pattern that says how that position can
// be taken.
func TransitiveGrant(ctx context.Context, bundle *opaengine.Bundle, reads *opaengine.ReadSet, shape opaengine.Shape, data *opaengine.Data, limits opaengine.Limits) ([]Finding, error) {
	if data == nil {
		return nil, fmt.Errorf("%w: %s", ErrNeedsData, TransitiveGrantViaOwnership)
	}

	relations := relationsPerDecision(reads)
	if len(relations) == 0 {
		return nil, nil
	}

	// The rest of the request stays unknown, so that the count is what the
	// principal can get out of the decision however they ask, and not what one
	// hand written request happens to return.
	unknowns := unknownsBesides(shape, reads.InputPaths)
	if len(unknowns) == 0 {
		return nil, nil
	}

	// Whether a principal can be named at all is a property of the subject, so
	// it is settled once here rather than per principal inside the loop, where
	// failing would throw away the findings already made.
	fields, named := subjectFieldsOf(shape)
	if !named {
		return nil, nil
	}

	principals, err := principalsOf(ctx, shape, reads, data)
	if err != nil || len(principals) == 0 {
		return nil, err
	}

	sites := closureSites(reads)

	var findings []Finding
	for decision, relation := range relations {
		cut, err := data.Without(ctx, relation...)
		if err != nil {
			return nil, err
		}

		for _, principal := range principals {
			request := requestNaming(fields, principal)

			granted, err := reachOf(ctx, bundle, data, decision, request, unknowns, limits)
			if err != nil {
				return nil, err
			}
			own, err := reachOf(ctx, bundle, cut, decision, request, unknowns, limits)
			if err != nil {
				return nil, err
			}

			if granted.always {
				// The decision grants this principal whatever they ask for, so
				// there is no number of ways to compare and no position in a
				// hierarchy to weigh: a decision that does not discriminate is
				// a different fact, and reporting it here would mean printing a
				// count of zero next to the word reaches.
				continue
			}
			if granted.nothing() || !own.nothing() {
				// Either the position grants nothing at all, or it grants
				// without the relation too. The second is the counter case of
				// the fixture: a member of a leaf, and an administrator who
				// reaches everything for a reason that has nothing to do with
				// the hierarchy.
				continue
			}

			findings = append(findings, Finding{
				PatternID: TransitiveGrantViaOwnership,
				Verdict:   VerdictCandidate,
				Summary: fmt.Sprintf("%s reaches %s in %d ways through %s, and in %d without it",
					principal, decision, granted.ways, strings.Join(relation, ", "), own.ways),
				Decision:        decision,
				Principal:       principal,
				ReachTransitive: granted.ways,
				ReachDirect:     own.ways,
				Relation:        slices.Clone(relation),
				Reads:           sites[decision],
				Subject:         shape.Subject,
				Confidence:      confidenceOf(shape),
			})
		}
	}
	return sortedFindings(findings), nil
}

// relationsPerDecision collects, for each decision, the data a transitive
// construct it depends on is built from.
//
// The relations of one decision are cut together rather than one at a time. A
// decision that follows two hierarchies is granting through both, and measuring
// them separately would report each as harmless because the other still holds.
//
// A closure reached only through a negation is left out: a relation that only
// ever denies is not one that grants a position, whatever its reach.
func relationsPerDecision(reads *opaengine.ReadSet) map[string][]string {
	relations := make(map[string][]string)
	for _, closure := range reads.Closures {
		if len(closure.Relation) == 0 {
			// Nothing in the data holds this propagation up, so there is
			// nothing to cut and no measurement to make. The pattern declares
			// the case rather than guessing at one.
			continue
		}
		for _, decision := range closure.Decisions {
			if !decision.UnderNegation {
				relations[decision.Name] = append(relations[decision.Name], closure.Relation...)
			}
		}
	}
	for decision, paths := range relations {
		relations[decision] = sortedUnique(paths)
	}
	return relations
}

// closureSites is where to go and look, per decision: the calls that follow the
// relation. The finding is a measurement rather than a read, so without these
// the report would name a number and no line of policy to check it against.
func closureSites(reads *opaengine.ReadSet) map[string][]ReadSite {
	sites := make(map[string][]ReadSite)
	for _, closure := range reads.Closures {
		site := ReadSite{Ref: closure.Builtin, Rule: closure.Rule, File: closure.File, Line: closure.Line}
		for _, decision := range closure.Decisions {
			if !decision.UnderNegation {
				sites[decision.Name] = append(sites[decision.Name], site)
			}
		}
	}
	return sites
}

// principalsOf names the principals the policy knows about, by reading the
// collection the subject of the request picks documents from, and the values
// it looks the subject up among.
//
// A policy does not list who exists, so this is the closest thing to a list
// there is, and it is worth stating what it costs: a principal nobody is
// decided about, because no rule ever reads their record, is invisible here.
// Only the values that are strings count, since a request names a principal
// with one.
func principalsOf(ctx context.Context, shape opaengine.Shape, reads *opaengine.ReadSet, data *opaengine.Data) ([]string, error) {
	var principals []string
	for _, collection := range opaengine.SubjectCollections(shape, reads) {
		presence, err := data.Presence(ctx, collection)
		if err != nil {
			return nil, err
		}
		principals = append(principals, presence.Present...)
	}
	for _, path := range opaengine.SubjectValues(shape, reads) {
		values, err := data.Values(ctx, path)
		if err != nil {
			return nil, err
		}
		for _, value := range values {
			if name, isString := value.(string); isString {
				principals = append(principals, name)
			}
		}
	}
	return sortedUnique(principals), nil
}

// reach is how much a decision grants somebody: in how many ways, or without
// any condition left to meet at all.
type reach struct {
	// ways is the number of residual conditions, which is how many ways the
	// decision has of granting rather than how many resources it grants. Two
	// ways to the same document count twice, and that is the honest reading of
	// what partial evaluation returns.
	ways int

	// always is true when the decision holds whatever the rest of the request
	// turns out to be. It is not a large number of ways, it is the absence of a
	// question, and the two must not be added together.
	always bool
}

// nothing reports whether the decision grants that principal nothing.
func (r reach) nothing() bool {
	return !r.always && r.ways == 0
}

// reachOf asks how much of a decision one principal can get, with the rest of
// the request left open.
func reachOf(ctx context.Context, bundle *opaengine.Bundle, data *opaengine.Data, decision string, request map[string]any, unknowns []string, limits opaengine.Limits) (reach, error) {
	residuals, err := opaengine.Residuals(ctx, bundle, data, opaengine.Request{
		Decision: decision,
		Unknowns: unknowns,
		Input:    request,
	}, limits)
	if err != nil {
		return reach{}, err
	}
	return reach{ways: len(residuals.Conditions), always: residuals.Always}, nil
}

// subjectFields is where a request names a principal: the fields that lead
// there, and whether the last of them holds a list of principals.
type subjectFields struct {
	path []string
	list bool
}

// subjectFieldsOf breaks the path of the subject into the fields of a request,
// and reports whether a request can name a principal that way at all.
//
// It refuses anything that is not a plain path, a list of principals aside: an
// index or a call standing where a field name should be cannot be written into
// a request, and a request that quietly named nobody would measure every
// principal as reaching whatever an anonymous caller reaches.
func subjectFieldsOf(shape opaengine.Shape) (subjectFields, bool) {
	const root = "input."
	subject, list := shape.SubjectList()
	if !strings.HasPrefix(subject, root) {
		return subjectFields{}, false
	}

	path := strings.Split(strings.TrimPrefix(subject, root), ".")
	for _, field := range path {
		if field == "" || strings.ContainsAny(field, "[]()\"") {
			return subjectFields{}, false
		}
	}
	return subjectFields{path: path, list: list}, true
}

// requestNaming builds a request that names one principal, however deep in the
// request the subject was found.
//
// A list names the principal as its only element. That is a request from one
// identity and nothing else, the way Chef Automate's own tests ask about a
// member (input.subjects as ["z"] in authz_test.rego at 61ca031): what the
// principal holds together with the teams an authenticator would add is a
// union of these, and which teams go together is not in the policy.
func requestNaming(fields subjectFields, principal string) map[string]any {
	request := map[string]any{}

	at := request
	for _, field := range fields.path[:len(fields.path)-1] {
		next := map[string]any{}
		at[field] = next
		at = next
	}
	var named any = principal
	if fields.list {
		named = []any{principal}
	}
	at[fields.path[len(fields.path)-1]] = named
	return request
}

// unknownsBesides returns the parts of the request to leave open: everything
// the decisions read except the subject, which is the part being fixed. For a
// list that is the whole list, since the request fixes all of it.
func unknownsBesides(shape opaengine.Shape, paths []string) []string {
	return unknownsExcept(paths, subjectRoot(shape))
}

// subjectRoot is the part of the request that naming one principal fixes: the
// subject, or the whole list when the subject is one of several identities.
func subjectRoot(shape opaengine.Shape) string {
	root, _ := shape.SubjectList()
	return root
}

// confidenceOf is what a claim about a principal is worth, which is what the
// recognition of the subject is worth.
func confidenceOf(shape opaengine.Shape) string {
	if shape.Subject == "" {
		return transitiveConfidence
	}
	return shape.Confidence.String()
}

// sortedUnique sorts a list of strings and drops the repeats.
func sortedUnique(values []string) []string {
	slices.Sort(values)
	return slices.Compact(values)
}

// sortedFindings puts the findings in an order that does not depend on the
// iteration order of a map, so that two runs over the same bundle report the
// same thing in the same order.
//
// The sort is stable and the path is part of the key, because one principal can
// have more than one way in: without both, two findings that differ only in the
// field to write could swap places between runs.
func sortedFindings(findings []Finding) []Finding {
	slices.SortStableFunc(findings, func(a, b Finding) int {
		for _, by := range []int{
			strings.Compare(a.Decision, b.Decision),
			strings.Compare(a.Principal, b.Principal),
			strings.Compare(a.Path, b.Path),
		} {
			if by != 0 {
				return by
			}
		}
		return 0
	})
	return findings
}
