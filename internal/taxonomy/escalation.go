package taxonomy

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/saluc28/petard/internal/graph"
	"github.com/saluc28/petard/internal/opaengine"
	"github.com/saluc28/petard/internal/writemodel"
)

// Analysis is what the patterns are applied to: what the engine found, plus
// what the run was given to judge it against.
//
// It exists for the chain, which is the one thing here that needs all of it at
// once: the reads to know what a decision touches, the bundle and the data to
// evaluate it, the shape to know who is asking, and the model to know who can
// write. The patterns that need less keep taking less.
type Analysis struct {
	Bundle *opaengine.Bundle
	Reads  *opaengine.ReadSet
	Shape  opaengine.Shape

	// Model and Data are what a run may not have. Their absence is not a
	// failure: it decides what the patterns are allowed to claim.
	Model *writemodel.Model
	Data  *opaengine.Data

	Limits opaengine.Limits
}

// Escalations chains the self write pattern with the transitive grant pattern,
// and it is the only place a path comes out instead of an observation.
//
// Neither pattern is an attack path on its own. The first says a field is
// writable by whoever is being decided about; the second says a position in a
// hierarchy is worth a great deal. Put together they say that somebody who
// holds nothing can write one field and end up where somebody powerful stands,
// and that sentence is the whole point of the project.
//
// Three measurements make it, and each is the difference between two answers
// OPA gave about the same decision:
//
//  1. the principal gets nothing out of the decision today;
//  2. with the field they can write left unknown, they get something: partial
//     evaluation answers "there is a value that would work" without anybody
//     having to invent which one;
//  3. part of what they would get goes through the relation the transitive
//     pattern measured, which is what makes it the position of that other
//     principal rather than some other way in.
//
// The third is what ties the two patterns together instead of leaving them next
// to each other. Without it the chain would report anybody who can write
// anything that grants anything, and the report would say "escalation" where
// the honest word is "access".
//
// Nothing here decides that the principal holds nothing: it asks, and a
// principal who already gets something is left alone. Reporting them would mean
// measuring how much more they would get, which needs a threshold, and the
// threshold is the open question the transitive pattern already declares.
func Escalations(ctx context.Context, a Analysis, selfWrite, positions []Finding) ([]Finding, error) {
	if a.Data == nil {
		return nil, fmt.Errorf("%w: the chain measures what a write would open", ErrNeedsData)
	}

	writable := writablePaths(selfWrite)
	if len(writable) == 0 || len(positions) == 0 {
		return nil, nil
	}

	unknowns := unknownsBesides(a.Shape.Subject, a.Reads.InputPaths)
	fields, named := subjectFields(a.Shape.Subject)
	if len(unknowns) == 0 || !named {
		return nil, nil
	}

	principals, err := principalsOf(ctx, a.Shape, a.Reads, a.Data)
	if err != nil || len(principals) == 0 {
		return nil, err
	}

	var findings []Finding
	for _, position := range positions {
		cut, err := a.Data.Without(ctx, position.Relation...)
		if err != nil {
			return nil, err
		}

		for _, principal := range principals {
			if principal == position.Principal {
				// Already standing there: there is nothing to reach.
				continue
			}
			request := requestNaming(fields, principal)

			held, err := reachOf(ctx, a.Bundle, a.Data, position.Decision, request, unknowns, a.Limits)
			if err != nil {
				return nil, err
			}
			if !held.nothing() {
				continue
			}

			for _, entry := range writable {
				finding, err := escalationBy(ctx, a, cut, position, entry, principal, request, unknowns)
				if err != nil {
					return nil, err
				}
				if finding != nil {
					findings = append(findings, *finding)
				}
			}
		}
	}
	return sortedFindings(findings), nil
}

// escalationBy measures what writing one field would open for one principal,
// and describes the chain when what it opens is the position. It returns
// nothing when the measurements do not add up to one.
func escalationBy(ctx context.Context, a Analysis, cut *opaengine.Data, position, entry Finding,
	principal string, request map[string]any, unknowns []string) (*Finding, error) {

	document, err := opaengine.DocumentPath(entry.Path, entry.SubjectPosition, principal)
	if err != nil {
		// The position came from the write model and the path from the engine.
		// If they no longer line up, saying so beats reporting a chain measured
		// against the wrong document.
		return nil, err
	}

	// Leaving the document unknown is how the question "is there a value that
	// would work" gets asked of OPA rather than answered by us. A residual
	// condition on it is a value somebody could write.
	asWritten := append(slices.Clone(unknowns), document)

	opened, err := reachOf(ctx, a.Bundle, a.Data, position.Decision, request, asWritten, a.Limits)
	if err != nil {
		return nil, err
	}
	withoutRelation, err := reachOf(ctx, a.Bundle, cut, position.Decision, request, asWritten, a.Limits)
	if err != nil {
		return nil, err
	}

	if opened.nothing() || opened.always || withoutRelation.always {
		// Nothing to gain, or a decision that grants whatever it is asked:
		// neither is a position taken, and the second has no number to compare.
		return nil, nil
	}
	through := opened.ways - withoutRelation.ways
	if through <= 0 {
		// Whatever the write would open does not come from the relation, so it
		// is not this position that is being taken. It may well be worth
		// reporting, and the self write pattern already does.
		return nil, nil
	}

	// The sentence says what was measured and no more: the principal ends up
	// reaching through the relation that makes the other one's position worth
	// having, which is not the same claim as becoming that person.
	return &Finding{
		PatternID: TransitiveGrantViaOwnership,
		Verdict:   VerdictFinding,
		Summary: fmt.Sprintf("%s can reach what the position of %s reaches in %s, by writing %s: nothing today, %d ways after, %d of them through %s",
			principal, position.Principal, position.Decision, document, opened.ways, through, strings.Join(position.Relation, ", ")),
		Principal:       principal,
		Target:          position.Principal,
		Decision:        position.Decision,
		Path:            entry.Path,
		ViaWritePath:    entry.ViaWritePath,
		Via:             entry.Via,
		Relation:        slices.Clone(position.Relation),
		ReachTransitive: opened.ways,
		ReachDirect:     withoutRelation.ways,
		Reads:           slices.Concat(entry.Reads, position.Reads),
		Subject:         a.Shape.Subject,
		Confidence:      entry.Confidence,
	}, nil
}

// writablePaths keeps the self write results the write model stood behind.
//
// A candidate is not enough here. It says "this would be a finding if somebody
// can write the field", and the chain is about somebody doing exactly that:
// building a path on top of a maybe would put the whole claim on a declaration
// nobody made.
func writablePaths(selfWrite []Finding) []Finding {
	var writable []Finding
	for _, finding := range selfWrite {
		if finding.Verdict == VerdictFinding && finding.SubjectPosition > 0 {
			writable = append(writable, finding)
		}
	}
	return writable
}

// AddEscalations puts each escalation into the graph, the edges that mean
// privilege escalation: the 001 to 003 chain and the split grant alike, both of
// them a PTD_CanEscalateTo between two principals.
//
// The principals are nodes of their own here, and they are the first ones the
// analysis creates: everything else in the graph so far comes from reading the
// policy, and these come from the data plus a declaration about who writes it.
// That is exactly the crossing the whole project is about.
func AddEscalations(g *graph.Graph, findings []Finding) error {
	for _, finding := range findings {
		if finding.Principal == "" || finding.Target == "" {
			continue
		}

		for _, name := range []string{finding.Principal, finding.Target} {
			if err := g.AddNode(graph.Node{
				ID:         name,
				Kind:       graph.NodeKindPrincipal,
				Properties: map[string]any{graph.PropName: name},
			}); err != nil {
				return fmt.Errorf("taxonomy: adding principal %s: %w", name, err)
			}
		}

		edge := graph.Edge{
			Kind:       graph.EdgeKindCanEscalateTo,
			From:       finding.Principal,
			To:         finding.Target,
			Properties: escalationProperties(finding),
		}
		if len(finding.Reads) > 0 {
			site := finding.Reads[0]
			edge.Source = graph.Source{File: site.File, Line: site.Line, Rule: site.Rule}
		}
		if err := g.AddEdge(edge); err != nil {
			return fmt.Errorf("taxonomy: adding the escalation of %s: %w", finding.Principal, err)
		}
	}
	return nil
}

// escalationProperties are what an analyst needs on the edge to judge the claim
// without rerunning anything: which decision it is about, what has to be
// written and through what, how much the position is worth, and how well the
// subject was recognized in the first place.
//
// The last one is not decoration. The whole claim reads "this principal can
// become that one", and it rests on having identified who the request is about:
// an edge that reached the graph on a guess about field names must not look
// like one that reached it on a declaration.
func escalationProperties(finding Finding) map[string]any {
	properties := map[string]any{
		graph.PropDecision:   finding.Decision,
		graph.PropConfidence: finding.Confidence,
	}
	if finding.ViaWritePath != "" {
		properties[graph.PropViaWritePath] = finding.ViaWritePath
	}
	if finding.Via != "" {
		properties[graph.PropVia] = finding.Via
	}
	if finding.AuthorizedBy != "" {
		properties[graph.PropAuthorizedBy] = finding.AuthorizedBy
	}
	if finding.Value != "" {
		properties[graph.PropValue] = finding.Value
	}
	if len(finding.Relation) > 0 {
		properties[graph.PropRelation] = strings.Join(finding.Relation, ", ")
		properties[graph.PropReachTransitive] = finding.ReachTransitive
		properties[graph.PropReachDirect] = finding.ReachDirect
	}
	return properties
}
