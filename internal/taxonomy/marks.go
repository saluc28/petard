package taxonomy

import (
	"fmt"
	"slices"
	"strings"

	"github.com/saluc28/petard/internal/graph"
	"github.com/saluc28/petard/internal/opaengine"
)

// This file puts into the graph what the patterns found, on the nodes and edges
// the findings are about. Without it a saved query could find an escalation
// and never tell which pattern drew it, and it could not find at all what
// several patterns report, since they draw no edge of their own: a check that
// goes quiet or a source that fails open is a fact about a read, not a new
// relation.

// AddFindings leaves the mark of every finding on the graph, and reports how
// many reached nothing.
//
// Each finding goes where its fact is. An escalation marks the edge that draws
// it, which AddEscalations has to have added already. A position a principal
// holds marks the principal. A quantifier marks the rule that holds it, which a
// rule reading no document does not otherwise have a node for. Every other
// finding is about reads, and marks the reads it names, from the rule to the
// document, or to the value an external source answered with.
//
// A finding that reaches nothing speaks about something the graph does not
// hold, which is a defect in one of the two, and the count is how it shows.
func AddFindings(g *graph.Graph, reads *opaengine.ReadSet, findings []Finding) (int, error) {
	unmatched := 0
	for _, finding := range findings {
		reached, err := addFinding(g, reads, finding)
		if err != nil {
			return 0, err
		}
		if reached == 0 {
			unmatched++
		}
	}
	return unmatched, nil
}

// addFinding leaves the mark of one finding, and reports how many nodes and
// edges it reached.
func addFinding(g *graph.Graph, reads *opaengine.ReadSet, finding Finding) (int, error) {
	mark := markOf(finding)

	switch {
	case finding.Principal != "" && finding.Target != "":
		return g.MarkEdges(graph.EdgeKindCanEscalateTo, finding.Principal, finding.Target, mark), nil

	case finding.Principal != "":
		if err := g.AddNode(graph.Node{
			ID:         finding.Principal,
			Kind:       graph.NodeKindPrincipal,
			Properties: map[string]any{graph.PropName: finding.Principal},
		}); err != nil {
			return 0, fmt.Errorf("taxonomy: adding the principal %s: %w", finding.Principal, err)
		}
		return countOf(g.MarkNode(finding.Principal, mark)), nil

	case finding.PatternID == EveryOverEmptyDomain:
		reached := 0
		for _, site := range finding.Reads {
			if err := g.AddNode(graph.Node{
				ID:   site.Rule,
				Kind: graph.NodeKindRule,
				Properties: map[string]any{
					graph.PropName:       site.Rule,
					graph.PropIsDecision: slices.Contains(reads.Decisions, site.Rule),
				},
			}); err != nil {
				return 0, fmt.Errorf("taxonomy: adding the rule %s: %w", site.Rule, err)
			}
			reached += countOf(g.MarkNode(site.Rule, mark))
		}
		return reached, nil

	default:
		reached := 0
		for _, site := range finding.Reads {
			// A read of a document is named by the normalized path, a value
			// from an external source by the reference itself, which is what
			// the graph holds each of them under.
			read := finding.Path
			if read == "" {
				read = site.Ref
			}
			reached += g.MarkEdges(graph.EdgeKindReads, site.Rule, read, mark)
		}
		return reached, nil
	}
}

// markOf is what one finding leaves: the id of its pattern, and what that
// pattern knows that a query or a reader of the element needs.
func markOf(finding Finding) graph.Mark {
	mark := graph.Mark{Pattern: finding.PatternID, Candidate: finding.Verdict == VerdictCandidate}

	switch finding.PatternID {
	case DenyUndefinedOnMissingData:
		mark.Properties = map[string]any{
			graph.PropUncoveredKeys: strings.Join(finding.UncoveredKeys, ", "),
			graph.PropKeysChecked:   finding.KeysChecked,
			graph.PropEnforcingSide: finding.EnforcingSide,
			graph.PropConfidence:    finding.Confidence,
		}
	case FailOpenOnSourceUnavailable:
		mark.Properties = map[string]any{graph.PropMitigation: finding.Note}
	case EveryOverEmptyDomain:
		mark.Lists = map[string][]string{graph.PropEmptyDomains: {finding.Path}}
	case TransitiveGrantViaOwnership:
		if finding.Target == "" {
			position := fmt.Sprintf("%s: %s through %s, and %d without it",
				finding.Decision, waysOf(finding.ReachTransitive), strings.Join(finding.Relation, ", "), finding.ReachDirect)
			mark.Lists = map[string][]string{graph.PropPositions: {position}}
		}
	}
	return mark
}

// countOf turns whether one element was reached into a count.
func countOf(reached bool) int {
	if reached {
		return 1
	}
	return 0
}
