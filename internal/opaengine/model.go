package opaengine

import (
	"fmt"

	"github.com/saluc28/petard/internal/graph"
)

// BuildGraph turns what the decisions read into the internal graph model.
//
// This is where the analysis stops being about Rego. Nothing of opa/v1/ast
// crosses over: a read arrives as a path, a provenance and a location, all of
// them strings and numbers, which is the whole point of the model being engine
// neutral. A second engine reaches the same graph by filling in the same
// fields.
//
// Three kinds of node come out of it. A rule is where a read happens, and it
// carries whether the PEP asks for that rule directly. An attribute is what
// gets read, named by its normalized path, so that two rules reading the same
// field meet on the same node: that meeting is what later makes it possible to
// ask who can write it. And a principal, for the external systems the policy
// asks and then believes.
func BuildGraph(reads *ReadSet) (*graph.Graph, error) {
	g := graph.New()

	decisions := make(map[string]bool, len(reads.Decisions))
	for _, decision := range reads.Decisions {
		decisions[decision] = true
	}

	if err := addReads(g, reads, decisions); err != nil {
		return nil, err
	}
	if err := addTaints(g, reads, decisions); err != nil {
		return nil, err
	}
	return g, nil
}

func addReads(g *graph.Graph, reads *ReadSet, decisions map[string]bool) error {
	for _, read := range reads.Reads {
		if err := g.AddNode(graph.Node{
			ID:   read.Rule,
			Kind: graph.NodeKindRule,
			Properties: map[string]any{
				graph.PropName:       read.Rule,
				graph.PropIsDecision: decisions[read.Rule],
			},
		}); err != nil {
			return fmt.Errorf("opaengine: adding rule %s: %w", read.Rule, err)
		}

		if err := g.AddNode(graph.Node{
			ID:   read.Path,
			Kind: graph.NodeKindAttribute,
			Properties: map[string]any{
				graph.PropName: read.Path,
			},
		}); err != nil {
			return fmt.Errorf("opaengine: adding attribute %s: %w", read.Path, err)
		}

		if err := g.AddEdge(graph.Edge{
			Kind: graph.EdgeKindReads,
			From: read.Rule,
			To:   read.Path,
			Source: graph.Source{
				File: read.File,
				Line: read.Line,
				Rule: read.Rule,
			},
			Properties: readProperties(read),
		}); err != nil {
			return fmt.Errorf("opaengine: adding read of %s: %w", read.Path, err)
		}
	}
	return nil
}

// addTaints puts the values the policy did not compute into the graph, each one
// pointing at whatever answered for it.
//
// The near end is an attribute like any other, even though no document under
// data holds it: what a decision depends on is the same kind of thing whether
// it was read from a store or believed from a response, and keeping the two in
// separate kinds would mean asking every query twice.
//
// The far end is a principal, which the model already defines as anything that
// can hold privilege, an external system deciding on somebody's behalf
// included. That is exactly what an endpoint the policy trusts is.
func addTaints(g *graph.Graph, reads *ReadSet, decisions map[string]bool) error {
	for _, taint := range reads.Taints {
		if err := g.AddNode(graph.Node{
			ID:         taint.Rule,
			Kind:       graph.NodeKindRule,
			Properties: map[string]any{graph.PropName: taint.Rule, graph.PropIsDecision: decisions[taint.Rule]},
		}); err != nil {
			return fmt.Errorf("opaengine: adding rule %s: %w", taint.Rule, err)
		}

		if err := g.AddNode(graph.Node{
			ID:         taint.Ref,
			Kind:       graph.NodeKindAttribute,
			Properties: map[string]any{graph.PropName: taint.Ref},
		}); err != nil {
			return fmt.Errorf("opaengine: adding tainted value %s: %w", taint.Ref, err)
		}

		source := externalSourceID(taint)
		if err := g.AddNode(graph.Node{
			ID:         source,
			Kind:       graph.NodeKindPrincipal,
			Properties: map[string]any{graph.PropName: source},
		}); err != nil {
			return fmt.Errorf("opaengine: adding external source %s: %w", source, err)
		}

		// The rule that reads the value depends on it exactly as it depends on
		// a document, so the read is recorded as one. Without it the tainted
		// value would sit in the graph attached to its origin and to nothing
		// that uses it.
		if err := g.AddEdge(graph.Edge{
			Kind:       graph.EdgeKindReads,
			From:       taint.Rule,
			To:         taint.Ref,
			Source:     graph.Source{File: taint.File, Line: taint.Line, Rule: taint.Rule},
			Properties: map[string]any{graph.PropRef: taint.Ref, graph.PropProvenance: ProvenanceBuiltin.String(), graph.PropProvenanceOrigin: taint.Origin, graph.PropUnderNegation: taint.UnderNegation},
		}); err != nil {
			return fmt.Errorf("opaengine: adding read of %s: %w", taint.Ref, err)
		}

		if err := g.AddEdge(graph.Edge{
			Kind:       graph.EdgeKindTaintedBy,
			From:       taint.Ref,
			To:         source,
			Source:     graph.Source{File: taint.File, Line: taint.Line, Rule: taint.Rule},
			Properties: map[string]any{graph.PropProvenanceOrigin: taint.Origin},
		}); err != nil {
			return fmt.Errorf("opaengine: adding the origin of %s: %w", taint.Ref, err)
		}
	}
	return nil
}

// externalSourceID names the thing that answered a call.
//
// Where the policy writes the destination out, that destination is the name,
// and two rules asking the same host meet on one node. Where the destination is
// computed the call site is the name instead, because a request that can steer
// where the policy asks is the worse case of the two and dropping it would hide
// it: what is known there is the call, not the host, and the id says so rather
// than inventing a host.
func externalSourceID(taint Taint) string {
	if taint.Endpoint != "" {
		return taint.Endpoint
	}
	return fmt.Sprintf("%s at %s:%d", taint.Origin, taint.File, taint.Line)
}

// readProperties are what an analyst needs on the edge to judge a read without
// opening the policy, plus what a taxonomy pattern needs to match on.
func readProperties(read Read) map[string]any {
	properties := map[string]any{
		graph.PropRef:           read.Ref,
		graph.PropProvenance:    read.Provenance.String(),
		graph.PropUnderNegation: read.UnderNegation,
	}
	if read.Trace != nil && read.Trace.Term != "" {
		properties[graph.PropProvenanceTerm] = read.Trace.Term
	}
	if read.Origin != "" {
		properties[graph.PropProvenanceOrigin] = read.Origin
	}
	return properties
}
