package taxonomy

import (
	"context"
	"fmt"
	"strings"

	"github.com/saluc28/petard/internal/graph"
	"github.com/saluc28/petard/internal/opaengine"
	"github.com/saluc28/petard/internal/writemodel"
)

// This file puts into the graph the two halves of the crossing the project is
// about: what each principal can get out of a decision as the data stands, and
// who can write the data those decisions are taken on. One comes out of the
// policy plus the documents, the other comes out of a declaration, and neither
// can be derived from the other.

// AddWritePaths puts the declared write model into the graph, as an edge from
// each attribute a decision reads to whoever can write it.
//
// Only writers that name one entity get an edge. A capture like {owner} and a
// derived relation like owner_of:{project} are rules for finding somebody, not
// somebody: turning them into a node would put a principal called "{owner}" in
// the graph and, worse, would make it traversable, so a path through it would
// read as a capability anybody could take. Where a capture actually matters,
// the subject writing their own field, the chain already produces a
// PTD_CanEscalateTo between the two real principals.
//
// It reports how many entries named nobody the graph could hold, which is the
// number that keeps this from looking like an empty write model.
func AddWritePaths(g *graph.Graph, reads *opaengine.ReadSet, model *writemodel.Model) (int, error) {
	if model == nil {
		return 0, nil
	}

	derived := 0
	for _, read := range reads.Paths() {
		path, err := writemodel.ParsePath(read)
		if err != nil {
			return 0, err
		}

		for _, entry := range model.Covering(path) {
			for _, writer := range entry.WritableBy {
				if !namesOneEntity(writer) {
					derived++
					continue
				}
				if err := addWriter(g, read, entry, writer); err != nil {
					return 0, err
				}
			}
		}
	}
	return derived, nil
}

// namesOneEntity reports whether a writer of the write model is somebody the
// graph can hold, rather than a way of finding them.
func namesOneEntity(writer writemodel.Writer) bool {
	if _, isCapture := writer.IsCapture(); isCapture {
		return false
	}
	return !strings.Contains(writer.Principal, "{")
}

func addWriter(g *graph.Graph, read string, entry writemodel.Entry, writer writemodel.Writer) error {
	if err := g.AddNode(graph.Node{
		ID:         writer.Principal,
		Kind:       graph.NodeKindPrincipal,
		Properties: map[string]any{graph.PropName: writer.Principal},
	}); err != nil {
		return fmt.Errorf("taxonomy: adding the writer %s: %w", writer.Principal, err)
	}

	// The attribute is already in the graph, put there by the read that found
	// it. An edge is refused if it is not, and that refusal is the check that
	// this model speaks about the policy that was analyzed.
	confidence := writer.Confidence
	if confidence == "" {
		confidence = "asserted"
	}
	if err := g.AddEdge(graph.Edge{
		Kind: graph.EdgeKindWrittenBy,
		From: read,
		To:   writer.Principal,
		Properties: map[string]any{
			graph.PropVia:             writer.Via,
			graph.PropWriteConfidence: confidence,
			graph.PropViaWritePath:    entry.RawPath,
		},
	}); err != nil {
		return fmt.Errorf("taxonomy: adding who writes %s: %w", read, err)
	}
	return nil
}

// AddCapabilities puts into the graph what each principal can get out of each
// decision, given the documents as they stand.
//
// It is the authorization graph itself, and the only part of the model
// that is a measurement of today rather than a reading of the policy: the same
// bundle against different data produces a different set of these edges, which
// is the point of having them.
//
// The far end is the resource the condition names, because that is what
// somebody path finding wants to arrive at. Where a condition constrains the
// action and nothing else, the action is the far end instead: a principal who
// may read anything has a capability worth an edge, and the only name that
// capability has is the verb.
//
// It returns how many ways of granting could not become an edge, which is not a
// detail to swallow. A capability edge is traversable, so BloodHound will walk
// it, and a way of granting that also depends on a second factor, on another
// part of the request, or on what a remote service answers is not a capability
// somebody simply has. Those are counted and left out rather than stated
// flatly, and the count is the honest size of the gap between this graph and
// what the policy really does.
func AddCapabilities(ctx context.Context, g *graph.Graph, a Analysis) (int, error) {
	if a.Data == nil {
		return 0, fmt.Errorf("%w: a capability is measured against documents", ErrNeedsData)
	}

	fields, named := subjectFieldsOf(a.Shape)
	if !named {
		return 0, nil
	}
	unknowns := unknownsBesides(a.Shape, a.Reads.InputPaths)
	if len(unknowns) == 0 {
		return 0, nil
	}

	principals, err := principalsOf(ctx, a.Shape, a.Reads, a.Data)
	if err != nil {
		return 0, err
	}

	conditional := 0
	for _, principal := range principals {
		for _, decision := range a.Reads.Decisions {
			if a.Reads.Denies(decision) {
				// What is left of a decision that denies are the ways to be
				// refused, and an edge somebody walks is a way to get in. See
				// grantingSide.
				continue
			}
			residuals, err := opaengine.Residuals(ctx, a.Bundle, a.Data, opaengine.Request{
				Decision: decision,
				Unknowns: unknowns,
				Input:    requestNaming(fields, principal),
			}, a.Limits)
			if err != nil {
				return 0, err
			}
			left, err := addCapabilities(g, a.Shape, principal, decision, residuals)
			if err != nil {
				return 0, err
			}
			conditional += left
		}
	}
	return conditional, nil
}

// grantingSide reports whether a decision reaches a read on the side that
// grants, and is one partial evaluation can measure access on.
//
// The patterns that measure access ask OPA what a decision still grants, and
// what it leaves of a decision declared to deny are the ways to be refused.
// Turning those around would take the complement of every condition, and the
// complement of a residual is a negation no edge and no written value can
// carry, so such a decision is left to the patterns that do not measure.
func grantingSide(reads *opaengine.ReadSet, decision opaengine.ReachedDecision) bool {
	return !decision.UnderNegation && !reads.Denies(decision.Name)
}

// addCapabilities turns the ways one decision can still hold for one principal
// into edges, one per way.
//
// Two ways to the same document stay two edges. They are two different
// conditions, and merging them would leave an edge whose property is half of
// why it exists: the fixture grants alice the same document both because she
// owns it and because of her department, and losing either would lose the
// reason somebody would act on.
func addCapabilities(g *graph.Graph, shape opaengine.Shape, principal, decision string, residuals *opaengine.ResidualSet) (int, error) {
	if len(residuals.Conditions) == 0 {
		return 0, nil
	}

	// Only the parts of the request that were recognized can be read out of a
	// condition, and asking about a role nobody identified would make every
	// condition look like it constrains something else.
	paths := make([]string, 0, 2)
	for _, path := range []string{shape.Resource, shape.Action} {
		if path != "" {
			paths = append(paths, path)
		}
	}
	if len(paths) == 0 {
		return len(residuals.Conditions), nil
	}

	if err := g.AddNode(graph.Node{
		ID:         principal,
		Kind:       graph.NodeKindPrincipal,
		Properties: map[string]any{graph.PropName: principal},
	}); err != nil {
		return 0, fmt.Errorf("taxonomy: adding the principal %s: %w", principal, err)
	}

	conditional := 0
	for _, condition := range residuals.Conditions {
		bindings, err := opaengine.BindingsOf(condition.Query, paths...)
		if err != nil {
			return 0, err
		}
		if bindings.Unexplained > 0 {
			// The decision grants here only if something else also holds, and
			// what that something is cannot be written on an edge somebody
			// walks. Stating it flatly would invent a capability.
			conditional++
			continue
		}

		resources, actions := bindings.Values[shape.Resource], bindings.Values[shape.Action]
		targets, kind := resources, graph.NodeKindResource
		if len(targets) == 0 {
			targets, kind = actions, graph.NodeKindAction
		}
		if len(targets) == 0 {
			conditional++
			continue
		}

		for _, target := range targets {
			properties := map[string]any{
				graph.PropDecision:   decision,
				graph.PropCondition:  condition.Query,
				graph.PropConfidence: shape.Confidence.String(),
			}
			// The action rides on the edge when the edge already points at the
			// resource, since an edge has one far end and the resource is the
			// one worth walking to.
			if kind == graph.NodeKindResource && len(actions) > 0 {
				properties[graph.PropAction] = strings.Join(actions, ", ")
			}
			if err := addCapability(g, principal, target, kind, properties); err != nil {
				return 0, err
			}
		}
	}
	return conditional, nil
}

func addCapability(g *graph.Graph, principal, target string, kind graph.NodeKind, properties map[string]any) error {
	if err := g.AddNode(graph.Node{
		ID:         target,
		Kind:       kind,
		Properties: map[string]any{graph.PropName: target},
	}); err != nil {
		return fmt.Errorf("taxonomy: adding %s: %w", target, err)
	}
	if err := g.AddEdge(graph.Edge{
		Kind:       graph.EdgeKindCanPerform,
		From:       principal,
		To:         target,
		Properties: properties,
	}); err != nil {
		return fmt.Errorf("taxonomy: adding what %s can do: %w", principal, err)
	}
	return nil
}
