package taxonomy

import (
	"context"
	"slices"

	"github.com/saluc28/petard/internal/graph"
	"github.com/saluc28/petard/internal/opaengine"
	"github.com/saluc28/petard/internal/writemodel"
)

// This file is the whole taxonomy applied once: every implemented pattern over
// one analysis, and then the graph the results make together. It exists because
// two commands need the same answers, and the second one copying the first is
// how the two would start disagreeing about what the tool found.

// Findings are what every implemented pattern made of one analysis.
//
// They are kept per pattern rather than in one list because that is how they
// are read: under the pattern that made them, with the pattern's own title. The
// flat list is available for whoever needs it and is nobody's default.
type Findings struct {
	SelfWrite   []Finding
	MissingData []Finding

	// Transitive holds the positions worth taking and, first, the chains that
	// reach them. The registry puts both under the same pattern: a position is
	// a candidate, and it becomes a finding when somebody can take it.
	Transitive []Finding

	Tainted     []Finding
	Unavailable []Finding

	// EveryEmpty holds the checks written with `every` that stop applying when
	// their domain is empty. Like the other fail-open patterns it needs no data.
	EveryEmpty []Finding

	// SplitGrant holds the escalations that come from one decision governing a
	// write another decision grants on. Like the chain, each is a
	// PTD_CanEscalateTo between two principals.
	SplitGrant []Finding

	// GlobalSwitch holds the documents every request shares that decide for a
	// principal nobody named, which is to say for anybody.
	GlobalSwitch []Finding

	// Skipped names the patterns that could not run, and what it would have
	// taken. A pattern left out in silence reads as a pattern that found
	// nothing, which is the one thing these patterns exist to disprove.
	Skipped map[string]string
}

// All returns every finding, in the order the patterns are applied.
func (f Findings) All() []Finding {
	all := slices.Clone(f.SelfWrite)
	all = append(all, f.MissingData...)
	all = append(all, f.Transitive...)
	all = append(all, f.Tainted...)
	all = append(all, f.Unavailable...)
	all = append(all, f.EveryEmpty...)
	all = append(all, f.SplitGrant...)
	all = append(all, f.GlobalSwitch...)
	return all
}

// needsData is what a pattern that reads the documents is missing when there
// are none, said once so that two callers cannot word it differently.
const needsData = "it reads the concrete data, and none was given"

// Run applies every implemented pattern to one analysis.
//
// A pattern that cannot run is recorded in Skipped rather than returning an
// error: an analysis without concrete data is a perfectly good analysis of the
// policy, and refusing to produce the half that does not need documents would
// make the tool useless exactly where it is most often pointed, at a bundle
// somebody handed over without a database.
func Run(ctx context.Context, a Analysis) (Findings, error) {
	found := Findings{Skipped: map[string]string{}}

	selfWrite, err := SelfWrite(a.Reads, a.Shape, a.Model)
	if err != nil {
		return Findings{}, err
	}
	found.SelfWrite = selfWrite

	if a.Data == nil {
		found.Skipped[DenyUndefinedOnMissingData] = needsData
		found.Skipped[TransitiveGrantViaOwnership] = needsData
		found.Skipped[WriteAllowedByAnotherDecision] = needsData
		found.Skipped[GlobalDocumentDecides] = needsData
	} else {
		if found.MissingData, err = FailOpenOnMissingData(ctx, a.Reads, a.Data); err != nil {
			return Findings{}, err
		}

		positions, err := TransitiveGrant(ctx, a.Bundle, a.Reads, a.Shape, a.Data, a.Limits)
		if err != nil {
			return Findings{}, err
		}
		escalations, err := Escalations(ctx, a, selfWrite, positions)
		if err != nil {
			return Findings{}, err
		}
		found.Transitive = append(escalations, positions...)

		if found.SplitGrant, err = SplitGrant(ctx, a); err != nil {
			return Findings{}, err
		}
		if found.GlobalSwitch, err = GlobalSwitch(ctx, a); err != nil {
			return Findings{}, err
		}
	}

	found.Tainted = TaintedByExternalSource(a.Reads)
	found.Unavailable = GrantsWhenSourceFails(a.Reads)
	found.EveryEmpty = FailOpenOnEmptyEvery(a.Reads)
	return found, nil
}

// Gaps are what the analysis knows and the graph could not hold.
//
// Each of these is a silence that would otherwise read as an absence: a write
// model that speaks only of captures, a decision that grants under a condition
// no edge can carry, and a pattern naming a read the graph does not have would
// all look like nothing to report.
type Gaps struct {
	// DerivedWriters are declared writers that name a way of finding somebody
	// rather than somebody.
	DerivedWriters int

	// ConditionalWays are ways of granting that depend on something an edge
	// cannot say.
	ConditionalWays int

	// UnmatchedFindings are facts about a read the graph does not hold, which
	// is a defect in one of the two rather than nothing to report.
	UnmatchedFindings int
}

// Assemble builds the internal graph from an analysis and what the patterns
// made of it.
//
// The order is not arbitrary. The reads come first because everything else
// attaches to the attributes they create, the write model and the capabilities
// then add the two sides of the crossing this project is about, and the
// findings arrive last: two of them enrich edges that have to exist already.
func Assemble(ctx context.Context, a Analysis, findings Findings) (*graph.Graph, Gaps, error) {
	var gaps Gaps

	g, err := opaengine.BuildGraph(a.Reads)
	if err != nil {
		return nil, gaps, err
	}
	if gaps.DerivedWriters, err = AddWritePaths(g, a.Reads, a.Model); err != nil {
		return nil, gaps, err
	}
	if a.Data != nil {
		if gaps.ConditionalWays, err = AddCapabilities(ctx, g, a); err != nil {
			return nil, gaps, err
		}
	}

	all := findings.All()
	if err := AddEscalations(g, all); err != nil {
		return nil, gaps, err
	}
	gaps.UnmatchedFindings = AddCoverageGaps(g, all)

	return g, gaps, nil
}

// Inputs are the files and bounds a command was pointed at, before any of them
// has been read.
//
// It exists so that two commands cannot come to mean different things by the
// same flag. Which rules are decisions and which documents the analysis is
// measured against change every answer the tool gives, and a second command
// that read them slightly differently would disagree with the first about what
// the policy does.
type Inputs struct {
	// Paths are the Rego files or directories to analyze.
	Paths []string

	Mode opaengine.ParseMode

	// Entrypoints are the decisions declared from outside, for bundles whose
	// author annotated none.
	Entrypoints []string

	// Subject is the part of the request that names who is asking, declared
	// from outside, and empty to have it recognized. See opaengine.ShapeOf.
	Subject string

	// DataPath is the concrete data, and empty when there is none. Without it
	// the patterns that measure against documents cannot run, and say so.
	DataPath string

	// WriteModelPath declares who can write what. Without it every match stays
	// a candidate, because who writes what is not in the policy.
	WriteModelPath string

	Limits opaengine.Limits
}

// Load reads everything the inputs name and builds the analysis over it.
func Load(inputs Inputs) (Analysis, error) {
	bundle, err := opaengine.Load(inputs.Paths, inputs.Mode)
	if err != nil {
		return Analysis{}, err
	}
	bundle.Entrypoints = inputs.Entrypoints

	reads, err := opaengine.Reads(bundle, inputs.Limits)
	if err != nil {
		return Analysis{}, err
	}
	shape, err := opaengine.ShapeOf(reads, inputs.Subject)
	if err != nil {
		return Analysis{}, err
	}

	analysis := Analysis{
		Bundle: bundle,
		Reads:  reads,
		Shape:  shape,
		Limits: inputs.Limits,
	}

	if inputs.WriteModelPath != "" {
		if analysis.Model, err = writemodel.Load(inputs.WriteModelPath); err != nil {
			return Analysis{}, err
		}
	}
	if inputs.DataPath != "" {
		if analysis.Data, err = opaengine.LoadData([]string{inputs.DataPath}); err != nil {
			return Analysis{}, err
		}
	}
	return analysis, nil
}
