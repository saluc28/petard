package taxonomy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"

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
	// PTD_CanEscalateTo between two principals. Its three shapes are here
	// together, the value and the join of splitgrant.go and the sibling attribute
	// of siblinggrant.go, since all three are PTD-OPA-006.
	SplitGrant []Finding

	// GlobalSwitch holds the documents every request shares that decide for a
	// principal nobody named, which is to say for anybody.
	GlobalSwitch []Finding

	// SelfAsserted holds the refusals a request lifts by saying it is exempt.
	// It reads the policy and the declaration of the enforcement point, needs
	// no data, and does not run without the declaration.
	SelfAsserted []Finding

	// UncontrolledName holds the grants on a name somebody outside the policy
	// picks. Like SelfAsserted it does not run without the declaration, and the
	// write model decides between a finding and a candidate.
	UncontrolledName []Finding

	// AssumableIdentity holds the grants on a runtime identity somebody can
	// assume in another layer. Like SelfAsserted it does not run without the
	// declaration, and the declaration decides between a finding and a candidate.
	AssumableIdentity []Finding

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
	all = append(all, f.SelfAsserted...)
	all = append(all, f.UncontrolledName...)
	all = append(all, f.AssumableIdentity...)
	return all
}

// needsData is what a pattern that reads the documents is missing when there
// are none, said once so that two callers cannot word it differently.
const needsData = "it reads the concrete data, and none was given"

// needsEnforcementPoint is what a pattern that asks who sets a part of the
// request is missing when nobody declared the enforcement point.
const needsEnforcementPoint = "it asks who sets each part of the request, and no enforcement point was declared"

// needsWriteModel is what PTD-OPA-006 is missing without a write model. It
// starts from a write the model says a decision of the bundle allows, and the
// policy alone cannot say which decision governs which write.
const needsWriteModel = "it asks which decision allows each write, and no write model was given"

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

		if a.Model == nil {
			found.Skipped[WriteAllowedByAnotherDecision] = needsWriteModel
		} else {
			splitGrant, err := SplitGrant(ctx, a)
			if err != nil {
				return Findings{}, err
			}
			siblingGrant, err := SiblingGrant(ctx, a)
			if err != nil {
				return Findings{}, err
			}
			found.SplitGrant = sortedFindings(append(splitGrant, siblingGrant...))
		}
		if found.GlobalSwitch, err = GlobalSwitch(ctx, a); err != nil {
			return Findings{}, err
		}
	}

	found.Tainted = TaintedByExternalSource(a.Reads)
	found.Unavailable = GrantsWhenSourceFails(a.Reads)
	found.EveryEmpty = FailOpenOnEmptyEvery(a.Reads)
	if a.EnforcementPoint == nil {
		found.Skipped[SelfAssertedExemption] = needsEnforcementPoint
		found.Skipped[GrantOnUncontrolledName] = needsEnforcementPoint
		found.Skipped[GrantOnAssumableIdentity] = needsEnforcementPoint
		return found, nil
	}
	found.SelfAsserted = SelfAssertedExemptions(a)
	if found.UncontrolledName, err = GrantsOnUncontrolledNames(a); err != nil {
		return Findings{}, err
	}
	found.AssumableIdentity = GrantsOnAssumableIdentities(a)
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

	// UnmatchedFindings are facts about something the graph does not hold,
	// which is a defect in one of the two rather than nothing to report.
	UnmatchedFindings int
}

// Assemble builds the internal graph from an analysis and what the patterns
// made of it.
//
// The order is not arbitrary. The reads come first because everything else
// attaches to the attributes they create, the write model and the capabilities
// then add the two sides of the crossing this project is about, and the
// findings arrive last: the escalations draw their edges, and then every
// finding marks the edges and nodes it is about, the escalations included.
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
	if gaps.UnmatchedFindings, err = AddFindings(g, a.Reads, all); err != nil {
		return nil, gaps, err
	}
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

	// DenyEntrypoints are the decisions declared from outside that refuse the
	// request when they hold. See opaengine.Bundle.DenyEntrypoints.
	DenyEntrypoints []string

	// Subject is the part of the request that names who is asking, declared
	// from outside, and empty to have it recognized. See opaengine.ShapeOf.
	Subject string

	// DataPath is the concrete data, and empty when there is none. Without it
	// the patterns that measure against documents cannot run, and say so.
	DataPath string

	// WriteModelPath declares who can write what. Without it every match stays
	// a candidate, because who writes what is not in the policy.
	WriteModelPath string

	// EnforcementPoint names the product that asks for the decisions, the id
	// of a declaration in pep-registry or the path to one, and is empty when
	// nobody said. See DeclareEnforcementPoint.
	EnforcementPoint string

	Limits opaengine.Limits
}

// TokenEnv is the environment variable a running OPA's bearer token is read
// from, so the token stays out of the command line and the shell history.
const TokenEnv = "PETARD_OPA_TOKEN"

// Load reads everything the inputs name and builds the analysis over it.
//
// The paths are files, directories or bundle archives, or a single URL of a
// running OPA, whose policies are read over its API (see opaengine.LoadRemote).
// The context bounds the requests to a running OPA and is otherwise unused.
func Load(ctx context.Context, inputs Inputs) (Analysis, error) {
	remote, err := remoteSource(inputs.Paths)
	if err != nil {
		return Analysis{}, err
	}

	var bundle *opaengine.Bundle
	var token string
	if remote != "" {
		token = os.Getenv(TokenEnv)
		bundle, err = opaengine.LoadRemote(ctx, remote, token, inputs.Mode)
		if errors.Is(err, opaengine.ErrUnauthorized) {
			err = fmt.Errorf("%w; set %s to the bearer token", err, TokenEnv)
		}
	} else {
		bundle, err = opaengine.Load(inputs.Paths, inputs.Mode)
	}
	if err != nil {
		return Analysis{}, err
	}
	bundle.Entrypoints = inputs.Entrypoints
	bundle.DenyEntrypoints = inputs.DenyEntrypoints

	point, err := DeclareEnforcementPoint(bundle, inputs.EnforcementPoint)
	if err != nil {
		return Analysis{}, err
	}

	reads, err := opaengine.Reads(bundle, inputs.Limits)
	inferred := errors.Is(err, opaengine.ErrNoDecisions)
	if inferred {
		inferDecisions(bundle)
		reads, err = opaengine.Reads(bundle, inputs.Limits)
		if errors.Is(err, opaengine.ErrNoDecisions) {
			return Analysis{}, fmt.Errorf("%w; none can be inferred either, "+
				"since every rule is a function, a test or used by another rule", err)
		}
	}
	if err != nil {
		return Analysis{}, err
	}
	shape, err := ShapeOf(reads, inputs.Subject, point)
	if err != nil {
		return Analysis{}, err
	}

	analysis := Analysis{
		Bundle:            bundle,
		Reads:             reads,
		Shape:             shape,
		EnforcementPoint:  point,
		DecisionsInferred: inferred,
		Limits:            inputs.Limits,
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
		return analysis, nil
	}
	if remote != "" {
		// The data is what the running OPA holds, read over its API for the
		// roots the decisions read, the same way the bundle's data is read from
		// disk. A server with nothing under those roots is an analysis without
		// data.
		analysis.Data, err = opaengine.FetchData(ctx, remote, token, dataRoots(reads))
		switch {
		case err == nil:
			analysis.DataFromLive = true
		case !errors.Is(err, opaengine.ErrNoData):
			return Analysis{}, err
		}
		return analysis, nil
	}

	// Without -data, the data is what the bundle carries, if anything, the way
	// opa run reads a bundle. A bundle without data is an analysis without it.
	analysis.Data, err = opaengine.LoadBundleData(inputs.Paths)
	switch {
	case err == nil:
		analysis.DataFromBundle = true
	case !errors.Is(err, opaengine.ErrNoData):
		return Analysis{}, err
	}
	return analysis, nil
}

// dataRoots returns the distinct top-level documents the decisions read, as the
// segment right after data: data.users[_].roles and data.users.alice both sit
// under users. They are what a running OPA is asked for, one GET per root, so a
// live analysis reads the whole of each document a decision touches and no more.
func dataRoots(reads *opaengine.ReadSet) []string {
	seen := map[string]bool{}
	var roots []string
	for _, path := range reads.Paths() {
		root := strings.TrimPrefix(path, "data.")
		if i := strings.IndexAny(root, ".["); i >= 0 {
			root = root[:i]
		}
		if root != "" && !seen[root] {
			seen[root] = true
			roots = append(roots, root)
		}
	}
	slices.Sort(roots)
	return roots
}

// remoteSource returns the URL of a running OPA when the paths name one, and the
// empty string when they are files. A URL is analyzed on its own: mixing it with
// files, or with a second server, has no single bundle to compile.
func remoteSource(paths []string) (string, error) {
	var urls, files int
	var url string
	for _, path := range paths {
		if opaengine.IsRemote(path) {
			urls++
			url = path
			continue
		}
		files++
	}
	switch {
	case urls == 0:
		return "", nil
	case urls == 1 && files == 0:
		return url, nil
	default:
		return "", errors.New("taxonomy: a running OPA is analyzed on its own, not alongside files or another server")
	}
}

// inferDecisions declares as decisions the rules no other rule uses, for a
// bundle where nothing names them: no annotation, no flag, no enforcement point.
// Whole families of Rego annotate none, gatekeeper-library among them, and
// stopping there would leave them unanalyzed, while a rule nothing in the
// policy uses is one only a caller outside can be asking for (see
// opaengine.Bundle.Roots).
//
// Which side a root is on comes from its name, the way conftest reads one: deny
// and violation fail a check, warn flags one, and so does each of them followed
// by an underscore and a name, as deny_root (failureRegex and warningRegex in
// policy/engine.go:47 and :48 at conftest v0.71.0). Gatekeeper queries
// violation the same way. Such a rule refuses or flags the request when it
// holds or collects anything, so it is declared to deny, and every other root
// to grant.
func inferDecisions(bundle *opaengine.Bundle) {
	for _, root := range bundle.Roots() {
		name := root[strings.LastIndex(root, ".")+1:]
		if refusingName.MatchString(name) {
			bundle.DenyEntrypoints = append(bundle.DenyEntrypoints, root)
			continue
		}
		bundle.Entrypoints = append(bundle.Entrypoints, root)
	}
}

// refusingName is the name of a rule conftest reports as a failure or a
// warning.
var refusingName = regexp.MustCompile(`^(deny|violation|warn)(_[a-zA-Z0-9]+)*$`)
