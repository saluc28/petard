package taxonomy

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/saluc28/petard/internal/graph"
	"github.com/saluc28/petard/internal/opaengine"
)

// DenyUndefinedOnMissingData is the id of the OPA instance of the fail open
// category whose absence lives in the data.
const DenyUndefinedOnMissingData = "PTD-OPA-002"

// missingDataConfidence is the level this pattern reaches here.
//
// The registry files it at B, and says why: the weak signal is knowing which
// side of a decision applies the check, which depends on how the PEP combines
// the answers and is therefore outside the policy. This engine never guesses
// it. The walk starts at the rules the policy itself annotates as entrypoints,
// and the side that denies is a negated edge of that walk, so the claim rests
// on a declaration by the author plus a bool in the AST. A recognizer that
// inferred decisions from names would have to lower this.
const missingDataConfidence = "A"

// enforcingSideDeclared is how the side that applies the check was found, and
// it travels with the finding so that the confidence above can be checked
// rather than trusted.
const enforcingSideDeclared = "declared entrypoint, reached under a negation"

// ErrNeedsData is returned when a pattern that reads the concrete data is asked
// to run without it.
//
// It is an error rather than an empty result, for the reason the design gives
// about silence everywhere else: a run that found nothing and a run that could
// not look produce the same picture, and only one of them means the policy is
// fine.
var ErrNeedsData = errors.New("taxonomy: the pattern reads the concrete data, and none was loaded")

// FailOpenOnMissingData finds the checks that part of the data escapes.
//
// The signals of the pattern, in order:
//
//  1. the read sits in a rule that reaches a decision only through a negation,
//     which is the side that denies, and the read itself is not negated: a deny
//     rule whose body is undefined produces nothing, and a not on nothing
//     succeeds;
//  2. the reads are the resolved ones the walk produced, as in every other
//     pattern;
//  3. the path is absent for at least one document of the collections it
//     crosses, which is the signal no reading of the policy can produce and the
//     reason this one needs the data;
//  4. nothing turns that absence into a denial already: not a default on the
//     rule that reads, and not another rule of the same decision that denies
//     when the path is missing.
//
// One finding per fact, and the fact is that one decision does not apply one
// check to part of the data. A check read in two rules that feed the same
// decision is one hole, not two, and the places stay listed because that is
// where somebody has to go and look.
func FailOpenOnMissingData(ctx context.Context, reads *opaengine.ReadSet, data *opaengine.Data) ([]Finding, error) {
	if data == nil {
		return nil, fmt.Errorf("%w: %s", ErrNeedsData, DenyUndefinedOnMissingData)
	}

	// fact is what the findings are grouped by: one decision, one check it does
	// not apply everywhere.
	type fact struct {
		decision string
		path     string
	}

	var findings []Finding
	at := make(map[fact]int)
	presences := make(map[string]opaengine.Presence)
	guards := guardedPaths(reads)

	for _, read := range reads.Reads {
		if read.UnderNegation || closesOnAbsence(read.RuleDefault) {
			continue
		}

		for _, decision := range read.Decisions {
			if !decision.UnderNegation || guards.covers(decision.Name, read.Path) {
				continue
			}

			presence, measured := presences[read.Path]
			if !measured {
				found, err := data.Presence(ctx, read.Path)
				if err != nil {
					return nil, err
				}
				presences[read.Path] = found
				presence = found
			}
			if len(presence.Absent) == 0 {
				continue
			}

			site := ReadSite{Ref: read.Ref, Rule: read.Rule, File: read.File, Line: read.Line}
			key := fact{decision: decision.Name, path: read.Path}
			if grouped, taken := at[key]; taken {
				findings[grouped].Reads = append(findings[grouped].Reads, site)
				continue
			}

			at[key] = len(findings)
			findings = append(findings, missingDataFinding(read, decision.Name, presence, site))
		}
	}
	return findings, nil
}

// missingDataFinding describes one check a decision does not apply to part of
// the data.
//
// The keys are copied out of the measurement because the same measurement is
// shared by every decision that reads the same path, and a caller sorting or
// cutting one finding's list would otherwise reach into another's.
func missingDataFinding(read opaengine.Read, decision string, presence opaengine.Presence, site ReadSite) Finding {
	return Finding{
		PatternID: DenyUndefinedOnMissingData,
		Verdict:   VerdictFinding,
		Summary: fmt.Sprintf("%s is absent for %d of %d documents, and %s does not apply the check there",
			read.Path, len(presence.Absent), presence.Keys(), decision),
		Path:          read.Path,
		Decision:      decision,
		Reads:         []ReadSite{site},
		UncoveredKeys: slices.Clone(presence.Absent),
		KeysChecked:   presence.Keys(),
		EnforcingSide: enforcingSideDeclared,
		Confidence:    missingDataConfidence,
	}
}

// closesOnAbsence reports whether the value a rule falls back to makes the
// check apply even where the document is missing.
//
// A rule with no default is undefined when its body does not hold, and one
// defaulting to false is false: a not on either succeeds and the request goes
// through, so both leave the hole open. Only a default standing for a denial
// closes it.
func closesOnAbsence(ruleDefault string) bool {
	return ruleDefault != "" && ruleDefault != "false"
}

// guarded holds, per decision, the paths whose absence some rule of that
// decision already turns into a denial.
type guarded map[string][]string

// guardedPaths collects the reads that deny when the document is missing.
//
// A deny rule written as "not data.tenants[t].policy" says the opposite of the
// one this pattern is about: where the vulnerable form goes quiet on a missing
// document, this one fires. Two negations on the way, and the check applies to
// the whole collection after all.
//
// It looks across the whole decision, which is wider than the same rule the
// pattern file first claimed, and wider is right here: a defence written as a
// second deny rule of the same decision is the ordinary way to write one, and
// reporting it would be the kind of false positive that costs a reader's trust.
// A defence living in another decision is still invisible, and stays a declared
// limit of the pattern.
func guardedPaths(reads *opaengine.ReadSet) guarded {
	guards := guarded{}
	for _, read := range reads.Reads {
		if !read.UnderNegation {
			continue
		}
		for _, decision := range read.Decisions {
			if decision.UnderNegation {
				guards[decision.Name] = append(guards[decision.Name], read.Path)
			}
		}
	}
	return guards
}

// covers reports whether the absence of a path is already answered for a
// decision.
//
// A guard on a prefix guards everything below it: a rule that denies when the
// policy object is missing covers every field of that object, and the fields
// are exactly what the vulnerable rule reads.
func (g guarded) covers(decision, path string) bool {
	for _, guard := range g[decision] {
		if path == guard || strings.HasPrefix(path, guard+".") || strings.HasPrefix(path, guard+"[") {
			return true
		}
	}
	return false
}

// AddCoverageGaps records on the reads of the graph what this pattern found out
// about them afterwards: that a path a check depends on is absent for part of
// the data, so the check does not apply there.
//
// It enriches the read rather than adding an edge of its own, because the fact
// is about that read and nothing else. A parallel edge would leave the graph
// holding the same relation twice with half the truth on each.
//
// It reports how many findings reached no edge at all. That would mean the
// pattern is speaking about a read the graph does not hold, which is a defect
// in one of the two and not a quiet nothing.
func AddCoverageGaps(g *graph.Graph, findings []Finding) int {
	unmatched := 0
	for _, finding := range findings {
		if finding.Path == "" || len(finding.UncoveredKeys) == 0 {
			continue
		}

		properties := map[string]any{
			graph.PropUncoveredKeys: strings.Join(finding.UncoveredKeys, ", "),
			graph.PropKeysChecked:   finding.KeysChecked,
			graph.PropEnforcingSide: finding.EnforcingSide,
			graph.PropConfidence:    finding.Confidence,
		}

		reached := 0
		for _, site := range finding.Reads {
			reached += g.EnrichEdges(graph.EdgeKindReads, site.Rule, finding.Path, properties)
		}
		if reached == 0 {
			unmatched++
		}
	}
	return unmatched
}
