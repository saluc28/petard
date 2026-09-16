package taxonomy

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/saluc28/petard/internal/opaengine"
)

// patternsOnPolicyAlone are the patterns a false positive case can exercise as
// it stands: the ones whose signals are all in the policy, so one small bundle
// is a whole analysis.
//
// A pattern that reads the concrete data or the write model needs a case
// carrying those too, and what that should look like is not settled. Until it
// is, declaring a case on one of them fails here instead of passing in silence.
var patternsOnPolicyAlone = map[string]func(*opaengine.ReadSet) []Finding{
	ExternalSourceTaint:         TaintedByExternalSource,
	FailOpenOnSourceUnavailable: GrantsWhenSourceFails,
	EveryOverEmptyDomain:        FailOpenOnEmptyEvery,
}

// Every condition a pattern declares it fires on for nothing, run against the
// policy that realizes it.
//
// This is what separates verified from implemented. Implemented says the engine
// finds the case in the fixture next to its counter case. Verified says the
// conditions under which it fires with nothing behind it have been settled too:
// either a policy shows what the engine does, or the file admits the
// discriminator is not in the policy at all.
//
// A case that reports is not a failure. A declared false positive that still
// happens is the honest outcome, and the point of running it is that the day
// the engine starts telling the condition apart, the registry stops being right
// about itself here rather than in somebody's report.
func TestDeclaredFalsePositivesRunAsDeclared(t *testing.T) {
	patterns, err := LoadRegistry(filepath.Join("..", "..", "taxonomy-registry", "opa"))
	if err != nil {
		t.Fatalf("LoadRegistry() error = %v", err)
	}

	for _, pattern := range patterns {
		for i, fp := range pattern.FalsePositives {
			if fp.Case == nil {
				continue
			}
			t.Run(fmt.Sprintf("%s/%d", pattern.ID, i), func(t *testing.T) {
				run, ok := patternsOnPolicyAlone[pattern.ID]
				if !ok {
					t.Fatalf("%s carries a false positive case, and its signals need more than a policy to run", pattern.ID)
				}

				reads := readsOf(t, fp.Case.Policy)
				reported := len(run(reads)) > 0
				if reported != fp.Case.Reports {
					t.Errorf("the engine reports %v on this case and the registry says %v:\n%s", reported, fp.Case.Reports, fp.Condition)
				}
			})
		}
	}
}

// readsOf compiles one policy written in the registry and analyzes it.
func readsOf(t *testing.T, policy string) *opaengine.ReadSet {
	t.Helper()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "case.rego"), []byte(policy), 0o600); err != nil {
		t.Fatalf("writing the case: %v", err)
	}
	bundle, err := opaengine.Load([]string{dir}, opaengine.ParseModeAuto)
	if err != nil {
		t.Fatalf("the case does not compile: %v", err)
	}
	reads, err := opaengine.Reads(bundle, opaengine.Limits{})
	if err != nil {
		t.Fatalf("Reads() error = %v", err)
	}
	return reads
}

// A pattern that calls itself verified while leaving a declared condition
// unsettled is the failure this whole mechanism exists to prevent, and the one
// that would be easiest to introduce by editing a status and nothing else.
func TestVerifiedNeedsEveryConditionSettled(t *testing.T) {
	unsettled := Pattern{
		ID:     "PTD-OPA-000",
		Status: StatusVerified,
		FalsePositives: []FalsePositive{
			{Condition: "the domain is never empty in practice"},
		},
	}
	if err := checkFalsePositives(unsettled); err == nil {
		t.Error("a verified pattern with an unsettled condition was accepted")
	}

	unsettled.Status = "implemented"
	if err := checkFalsePositives(unsettled); err != nil {
		t.Errorf("an implemented pattern may still have conditions to settle: %v", err)
	}
}
