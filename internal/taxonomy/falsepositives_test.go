package taxonomy

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/saluc28/petard/internal/opaengine"
	"github.com/saluc28/petard/internal/writemodel"
	registry "github.com/saluc28/petard/taxonomy-registry"
)

// Every condition a pattern declares it fires on for nothing, run against the
// case that realizes it.
//
// This is what separates verified from implemented. Implemented says the engine
// finds the case in the fixture next to its counter case. Verified says the
// conditions under which it fires with nothing behind it have been settled too:
// either a case shows what the engine does, or the file admits the
// discriminator is not in the policy or the data at all.
//
// A case that reports is not a failure. A declared false positive that still
// happens is the honest outcome, and the point of running it is that the day
// the engine starts telling the condition apart, the registry stops being right
// about itself here rather than in somebody's report.
//
// Each case goes through Run, the path an analysis takes, so a pattern that
// needs the documents or the write model finds them in the case. One that Run
// skips because the case left them out fails here, instead of passing because
// a pattern that never ran reported nothing.
func TestDeclaredFalsePositivesRunAsDeclared(t *testing.T) {
	patterns, err := LoadRegistry(registry.OPA)
	if err != nil {
		t.Fatalf("LoadRegistry() error = %v", err)
	}

	for _, pattern := range patterns {
		for i, fp := range pattern.FalsePositives {
			if fp.Case == nil {
				continue
			}
			t.Run(fmt.Sprintf("%s/%d", pattern.ID, i), func(t *testing.T) {
				found, err := Run(t.Context(), analysisOf(t, fp.Case))
				if err != nil {
					t.Fatalf("Run() error = %v", err)
				}
				if reason, skipped := found.Skipped[pattern.ID]; skipped {
					t.Fatalf("%s did not run on this case: %s", pattern.ID, reason)
				}

				reported := slices.ContainsFunc(found.All(), func(f Finding) bool {
					return f.PatternID == pattern.ID
				})
				if reported != fp.Case.Reports {
					t.Errorf("the engine reports %v on this case and the registry says %v:\n%s", reported, fp.Case.Reports, fp.Condition)
				}
			})
		}
	}
}

// analysisOf lays one case out the way an analysis finds it on disk, a bundle
// with its documents and its write model beside it, and analyzes it.
func analysisOf(t *testing.T, c *FalsePositiveCase) Analysis {
	t.Helper()

	dir := t.TempDir()
	policy := filepath.Join(dir, "policy")
	writeCaseFile(t, filepath.Join(policy, "case.rego"), c.Policy)
	bundle, err := opaengine.Load([]string{policy}, opaengine.ParseModeAuto)
	if err != nil {
		t.Fatalf("the case does not compile: %v", err)
	}
	reads, err := opaengine.Reads(bundle, opaengine.Limits{})
	if err != nil {
		t.Fatalf("Reads() error = %v", err)
	}
	a := Analysis{Bundle: bundle, Reads: reads, Shape: opaengine.RecognizeShape(reads)}

	if c.Data != "" {
		documents := filepath.Join(dir, "data")
		writeCaseFile(t, filepath.Join(documents, "data.json"), c.Data)
		if a.Data, err = opaengine.LoadData([]string{documents}); err != nil {
			t.Fatalf("the data of the case does not load: %v", err)
		}
	}
	if c.WriteModel != "" {
		file := filepath.Join(dir, "write-model.yaml")
		writeCaseFile(t, file, c.WriteModel)
		if a.Model, err = writemodel.Load(file); err != nil {
			t.Fatalf("the write model of the case does not load: %v", err)
		}
	}
	return a
}

func writeCaseFile(t *testing.T, path, content string) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("creating %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
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
