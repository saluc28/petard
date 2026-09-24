package taxonomy

import (
	"fmt"
	"slices"
	"testing"

	"github.com/saluc28/petard/internal/fixture"
	"github.com/saluc28/petard/internal/opaengine"
	"github.com/saluc28/petard/internal/writemodel"
)

// analyzeGenerated runs the whole pipeline over a generated world, with the
// policy and the write model of the hand written fixture.
//
// The policy is the one that reads this shape of data, and the write model
// speaks about paths rather than about documents, so both carry over unchanged.
// What changes is the world, which is the point: the same rules against another
// dataset is where a pattern that reports too much shows it.
func analyzeGenerated(t *testing.T, params fixture.Params) (*fixture.Dataset, Analysis) {
	t.Helper()

	dataset, err := fixture.Generate(params)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	dir := t.TempDir()
	if err := dataset.Write(dir); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	data, err := opaengine.LoadData([]string{dir})
	if err != nil {
		t.Fatalf("LoadData() error = %v", err)
	}
	model, err := writemodel.Load(fixturePath("write-model.yaml"))
	if err != nil {
		t.Fatalf("writemodel.Load() error = %v", err)
	}

	bundle := fixtureBundle(t)
	reads, err := opaengine.Reads(bundle, opaengine.Limits{})
	if err != nil {
		t.Fatalf("Reads() error = %v", err)
	}

	return dataset, Analysis{
		Bundle:           bundle,
		Reads:            reads,
		Shape:            opaengine.RecognizeShape(reads),
		Model:            model,
		Data:             data,
		EnforcementPoint: fixtureGateway(t),
	}
}

// The measurement a pattern needs before the registry may call it verified,
// and the one a hand written bundle cannot give.
//
// With one case written by hand the only question is "does the engine find that
// one", and a pattern that reported everything would pass it. Here K principals
// are planted holding nothing, at coordinates the generator knows, and the run
// is scored twice: how many of them come back, and how many come back that were
// never planted.
//
// Recall has to be total. Precision is allowed to be less than perfect and is
// not allowed to be unexplained: the number below is asserted exactly, so that
// a change in the engine that starts inventing escalations fails here instead
// of being discovered in a report.
func TestPrecisionOnGeneratedData(t *testing.T) {
	dataset, a := analyzeGenerated(t, fixture.Medium(20260822))

	selfWrite, err := SelfWrite(a.Reads, a.Shape, a.Model)
	if err != nil {
		t.Fatalf("SelfWrite() error = %v", err)
	}
	positions, err := TransitiveGrant(t.Context(), a.Bundle, a.Reads, a.Shape, a.Data, a.Limits)
	if err != nil {
		t.Fatalf("TransitiveGrant() error = %v", err)
	}
	escalations, err := Escalations(t.Context(), a, selfWrite, positions)
	if err != nil {
		t.Fatalf("Escalations() error = %v", err)
	}

	planted := dataset.Truth.Escalating
	var found, invented []string
	for _, finding := range escalations {
		if slices.Contains(planted, finding.Principal) {
			found = append(found, finding.Principal)
			continue
		}
		invented = append(invented, finding.Principal)
	}
	found = slices.Compact(slices.Sorted(slices.Values(found)))

	if !slices.Equal(found, planted) {
		t.Errorf("recall: found %v of the %v planted, and it has to be all of them", found, planted)
	}
	if len(invented) != 0 {
		t.Errorf("precision: %d escalations reported that were never planted: %v", len(invented), invented)
	}

	// Every escalation points at the principal standing in the root, which is
	// the only position in a generated world that holds no document of its own.
	for _, finding := range escalations {
		if finding.Target != dataset.Truth.Rooted {
			t.Errorf("%s was said to reach the position of %s, and the planted position is %s",
				finding.Principal, finding.Target, dataset.Truth.Rooted)
		}
	}
}

// The same measurement for the check that goes missing, where the coordinates
// are tenants rather than principals. It is exact on both sides: the keys the
// engine reports as uncovered have to be the keys the generator left uncovered,
// no more and no fewer.
func TestUncoveredKeysOnGeneratedData(t *testing.T) {
	dataset, a := analyzeGenerated(t, fixture.Medium(20260822))

	findings, err := FailOpenOnMissingData(t.Context(), a.Reads, a.Data)
	if err != nil {
		t.Fatalf("FailOpenOnMissingData() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want the one check the generator plants a hole in:\n%v", len(findings), findings)
	}

	if !slices.Equal(findings[0].UncoveredKeys, dataset.Truth.UncoveredTenants) {
		t.Errorf("uncovered = %v, planted = %v", findings[0].UncoveredKeys, dataset.Truth.UncoveredTenants)
	}
}

// A world generated from another seed is another world, and the numbers have to
// hold there too: an assertion that only passes on one dataset is measuring the
// dataset.
func TestPrecisionHoldsAcrossSeeds(t *testing.T) {
	for _, seed := range []uint64{1, 7, 4242} {
		t.Run(fmt.Sprintf("seed %d", seed), func(t *testing.T) {
			dataset, a := analyzeGenerated(t, fixture.Small(seed))

			selfWrite, err := SelfWrite(a.Reads, a.Shape, a.Model)
			if err != nil {
				t.Fatalf("SelfWrite() error = %v", err)
			}
			positions, err := TransitiveGrant(t.Context(), a.Bundle, a.Reads, a.Shape, a.Data, a.Limits)
			if err != nil {
				t.Fatalf("TransitiveGrant() error = %v", err)
			}
			escalations, err := Escalations(t.Context(), a, selfWrite, positions)
			if err != nil {
				t.Fatalf("Escalations() error = %v", err)
			}

			var reported []string
			for _, finding := range escalations {
				reported = append(reported, finding.Principal)
			}
			reported = slices.Compact(slices.Sorted(slices.Values(reported)))

			if !slices.Equal(reported, dataset.Truth.Escalating) {
				t.Errorf("reported %v, planted %v", reported, dataset.Truth.Escalating)
			}
		})
	}
}

// The split grant invents nothing on a world that plants none. The generator
// gives every principal the viewer role, so nobody can write themselves editor,
// and a pattern that reported one anyway would be inventing an escalation, which
// is the one risk generated data is here to rule out. Recall for this pattern is
// the hand written fixture's job; this is the precision half, across seeds.
func TestSplitGrantInventsNothingOnGeneratedData(t *testing.T) {
	for _, seed := range []uint64{1, 7, 4242} {
		t.Run(fmt.Sprintf("seed %d", seed), func(t *testing.T) {
			_, a := analyzeGenerated(t, fixture.Small(seed))

			findings, err := SplitGrant(t.Context(), a)
			if err != nil {
				t.Fatalf("SplitGrant() error = %v", err)
			}
			if len(findings) != 0 {
				t.Errorf("split grant invented %d escalations on data that plants none: %v", len(findings), findings)
			}
		})
	}
}

// The global switch rests on the policy too: whether a setting decides for
// somebody no document names depends on what the decision reads before it, and
// the generated worlds change the records, not the rules. On every one of them
// the reading room comes out and the console does not.
func TestGlobalSwitchRestsOnThePolicyNotTheData(t *testing.T) {
	for _, seed := range []uint64{1, 7, 4242} {
		t.Run(fmt.Sprintf("seed %d", seed), func(t *testing.T) {
			_, a := analyzeGenerated(t, fixture.Small(seed))

			findings, err := GlobalSwitch(t.Context(), a)
			if err != nil {
				t.Fatalf("GlobalSwitch() error = %v", err)
			}
			if len(findings) != 1 || findings[0].Path != "data.settings.reading_room.open" {
				t.Errorf("global switch on generated data = %v, want only the reading room", findings)
			}
		})
	}
}

// The every-over-empty pattern rests on the policy, not the data, so on every
// generated world it reports the same one finding, the unguarded merge decision,
// and never another. It is the same property `PTD-OPA-004` and `PTD-OPA-005`
// have: a dataset does not move a defect that lives in the shape of the rule. A
// second finding here would be the engine reading the data where it must not.
func TestEveryEmptyRestsOnThePolicyNotTheData(t *testing.T) {
	for _, seed := range []uint64{1, 7, 4242} {
		t.Run(fmt.Sprintf("seed %d", seed), func(t *testing.T) {
			_, a := analyzeGenerated(t, fixture.Small(seed))

			findings := FailOpenOnEmptyEvery(a.Reads)
			if len(findings) != 1 || findings[0].Decision != "data.quill.review.allow_unguarded" {
				t.Errorf("every-empty on generated data = %v, want only the unguarded merge decision", findings)
			}
		})
	}
}

// The self-asserted exemption rests on the policy and on the declaration of
// the gateway, and a generated world changes neither: on every one of them the
// scheduled export comes out, and the second factor does not.
func TestSelfAssertedExemptionRestsOnThePolicyNotTheData(t *testing.T) {
	for _, seed := range []uint64{1, 7, 4242} {
		t.Run(fmt.Sprintf("seed %d", seed), func(t *testing.T) {
			_, a := analyzeGenerated(t, fixture.Small(seed))

			findings := SelfAssertedExemptions(a)
			if len(findings) != 1 || findings[0].Path != "input.scheduled" {
				t.Errorf("self-asserted exemptions on generated data = %v, want only input.scheduled", findings)
			}
		})
	}
}
