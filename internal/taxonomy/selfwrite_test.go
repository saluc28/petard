package taxonomy

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/saluc28/petard/internal/opaengine"
	"github.com/saluc28/petard/internal/writemodel"
)

func fixturePath(parts ...string) string {
	return filepath.Join(append([]string{"..", "..", "fixtures", "vulnerable-bundle"}, parts...)...)
}

// analyzeFixture runs the whole pipeline on the fixture, which is the only way
// this test means anything: the findings have to come out of the real policy,
// not out of a ReadSet written to produce them.
func analyzeFixture(t *testing.T) (*opaengine.ReadSet, opaengine.Shape, *writemodel.Model) {
	t.Helper()

	bundle, err := opaengine.Load([]string{fixturePath("policy-v1")}, opaengine.ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	reads, err := opaengine.Reads(bundle, opaengine.Limits{})
	if err != nil {
		t.Fatalf("Reads() error = %v", err)
	}
	model, err := writemodel.Load(fixturePath("write-model.yaml"))
	if err != nil {
		t.Fatalf("writemodel.Load() error = %v", err)
	}
	return reads, opaengine.RecognizeShape(reads), model
}

// This is the case and the counter case of PTD-OPA-001, and the counter case is
// the one that matters: the same record, both fields picked by the subject, and
// only the write model tells them apart. A model at record granularity would
// report both, which is the systematic false positive the design warns about.
func TestSelfWriteOnFixture(t *testing.T) {
	reads, shape, model := analyzeFixture(t)

	findings, err := SelfWrite(reads, shape, model)
	if err != nil {
		t.Fatalf("SelfWrite() error = %v", err)
	}

	var paths []string
	for _, finding := range findings {
		if finding.Verdict != VerdictFinding {
			t.Errorf("%s is a %s, want a finding: the model covers it", finding.Path, finding.Verdict)
		}
		paths = append(paths, finding.Path)
	}
	slices.Sort(paths)
	paths = slices.Compact(paths)

	expected := []string{"data.users[_].profile.department"}
	if !slices.Equal(paths, expected) {
		t.Errorf("findings = %v, want %v", paths, expected)
	}

	if len(findings) != 1 {
		t.Fatalf("findings = %d, want one per fact and not one per line", len(findings))
	}
	if sites := len(findings[0].Reads); sites != 2 {
		t.Errorf("read sites = %d, want 2: the decision reads it, and so does is_member", sites)
	}
	for _, finding := range findings {
		if finding.ViaWritePath != "data.users.{owner}.profile.department" {
			t.Errorf("via write path = %q", finding.ViaWritePath)
		}
		if finding.Via != "PATCH /api/v1/me/profile" {
			t.Errorf("via = %q, want the endpoint from the model", finding.Via)
		}
		if finding.Subject != "input.user" || finding.Confidence != "D" {
			t.Errorf("subject = %q at confidence %q, want input.user at D", finding.Subject, finding.Confidence)
		}
	}
}

// data.users[_].roles is read by a decision, indexed by the subject, and not
// negated: the first three signals hold exactly as they do for the case. It is
// not a finding because roles are written by an administrator, and an
// administrator who can elevate anybody is the expected behaviour.
func TestSelfWriteLeavesTheCounterCaseAlone(t *testing.T) {
	reads, shape, model := analyzeFixture(t)

	findings, err := SelfWrite(reads, shape, model)
	if err != nil {
		t.Fatalf("SelfWrite() error = %v", err)
	}
	for _, finding := range findings {
		if finding.Path == "data.users[_].roles" {
			t.Errorf("the counter case was reported: %s", finding)
		}
	}

	// And the signals really do hold for it, so the silence comes from the
	// write model and not from having missed the read.
	var subjectIndexed bool
	for _, read := range reads.Reads {
		if read.Path == "data.users[_].roles" && signalsHold(read, shape) {
			subjectIndexed = true
		}
	}
	if !subjectIndexed {
		t.Error("the counter case does not even reach signal 4, so this test proves nothing")
	}
}

// Without a write model the policy side still holds, and saying "finding"
// would be claiming something nobody declared. A candidate is a question with
// a place to look for the answer.
func TestSelfWriteWithoutAModelEmitsCandidates(t *testing.T) {
	reads, shape, _ := analyzeFixture(t)

	findings, err := SelfWrite(reads, shape, nil)
	if err != nil {
		t.Fatalf("SelfWrite() error = %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("no candidates: the first three signals hold with or without a model")
	}
	for _, finding := range findings {
		if finding.Verdict != VerdictCandidate {
			t.Errorf("%s is a %s, want a candidate", finding.Path, finding.Verdict)
		}
		if finding.ViaWritePath != "" {
			t.Errorf("%s claims a write path with no model: %q", finding.Path, finding.ViaWritePath)
		}
	}
}

// The numbers EXPECTED.md declares for the fixture, measured rather than
// stated: nine paths read, four covered, five not. The design keeps it low on
// purpose, because a fixture that declares full coverage would teach the engine
// to run only on complete models, which do not exist in practice.
func TestCoverageOnFixture(t *testing.T) {
	reads, _, model := analyzeFixture(t)

	coverage, err := CoverageOf(reads, model)
	if err != nil {
		t.Fatalf("CoverageOf() error = %v", err)
	}

	if len(coverage.Read) != 9 || len(coverage.Covered) != 4 || len(coverage.Uncovered) != 5 {
		t.Fatalf("coverage = %d read, %d covered, %d uncovered, want 9, 4, 5",
			len(coverage.Read), len(coverage.Covered), len(coverage.Uncovered))
	}
	if coverage.Percent() != 44 {
		t.Errorf("percent = %d, want 44", coverage.Percent())
	}

	expectedCovered := []string{
		"data.projects[_].members",
		"data.tenants[_].policy.require_mfa",
		"data.users[_].profile.department",
		"data.users[_].roles",
	}
	if !slices.Equal(coverage.Covered, expectedCovered) {
		t.Errorf("covered = %v, want %v", coverage.Covered, expectedCovered)
	}
}

func TestLoadRegistry(t *testing.T) {
	patterns, err := LoadRegistry(filepath.Join("..", "..", "taxonomy-registry", "opa"))
	if err != nil {
		t.Fatalf("LoadRegistry() error = %v", err)
	}
	if len(patterns) != 5 {
		t.Errorf("patterns = %d, want the five of the registry", len(patterns))
	}

	pattern, ok := Find(patterns, AttrSelfWrite)
	if !ok {
		t.Fatalf("%s is not in the registry", AttrSelfWrite)
	}
	if pattern.Category.ID != "ATTR-SELF-WRITE" {
		t.Errorf("category = %q, want ATTR-SELF-WRITE", pattern.Category.ID)
	}
	if !pattern.Detection.RequiresWriteModel {
		t.Error("the pattern does not declare requires_write_model, but the fourth signal is the write model")
	}
	if pattern.Graph.Emits != "finding" {
		t.Errorf("emits = %q, want finding", pattern.Graph.Emits)
	}
}
