package taxonomy

import (
	"path/filepath"
	"slices"
	"testing"
	"testing/fstest"

	"github.com/saluc28/petard/internal/opaengine"
	"github.com/saluc28/petard/internal/writemodel"
	registry "github.com/saluc28/petard/taxonomy-registry"
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
// report both, which is the systematic false positive the registry declares.
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

// data.users[_].roles is read by a decision and indexed by the subject: the
// first two signals hold exactly as they do for the case. It is not a finding
// because roles are written by an administrator, and an administrator who can
// elevate anybody is the expected behaviour.
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
		t.Error("the counter case does not even reach signal 3, so this test proves nothing")
	}
}

// A field the subject writes decides about them on either side of the
// decision. A suspension read under not is one the subject can clear, and it
// is reported exactly like a department read to grant.
func TestSelfWriteReportsAFieldReadUnderNot(t *testing.T) {
	a := analysisOf(t, &FalsePositiveCase{
		Policy: `package suspension

# METADATA
# scope: document
# title: Decision that refuses suspended requesters
# entrypoint: true
default allow := false

allow if {
	input.action == "read"
	not data.users[input.user].suspended
}
`,
		WriteModel: `schema_version: 1
model: write-paths
entries:
  - path: data.users.{owner}.suspended
    writable_by:
      - principal: "{owner}"
        via: "PATCH /api/v1/me"
`,
	})

	negated := slices.ContainsFunc(a.Reads.Reads, func(read opaengine.Read) bool {
		return read.Path == "data.users[_].suspended" && read.UnderNegation
	})
	if !negated {
		t.Fatal("the suspension is not read under a negation, so this test proves nothing")
	}

	findings, err := SelfWrite(a.Reads, a.Shape, a.Model)
	if err != nil {
		t.Fatalf("SelfWrite() error = %v", err)
	}
	if len(findings) != 1 || findings[0].Path != "data.users[_].suspended" || findings[0].Verdict != VerdictFinding {
		t.Errorf("findings = %v, want one finding on data.users[_].suspended", findings)
	}
}

// joinPolicy grants to the members of a team, which the policy finds by
// searching the members for whoever is asking.
const joinPolicy = `package membership

# METADATA
# scope: document
# title: Decision on the members of a team
# entrypoint: true
default allow := false

allow if {
	input.action == "read"
	input.user in data.teams[input.team].members
}
`

// Joining a list the policy searches is the self write of a lookup by value:
// the model says each member writes their own element, so anybody can add
// themselves. An entry that only names the list, written by an administrator,
// says nothing about joining and leaves the pattern quiet.
func TestSelfWriteFindsAJoin(t *testing.T) {
	tests := []struct {
		name       string
		writeModel string
		reports    bool
	}{
		{
			name: "each member writes their own element",
			writeModel: `schema_version: 1
model: write-paths
entries:
  - path: data.teams.{team}.members.{member}
    writable_by:
      - principal: "{member}"
        via: "POST /api/v1/teams/{team}/join"
`,
			reports: true,
		},
		{
			name: "an administrator writes the list",
			writeModel: `schema_version: 1
model: write-paths
entries:
  - path: data.teams.{team}.members
    writable_by:
      - principal: role:team-admin
        via: "PUT /api/v1/teams/{team}/members"
`,
			reports: false,
		},
		{
			// The capture names an element, but the element is the team.
			name: "a capture on another segment",
			writeModel: `schema_version: 1
model: write-paths
entries:
  - path: data.teams.{team}.members.{member}
    writable_by:
      - principal: "{team}"
        via: "a team service account"
`,
			reports: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := analysisOf(t, &FalsePositiveCase{Policy: joinPolicy, WriteModel: tt.writeModel})

			findings, err := SelfWrite(a.Reads, a.Shape, a.Model)
			if err != nil {
				t.Fatalf("SelfWrite() error = %v", err)
			}
			if !tt.reports {
				if len(findings) != 0 {
					t.Errorf("findings = %v, want none", findings)
				}
				return
			}
			if len(findings) != 1 {
				t.Fatalf("findings = %v, want one on the members", findings)
			}
			finding := findings[0]
			if finding.Verdict != VerdictFinding || finding.Path != "data.teams[_].members" {
				t.Errorf("finding = %s on %s, want a finding on data.teams[_].members", finding.Verdict, finding.Path)
			}
			if finding.SubjectElement != 4 || finding.SubjectPosition != 0 {
				t.Errorf("element = %d and position = %d, want 4 and 0: the subject is an element, not a key",
					finding.SubjectElement, finding.SubjectPosition)
			}
			if finding.ViaWritePath != "data.teams.{team}.members.{member}" {
				t.Errorf("via write path = %q", finding.ViaWritePath)
			}
		})
	}
}

// Chef Automate asks about a list of subjects, compares each with every member
// of every policy inside a function, and keeps no collection of users at all.
func TestSelfWriteOnAListOfSubjects(t *testing.T) {
	a := analysisOf(t, &FalsePositiveCase{
		Policy: `package authz

# METADATA
# scope: document
# title: Projects the subjects are authorized on
# entrypoint: true
authorized_project contains project if {
	has_member[policy]
	some project in data.policies[policy].projects
}

has_member contains policy if {
	member := data.policies[policy].members[_]
	subject := input.subjects[_]
	subject_matches(subject, member)
}

subject_matches(value, stored) if value == stored
`,
		WriteModel: `schema_version: 1
model: write-paths
entries:
  - path: data.policies.{policy}.members.{member}
    writable_by:
      - principal: "{member}"
        via: "POST /apis/iam/v2/policies/{id}/members:add"
`,
	})

	if a.Shape.Subject != "input.subjects[_]" {
		t.Fatalf("subject = %q, want input.subjects[_]", a.Shape.Subject)
	}
	findings, err := SelfWrite(a.Reads, a.Shape, a.Model)
	if err != nil {
		t.Fatalf("SelfWrite() error = %v", err)
	}
	if len(findings) != 1 || findings[0].Path != "data.policies[_].members[_]" || findings[0].Verdict != VerdictFinding {
		t.Fatalf("findings = %v, want one finding on data.policies[_].members[_]", findings)
	}
	if findings[0].SubjectElement != 4 {
		t.Errorf("element = %d, want 4", findings[0].SubjectElement)
	}
}

// A capture stands for the subject only where the subject stands. A read
// indexed by the requester and by the document they ask for has two captures,
// and the model naming the second one says the document writes it.
func TestSelfWriteHoldsTheCaptureToTheSubject(t *testing.T) {
	policy := `package pins

# METADATA
# scope: document
# title: Decision on pinned documents
# entrypoint: true
default allow := false

allow if data.workspaces[input.user].documents[input.doc].pinned == true
`
	for _, tt := range []struct {
		capture string
		reports bool
	}{
		{capture: "{owner}", reports: true},
		{capture: "{document}", reports: false},
	} {
		t.Run(tt.capture, func(t *testing.T) {
			a := analysisOf(t, &FalsePositiveCase{
				Policy: policy,
				WriteModel: `schema_version: 1
model: write-paths
entries:
  - path: data.workspaces.{owner}.documents.{document}.pinned
    writable_by:
      - principal: "` + tt.capture + `"
        via: "PATCH /api/v1/documents/{document}"
`,
			})
			findings, err := SelfWrite(a.Reads, a.Shape, a.Model)
			if err != nil {
				t.Fatalf("SelfWrite() error = %v", err)
			}
			if reported := len(findings) > 0; reported != tt.reports {
				t.Errorf("findings = %v, want reported %v", findings, tt.reports)
			}
		})
	}
}

// The chain writes a document of the subject's own, and a list the subject
// joins is not one: the finding stays out of it rather than being turned into
// a path the data never had.
func TestTheChainLeavesAJoinAlone(t *testing.T) {
	joined := Finding{PatternID: AttrSelfWrite, Verdict: VerdictFinding, Path: "data.teams[_].members", SubjectElement: 4}
	owned := Finding{PatternID: AttrSelfWrite, Verdict: VerdictFinding, Path: "data.users[_].tier", SubjectPosition: 2}

	writable := writablePaths([]Finding{joined, owned})
	if len(writable) != 1 || writable[0].Path != owned.Path {
		t.Errorf("writablePaths() = %v, want only %s", writable, owned.Path)
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
	var paths []string
	for _, finding := range findings {
		paths = append(paths, finding.Path)
	}
	slices.Sort(paths)
	// The members of a project are a candidate too: the policy searches them
	// for the requester, and who can add a member is what the model would say.
	expected := []string{"data.projects[_].members", "data.users[_].profile.department", "data.users[_].roles"}
	if !slices.Equal(paths, expected) {
		t.Fatalf("candidates = %v, want %v", paths, expected)
	}
	for _, finding := range findings {
		if element := finding.SubjectElement; (finding.Path == "data.projects[_].members") != (element == 4) {
			t.Errorf("%s has the subject as element %d", finding.Path, element)
		}
		if finding.Verdict != VerdictCandidate {
			t.Errorf("%s is a %s, want a candidate", finding.Path, finding.Verdict)
		}
		if finding.ViaWritePath != "" {
			t.Errorf("%s claims a write path with no model: %q", finding.Path, finding.ViaWritePath)
		}
	}
}

// The numbers EXPECTED.md declares for the fixture, measured rather than
// stated: eleven paths read, six covered, five not. The design keeps it low on
// purpose, because a fixture that declares full coverage would teach the engine
// to run only on complete models, which do not exist in practice.
func TestCoverageOnFixture(t *testing.T) {
	reads, _, model := analyzeFixture(t)

	coverage, err := CoverageOf(reads, model)
	if err != nil {
		t.Fatalf("CoverageOf() error = %v", err)
	}

	if len(coverage.Read) != 11 || len(coverage.Covered) != 6 || len(coverage.Uncovered) != 5 {
		t.Fatalf("coverage = %d read, %d covered, %d uncovered, want 11, 6, 5",
			len(coverage.Read), len(coverage.Covered), len(coverage.Uncovered))
	}
	if coverage.Percent() != 54 {
		t.Errorf("percent = %d, want 54", coverage.Percent())
	}

	expectedCovered := []string{
		"data.projects[_].members",
		"data.settings.console.enabled",
		"data.settings.reading_room.open",
		"data.tenants[_].policy.require_mfa",
		"data.users[_].profile.department",
		"data.users[_].roles",
	}
	if !slices.Equal(coverage.Covered, expectedCovered) {
		t.Errorf("covered = %v, want %v", coverage.Covered, expectedCovered)
	}
}

func TestLoadRegistry(t *testing.T) {
	patterns, err := LoadRegistry(registry.OPA)
	if err != nil {
		t.Fatalf("LoadRegistry() error = %v", err)
	}
	if len(patterns) != 9 {
		t.Errorf("patterns = %d, want the nine of the registry", len(patterns))
	}

	pattern, ok := Find(patterns, AttrSelfWrite)
	if !ok {
		t.Fatalf("%s is not in the registry", AttrSelfWrite)
	}
	if pattern.Category.ID != "ATTR-SELF-WRITE" {
		t.Errorf("category = %q, want ATTR-SELF-WRITE", pattern.Category.ID)
	}
	if !pattern.Detection.RequiresWriteModel {
		t.Error("the pattern does not declare requires_write_model, but the third signal is the write model")
	}
	if pattern.Graph.Emits != "finding" {
		t.Errorf("emits = %q, want finding", pattern.Graph.Emits)
	}
}

// A registry with nothing in it has to be an error rather than a list of no
// patterns. The empty list reaches a report as findings filed under bare ids,
// with the titles gone and nothing saying they were ever expected.
func TestLoadRegistryRefusesAFilesystemWithNoPatterns(t *testing.T) {
	_, err := LoadRegistry(fstest.MapFS{"README.md": {Data: []byte("not a pattern")}})
	if err == nil {
		t.Fatal("LoadRegistry() on a filesystem with no pattern files returned no error")
	}
}
