package taxonomy

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/saluc28/petard/internal/opaengine"
)

// The case of PTD-OPA-008 on the fixture: the reading room is open to whoever
// asks while one setting says so, and the settings come from a configuration
// repository. The claim comes out of evaluating the decision for somebody no
// document names, not out of a ReadSet written to produce it.
func TestGlobalSwitchOnFixture(t *testing.T) {
	findings, err := GlobalSwitch(t.Context(), fixtureAnalysis(t))
	if err != nil {
		t.Fatalf("GlobalSwitch() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want the reading room alone:\n%v", len(findings), findings)
	}

	f := findings[0]
	if f.PatternID != GlobalDocumentDecides || f.Verdict != VerdictFinding {
		t.Errorf("%s %s, want a finding of %s", f.PatternID, f.Verdict, GlobalDocumentDecides)
	}
	if f.Path != "data.settings.reading_room.open" || f.Decision != "data.quill.platform.allow_reading_room" {
		t.Errorf("finding on %s for %s, want the reading room setting and its decision", f.Path, f.Decision)
	}
	if f.ViaWritePath != "data.settings.*" || f.Via != "configuration repository, synced on merge" {
		t.Errorf("written at %q via %q, want the settings entry of the model", f.ViaWritePath, f.Via)
	}
	for _, said := range []string{"for a principal no document names", "today it grants them nothing", "system:config-sync writes it"} {
		if !strings.Contains(f.Summary, said) {
			t.Errorf("the summary does not say %q: %s", said, f.Summary)
		}
	}
	if f.Subject != "input.user" || f.Confidence != "D" {
		t.Errorf("subject = %q at %q, want input.user at D", f.Subject, f.Confidence)
	}
	if len(f.Reads) != 1 {
		t.Errorf("places to look = %d, want the one line that reads the setting", len(f.Reads))
	}
}

// The console setting is read the same way, a path with no dynamic segment, and
// the pattern stays quiet about it because it only decides for somebody with a
// record. The first half checks that the read is there at all, since otherwise
// the silence would only prove the walk missed it.
func TestGlobalSwitchLeavesTheConsoleAlone(t *testing.T) {
	a := fixtureAnalysis(t)

	static := slices.ContainsFunc(a.Reads.Reads, func(read opaengine.Read) bool {
		return read.Path == "data.settings.console.enabled" && read.Provenance == opaengine.ProvenanceStatic
	})
	if !static {
		t.Fatal("the console setting is not a static read, so this test proves nothing")
	}

	findings, err := GlobalSwitch(t.Context(), a)
	if err != nil {
		t.Fatalf("GlobalSwitch() error = %v", err)
	}
	for _, f := range findings {
		if f.Path == "data.settings.console.enabled" {
			t.Errorf("the counter case was reported: %s", f)
		}
	}
}

// Without the write model the first two signals still hold, and the reading
// room comes out as a candidate: nobody said who writes it.
func TestGlobalSwitchWithoutAModelEmitsACandidate(t *testing.T) {
	a := fixtureAnalysis(t)
	a.Model = nil

	findings, err := GlobalSwitch(t.Context(), a)
	if err != nil {
		t.Fatalf("GlobalSwitch() error = %v", err)
	}
	if len(findings) != 1 || findings[0].Verdict != VerdictCandidate || findings[0].ViaWritePath != "" {
		t.Errorf("findings = %v, want one candidate on the reading room with no write path", findings)
	}
}

// A world is closed: a document the model does not cover is one nobody writes,
// and a switch nobody can reach is left alone.
func TestGlobalSwitchLeavesWhatNobodyWrites(t *testing.T) {
	a := analysisOf(t, &FalsePositiveCase{
		Policy: `package room

# METADATA
# scope: document
# title: Reading room decision
# entrypoint: true
default allow := false

allow if {
	input.user != ""
	data.settings.reading_room.open == true
}
`,
		Data: `{"settings": {"reading_room": {"open": false}}}`,
		WriteModel: `schema_version: 1
model: write-paths
entries:
  - path: data.users.{owner}.name
    writable_by:
      - principal: "{owner}"
        via: "PATCH /api/v1/me"
`,
	})

	findings, err := GlobalSwitch(t.Context(), a)
	if err != nil {
		t.Fatalf("GlobalSwitch() error = %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("findings = %v, want none: the model says nobody writes the setting", findings)
	}
}

// A decision that never looks at who is asking decides for anybody by
// construction, and with no subject to name the pattern asks about any request
// and says so, at the confidence of a shape that recognized nothing.
func TestGlobalSwitchAsksAnyRequestWithoutASubject(t *testing.T) {
	a := analysisOf(t, &FalsePositiveCase{
		Policy: `package maintenance

# METADATA
# scope: document
# title: Decision during maintenance
# entrypoint: true
default allow := false

allow if data.settings.maintenance.open == true
`,
		Data: `{"settings": {"maintenance": {"open": true}}}`,
	})
	if a.Shape.Subject != "" {
		t.Fatalf("subject = %q, want none recognized", a.Shape.Subject)
	}

	findings, err := GlobalSwitch(t.Context(), a)
	if err != nil {
		t.Fatalf("GlobalSwitch() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %v, want one candidate on the maintenance switch", findings)
	}
	if findings[0].Verdict != VerdictCandidate {
		t.Errorf("verdict = %s, want a candidate: no write model was given", findings[0].Verdict)
	}
	if !strings.Contains(findings[0].Summary, "for any request") || findings[0].Confidence != "E" {
		t.Errorf("finding = %s at %q, want any request at E", findings[0].Summary, findings[0].Confidence)
	}
}

func TestGlobalSwitchNeedsData(t *testing.T) {
	a := fixtureAnalysis(t)
	a.Data = nil

	if _, err := GlobalSwitch(t.Context(), a); !errors.Is(err, ErrNeedsData) {
		t.Errorf("GlobalSwitch() error = %v, want ErrNeedsData", err)
	}
}

// The sentence a finding carries is read by a person, and one way is one way.
func TestDescribeTodayCountsTheWays(t *testing.T) {
	tests := []struct {
		granted  reach
		expected string
	}{
		{reach{}, "today it grants them nothing"},
		{reach{ways: 1}, "today it grants them in 1 way"},
		{reach{ways: 3}, "today it grants them in 3 ways"},
		{reach{always: true}, "today it grants them whatever they ask"},
	}
	for _, tt := range tests {
		if got := describeToday(tt.granted); got != tt.expected {
			t.Errorf("describeToday(%+v) = %q, want %q", tt.granted, got, tt.expected)
		}
	}
}
