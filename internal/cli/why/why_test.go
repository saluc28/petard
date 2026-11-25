package why

import (
	"bytes"
	"strings"
	"testing"

	"github.com/saluc28/petard/internal/cli/render"
	"github.com/saluc28/petard/internal/cli/zanzibarsetup"
	"github.com/saluc28/petard/internal/taxonomy"
	"github.com/saluc28/petard/internal/zanzibar"
)

// why lays out the finding named under the paths: the writes in order, where
// each relation is declared, the decisive write, and how to have the product
// confirm it. It is the witness the engine already produced, not a second
// derivation, so what it shows is a line in the schema a reader can check.
func TestWhyLaysOutTheChain(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"ptd-zan-007-document-edit", "testdata"}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{
		"PTD-ZAN-007  document#edit  written in behind a permission the coalition held",
		"A weaker permission gates writing a stronger one into the object",
		"raises edit on document, from no to yes",
		"write document:target#editor@user:attacker",
		"decisive",
		"whoever holds view, through POST /editors",
		"declared at testdata/schema.zed:5:3",
		"Have SpiceDB confirm it",
		"petard analyze -proofs <dir> testdata",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("why does not say %q:\n%s", want, out)
		}
	}
}

// A finding is named by its pattern id, by the slug a report gives it, or by the
// pattern name, and a name that matches nothing is told apart from a run that
// found nothing.
func TestWhySelects(t *testing.T) {
	for _, tt := range []struct {
		name   string
		wanted string
		code   int
		shows  string
	}{
		{"by pattern id", "PTD-ZAN-007", exitOK, "document#edit"},
		{"by slug", "ptd-zan-007-document-edit", exitOK, "document#edit"},
		{"case does not matter", "ptd-zan-007", exitOK, "document#edit"},
		{"no such finding", "PTD-ZAN-001", exitUsage, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Run([]string{tt.wanted, "testdata"}, &stdout, &stderr)
			if code != tt.code {
				t.Fatalf("exit code = %d, want %d (stderr: %s)", code, tt.code, stderr.String())
			}
			if tt.shows != "" && !strings.Contains(stdout.String(), tt.shows) {
				t.Errorf("output does not show %q:\n%s", tt.shows, stdout.String())
			}
		})
	}
}

// A finding and a path are both needed: the command explains one finding, and it
// has to read the schema to find it.
func TestWhyNeedsAFindingAndAPath(t *testing.T) {
	for _, args := range [][]string{nil, {"PTD-ZAN-007"}} {
		var stdout, stderr bytes.Buffer
		if code := Run(args, &stdout, &stderr); code != exitUsage {
			t.Errorf("Run(%q) = %d, want %d", args, code, exitUsage)
		}
	}
}

// The count of writes reads as a count, so a single write is not "1 writes".
func TestReaches(t *testing.T) {
	for _, tt := range []struct {
		n    int
		want string
	}{
		{1, "The coalition reaches it in a single write"},
		{2, "The coalition reaches it in 2 writes"},
	} {
		if got := reaches(tt.n); got != tt.want {
			t.Errorf("reaches(%d) = %q, want %q", tt.n, got, tt.want)
		}
	}
}

// A finding names the schema it is in only when the findings span more than one,
// so a single-schema run does not repeat a path the reader already gave.
func TestPrintWhyNamesTheSchemaOnlyWhenAsked(t *testing.T) {
	e := escalation{
		schema:  "a/schema.zed",
		product: zanzibarsetup.SpiceDB,
		match: zanzibar.Match{
			PatternID: "PTD-ZAN-007",
			Raise: &zanzibar.Raise{
				Type: "document", Permission: "edit", Kind: "written in behind a permission the coalition held",
				Before: zanzibar.No, After: zanzibar.Yes,
				Witness: []zanzibar.WitnessStep{{Verb: "write", Tuple: "document:d#editor@user:x", Who: "whoever holds view", Decisive: true}},
				Proof:   &zanzibar.Proof{},
			},
		},
	}
	for _, tt := range []struct {
		name       string
		nameSchema bool
		names      bool
	}{
		{"spans more than one schema", true, true},
		{"one schema", false, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			printWhy(&buf, e, tt.nameSchema, []string{"a"}, nil, render.Style{})
			if got := strings.Contains(buf.String(), "in a/schema.zed"); got != tt.names {
				t.Errorf("names the schema = %v, want %v:\n%s", got, tt.names, buf.String())
			}
		})
	}
}

// selects matches a finding by its id, its slug or its pattern name, in any
// case, and by nothing else.
func TestSelects(t *testing.T) {
	e := escalation{match: zanzibar.Match{
		PatternID: "PTD-ZAN-007",
		Raise:     &zanzibar.Raise{Type: "document", Permission: "edit"},
	}}
	patterns := []taxonomy.Pattern{{ID: "PTD-ZAN-007", Name: "split-grant"}}
	for _, tt := range []struct {
		wanted string
		want   bool
	}{
		{"PTD-ZAN-007", true},
		{"ptd-zan-007", true},
		{"ptd-zan-007-document-edit", true},
		{"split-grant", true},
		{"SPLIT-GRANT", true},
		{"PTD-ZAN-008", false},
		{"ptd-zan-007-document-view", false},
	} {
		if got := e.selects(tt.wanted, patterns); got != tt.want {
			t.Errorf("selects(%q) = %v, want %v", tt.wanted, got, tt.want)
		}
	}
}

// The replay block names the product's own checker, and when petard cannot
// write a proof it says so instead of pointing at one.
func TestPrintReplay(t *testing.T) {
	for _, tt := range []struct {
		name   string
		esc    escalation
		want   []string
		absent string
	}{
		{
			name: "SpiceDB names zed validate",
			esc:  escalation{product: zanzibarsetup.SpiceDB, match: zanzibar.Match{Raise: &zanzibar.Raise{Type: "document", Permission: "edit", Proof: &zanzibar.Proof{}}}},
			want: []string{"Have SpiceDB confirm it", "zed validate", "petard analyze -proofs <dir> testdata"},
		},
		{
			name: "OpenFGA names fga model test",
			esc:  escalation{product: zanzibarsetup.OpenFGA, match: zanzibar.Match{Raise: &zanzibar.Raise{Type: "document", Permission: "edit", Proof: &zanzibar.Proof{}}}},
			want: []string{"Have OpenFGA confirm it", "fga model test"},
		},
		{
			name:   "no proof says so",
			esc:    escalation{product: zanzibarsetup.SpiceDB, match: zanzibar.Match{Raise: &zanzibar.Raise{Type: "document", Permission: "edit", NoProof: "the schema leaves no before state"}}},
			want:   []string{"petard cannot write a replayable proof for this one: the schema leaves no before state"},
			absent: "petard analyze -proofs",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			printReplay(&buf, tt.esc, []string{"testdata"})
			out := buf.String()
			for _, want := range tt.want {
				if !strings.Contains(out, want) {
					t.Errorf("replay does not say %q:\n%s", want, out)
				}
			}
			if tt.absent != "" && strings.Contains(out, tt.absent) {
				t.Errorf("replay should not say %q:\n%s", tt.absent, out)
			}
		})
	}
}
