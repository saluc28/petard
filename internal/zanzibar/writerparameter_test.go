package zanzibar

import (
	"strings"
	"testing"
	"time"
)

// networked is a model of documents whose viewers may be held to a network:
// the caveat reads an address and a zone, and insideOnly evaluates it on the
// address alone.
func networked(t *testing.T) *Model {
	t.Helper()

	doc := &Type{
		Name:      "doc",
		Relations: []*Relation{{Name: "viewer", Allowed: []Allowed{{Type: "user"}, {Type: "user", Caveat: "network"}}}},
		Permissions: []*Permission{{
			Name: "view",
			Expr: Computed{Name: "viewer"},
		}},
	}
	m, err := NewModel([]*Type{{Name: "user"}, doc}, []*Caveat{{
		Name:       "network",
		Parameters: []Parameter{{Name: "address", Type: "string"}, {Name: "zone", Type: "string"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func viewerWith(context map[string]any) Relationship {
	return Relationship{
		Resource: Object{Type: "doc", ID: "a"},
		Relation: "viewer",
		Subject:  user("vic"),
		Caveat:   &CaveatUse{Name: "network", Context: context},
	}
}

func viewCheck(context map[string]any, level Level) Assertion {
	return Assertion{Resource: Object{Type: "doc", ID: "a"}, Name: "view", Subject: user("vic"), Context: context, Level: level}
}

func detail(m Match, label string) string {
	for _, d := range m.Details {
		if d.Label == label {
			return d.Text
		}
	}
	return ""
}

// The address is what the checks supply and the zone is what every
// relationship writes: the address is reported, with the check it lets
// through once written, and the zone is not.
func TestWriterSetParametersFindsWhatTheCheckSupplies(t *testing.T) {
	matches := WriterSetParameters(Sample{
		Model:         networked(t),
		Relationships: []Relationship{viewerWith(map[string]any{"zone": "office"})},
		Assertions: []Assertion{
			viewCheck(map[string]any{"address": "outside"}, No),
			viewCheck(map[string]any{"address": "inside"}, Yes),
		},
		Caveats: insideOnly{},
		Now:     time.Now(),
	})
	if len(matches) != 1 {
		t.Fatalf("matches = %+v, want one, on the address", matches)
	}
	m := matches[0]
	if m.PatternID != WriterSetParameterID || m.Verdict != Candidate || m.Subject != "doc#viewer, address of caveat network" {
		t.Errorf("match = %+v", m)
	}
	if got := detail(m, "supplied by"); !strings.HasPrefix(got, "2 checks of the file, the first at") {
		t.Errorf("supplied by = %q", got)
	}
	shown := detail(m, "shown by")
	for _, want := range []string{`doc:a#view@user:vic with {"address":"outside"}`, "goes from no to yes", `{"address":"inside","zone":"office"}`} {
		if !strings.Contains(shown, want) {
			t.Errorf("shown by = %q, want it to say %q", shown, want)
		}
	}
}

// With no check in the file, relationships that leave the parameter out are
// the evidence, and the match says no check shows it.
func TestWriterSetParametersReadsWhatRelationshipsLeaveOut(t *testing.T) {
	matches := WriterSetParameters(Sample{
		Model:         networked(t),
		Relationships: []Relationship{viewerWith(map[string]any{"zone": "office"})},
		Caveats:       insideOnly{},
		Now:           time.Now(),
	})
	if len(matches) != 1 {
		t.Fatalf("matches = %+v, want one, on the address", matches)
	}
	if got := detail(matches[0], "left by"); !strings.HasPrefix(got, "1 relationship of the relation, which leave it to the check") {
		t.Errorf("left by = %q", got)
	}
	if got := detail(matches[0], "shown by"); !strings.HasPrefix(got, "no check of the file") {
		t.Errorf("shown by = %q", got)
	}
}

// A sample that says nothing about where a parameter comes from leaves it
// alone, and so does one where every relationship writes it.
func TestWriterSetParametersLeavesAloneWhatNothingSays(t *testing.T) {
	tests := []struct {
		name          string
		relationships []Relationship
	}{
		{name: "no relationship and no check"},
		{name: "every relationship writes both", relationships: []Relationship{viewerWith(map[string]any{"address": "inside", "zone": "office"})}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := WriterSetParameters(Sample{Model: networked(t), Relationships: tt.relationships, Caveats: insideOnly{}, Now: time.Now()})
			if len(matches) != 0 {
				t.Errorf("matches = %+v, want none", matches)
			}
		})
	}
}

// A parameter the checks supply and some relationships write already is still
// reported, and the match says how many write it.
func TestWriterSetParametersCountsWhatIsWrittenAlready(t *testing.T) {
	written := viewerWith(map[string]any{"address": "inside"})
	written.Subject = user("svc")
	matches := WriterSetParameters(Sample{
		Model:         networked(t),
		Relationships: []Relationship{viewerWith(nil), written},
		Assertions:    []Assertion{viewCheck(map[string]any{"address": "outside"}, No)},
		Caveats:       insideOnly{},
		Now:           time.Now(),
	})
	var address *Match
	for i := range matches {
		if strings.HasPrefix(matches[i].Subject, "doc#viewer, address") {
			address = &matches[i]
		}
	}
	if address == nil {
		t.Fatalf("matches = %+v, want one on the address", matches)
	}
	if got := detail(*address, "written by"); got != "1 relationship of the relation already" {
		t.Errorf("written by = %q", got)
	}
}
