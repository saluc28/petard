package zanzibar

import (
	"strings"
	"testing"
	"time"
)

// aspectModel has an editor relation that carries an expiration, a viewer that
// does not, a public relation whose wildcard subject carries one, and a mixed
// relation where only the userset subject does.
func aspectModel(t *testing.T) *Model {
	t.Helper()
	types := []*Type{
		{Name: "user"},
		{Name: "group", Relations: []*Relation{{Name: "member", Allowed: []Allowed{{Type: "user"}}}}},
		{
			Name: "doc",
			Relations: []*Relation{
				{Name: "editor", Allowed: []Allowed{{Type: "user", Expiration: true}}},
				{Name: "viewer", Allowed: []Allowed{{Type: "user"}}},
				{Name: "pub", Allowed: []Allowed{{Type: "user", Wildcard: true, Expiration: true}}},
				{Name: "mixed", Allowed: []Allowed{{Type: "user"}, {Type: "group", Relation: "member", Expiration: true}}},
			},
			Permissions: []*Permission{{Name: "edit", Expr: Computed{Name: "editor"}}},
		},
	}
	m, err := NewModel(types, nil)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func docStep(relation string, subj Subject, rule *WriteRule) WriteStep {
	return WriteStep{Relationship: Relationship{Resource: Object{Type: "doc", ID: "d"}, Relation: relation, Subject: subj}, Rule: rule}
}

func TestDefeatsExpiry(t *testing.T) {
	model := aspectModel(t)
	user := Subject{Object: Object{Type: "user", ID: "a"}}
	rule := func(relation string, f Filler) *WriteRule {
		return &WriteRule{Resource: "doc", Relation: relation, Expiration: f}
	}
	cases := []struct {
		name string
		step WriteStep
		want bool
	}{
		{"expiring, writer fills", docStep("editor", user, rule("editor", FillerWriter)), true},
		{"expiring, no expiration carried", docStep("editor", user, rule("editor", FillerNone)), true},
		{"expiring, filler left default", docStep("editor", user, rule("editor", "")), true},
		{"expiring, application fills", docStep("editor", user, rule("editor", FillerApplication)), false},
		{"relation carries no expiration", docStep("viewer", user, rule("viewer", FillerWriter)), false},
		{"wildcard subject carries one", docStep("pub", Subject{Object: Object{Type: "user", ID: WildcardID}}, rule("pub", FillerWriter)), true},
		{"userset subject carries one", docStep("mixed", Subject{Object: Object{Type: "group", ID: "g"}, Relation: "member"}, rule("mixed", FillerWriter)), true},
		{"other subject kind on a mixed relation", docStep("mixed", user, rule("mixed", FillerWriter)), false},
		{"creation step has no rule", WriteStep{Relationship: Relationship{Resource: Object{Type: "doc", ID: "d"}, Relation: "editor", Subject: user}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := defeatsExpiry(model, tc.step); got != tc.want {
				t.Errorf("defeatsExpiry = %v, want %v", got, tc.want)
			}
		})
	}
}

// The aspect reaches a classified escalation: a coalition that writes an
// expiring relation it controls the expiration of carries DefeatsExpiry, and one
// whose expiration the application fills does not.
func TestClassifyMarksDefeatsExpiry(t *testing.T) {
	model := aspectModel(t)
	start := []Relationship{{Resource: Object{Type: "doc", ID: "d"}, Relation: "editor", Subject: Subject{Object: Object{Type: "user", ID: "seed"}}}}
	attacker := Object{Type: "user", ID: "attacker"}
	opts := Options{Now: time.Unix(0, 0)}

	for _, tc := range []struct {
		name string
		exp  Filler
		want bool
	}{
		{"writer sets the expiration", FillerWriter, true},
		{"application sets the expiration", FillerApplication, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wm := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: []*WriteRule{
				{Resource: "doc", Relation: "editor", Operations: []Operation{Create, Touch}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Self: true}, Expiration: tc.exp},
			}}
			classified, err := classifyScoped(model, wm, stubCaveats{}, start, []Object{attacker}, nil, opts)
			if err != nil {
				t.Fatalf("classifyScoped: %v", err)
			}
			var edit *ClassifiedEscalation
			for i := range classified {
				if classified[i].Permission == "edit" {
					edit = &classified[i]
				}
			}
			if edit == nil {
				t.Fatalf("no edit escalation found; got %d classified", len(classified))
			}
			if edit.DefeatsExpiry != tc.want {
				t.Errorf("edit escalation DefeatsExpiry = %v, want %v", edit.DefeatsExpiry, tc.want)
			}
			// The aspect reaches the report as a non-verbose annotation shown in
			// the summary, present exactly when the raise defeats a time bound.
			found := false
			for _, d := range escalationMatch("PTD-ZAN-003", *edit).Details {
				if strings.Contains(d.Text, "defeats a time bound") {
					found = true
					if d.Verbose {
						t.Error("the expiry annotation should show in the summary, not only under -v")
					}
				}
			}
			if found != tc.want {
				t.Errorf("expiry annotation in the report = %v, want %v", found, tc.want)
			}
		})
	}
}
