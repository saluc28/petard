package zanzibar

import (
	"slices"
	"testing"
	"time"
)

// A subject that happens to be called attacker is a real subject, and the attacker the
// analysis supposes takes another name rather than what that subject holds.
func TestASupposedObjectTakesANameNobodyUses(t *testing.T) {
	tests := []struct {
		name          string
		relationships []Relationship
		expected      string
	}{
		{name: "nobody uses it", expected: "attacker"},
		{
			name:          "another type uses it",
			relationships: []Relationship{rel("document:attacker", "viewer", "user:vic")},
			expected:      "attacker",
		},
		{
			name:          "a subject uses it",
			relationships: []Relationship{rel("document:roadmap", "viewer", "user:attacker")},
			expected:      "attacker-1",
		},
		{
			name: "a subject uses the next one too",
			relationships: []Relationship{
				rel("document:roadmap", "viewer", "user:attacker"),
				rel("document:plan", "viewer", "user:attacker-1"),
			},
			expected: "attacker-2",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := freeObject(namedObjects(Sample{Relationships: tt.relationships}), "user", "attacker")
			if got != (Object{Type: "user", ID: tt.expected}) {
				t.Errorf("freeObject = %s, want user:%s", got, tt.expected)
			}
		})
	}
}

// The attacker the analysis supposes does not inherit from a real subject of its name:
// a real user:attacker who already views the document does not hide that an account with
// nothing can write itself in.
func TestARealSubjectCalledAttackerHidesNothing(t *testing.T) {
	wm := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: []*WriteRule{
		{Resource: "document", Relation: "viewer", Operations: []Operation{Create}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Self: true}},
	}}
	sample := Sample{
		Model:         documents(t),
		Relationships: []Relationship{rel("document:roadmap", "viewer", "user:attacker")},
		Now:           time.Unix(0, 0),
	}
	found := false
	for _, m := range Run(sample, wm) {
		if m.Raise != nil && m.Raise.Permission == "view" && m.Raise.Type == "document" {
			found = true
		}
	}
	if !found {
		t.Error("the self-write on view is not reported, because the real subject already holds it")
	}
}

// A subject is an object a relationship names on its own. A userset's members are who
// hold what it grants, and a wildcard names nobody.
func TestRealSubjects(t *testing.T) {
	got := realSubjects([]Relationship{
		rel("document:roadmap", "viewer", "user:vic"),
		rel("document:roadmap", "editor", "user:erin"),
		rel("document:plan", "viewer", "user:vic"),
		rel("document:roadmap", "viewer", "user:*"),
		{Resource: Object{Type: "document", ID: "roadmap"}, Relation: "viewer", Subject: Subject{Object: Object{Type: "team", ID: "design"}, Relation: "member"}},
	})
	want := []Object{{Type: "user", ID: "erin"}, {Type: "user", ID: "vic"}}
	if !slices.Equal(got, want) {
		t.Errorf("realSubjects = %v, want %v", got, want)
	}
}

// What a subject holds is what a check answers yes to, on every way a schema can grant:
// directly, through a permission, through a wildcard. Nothing is drawn for what it does
// not hold, and a subject's hold on itself says nothing about who can reach what.
func TestSubjectHoldings(t *testing.T) {
	document := &Type{
		Name: "document",
		Relations: []*Relation{
			{Name: "viewer", Allowed: []Allowed{{Type: "user"}, {Type: "user", Wildcard: true}}},
			{Name: "editor", Allowed: []Allowed{{Type: "user"}}},
		},
		Permissions: []*Permission{
			{Name: "edit", Expr: Computed{Name: "editor"}},
			{Name: "view", Expr: Union{Children: []Expr{Computed{Name: "viewer"}, Computed{Name: "editor"}}}},
		},
	}
	user := &Type{Name: "user", Permissions: []*Permission{{Name: "me", Expr: Self{}}}}
	model, err := NewModel([]*Type{user, document}, nil)
	if err != nil {
		t.Fatal(err)
	}
	roadmap, plan := Object{Type: "document", ID: "roadmap"}, Object{Type: "document", ID: "plan"}
	erin, vic := Object{Type: "user", ID: "erin"}, Object{Type: "user", ID: "vic"}

	got, _ := subjectHoldings(Sample{
		Model: model,
		Relationships: []Relationship{
			rel("document:roadmap", "editor", "user:erin"),
			rel("document:plan", "viewer", "user:*"),
			rel("document:plan", "viewer", "user:vic"),
		},
		Now: time.Unix(0, 0),
	}, maxHoldingChecks)
	want := []holding{
		{subject: erin, object: plan, permission: "view"},
		{subject: vic, object: plan, permission: "view"},
		{subject: erin, object: roadmap, permission: "edit"},
		{subject: erin, object: roadmap, permission: "view"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("subjectHoldings =\n%v\nwant\n%v", got, want)
	}
}

// A holding is an unconditional yes. A relationship behind a caveat the check does not
// settle holds for some checks and not for others, and a yes that cut a loop rests on a
// walk the product may not finish.
func TestAHoldingIsAnUnconditionalYes(t *testing.T) {
	document := &Type{
		Name: "document",
		Relations: []*Relation{
			{Name: "viewer", Allowed: []Allowed{{Type: "user"}, {Type: "user", Caveat: "open"}}},
		},
		Permissions: []*Permission{{Name: "view", Expr: Computed{Name: "viewer"}}},
	}
	model, err := NewModel([]*Type{{Name: "user"}, document}, []*Caveat{{Name: "open", Parameters: []Parameter{{Name: "x", Type: "int"}}}})
	if err != nil {
		t.Fatal(err)
	}
	conditional := rel("document:roadmap", "viewer", "user:vic")
	conditional.Caveat = &CaveatUse{Name: "open"}
	got, _ := subjectHoldings(Sample{
		Model:         model,
		Relationships: []Relationship{conditional},
		Caveats:       stubCaveats{},
		Now:           time.Unix(0, 0),
	}, maxHoldingChecks)
	if len(got) != 0 {
		t.Errorf("a conditional yes reads as a holding: %v", got)
	}

	loop := &Type{
		Name: "folder",
		Relations: []*Relation{
			{Name: "parent", Allowed: []Allowed{{Type: "folder"}}},
			{Name: "viewer", Allowed: []Allowed{{Type: "user"}}},
		},
		Permissions: []*Permission{{
			Name: "view",
			Expr: Union{Children: []Expr{Computed{Name: "viewer"}, Arrow{Through: "parent", Target: "view"}}},
		}},
	}
	loopModel, err := NewModel([]*Type{{Name: "user"}, loop}, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, _ = subjectHoldings(Sample{
		Model: loopModel,
		Relationships: []Relationship{
			rel("folder:a", "parent", "folder:b"),
			rel("folder:b", "parent", "folder:a"),
			rel("folder:c", "viewer", "user:vic"),
		},
		Now: time.Unix(0, 0),
	}, maxHoldingChecks)
	for _, h := range got {
		if h.object.ID == "a" || h.object.ID == "b" {
			t.Errorf("a loop that grants nothing reads as a holding: %v", h)
		}
	}
}

// Only the subjects the tuples a check reads name, or the type of a wildcard among them,
// are asked of an object. The answer is the one asking every subject of every object
// gives, through a chain of arrows, a userset, a wildcard far from the object, an
// exclusion, an intersection and a permission that reads the subject itself.
func TestHoldingsAreWhatAskingEverySubjectGives(t *testing.T) {
	user := &Type{
		Name:        "user",
		Relations:   []*Relation{{Name: "friend", Allowed: []Allowed{{Type: "user"}}}},
		Permissions: []*Permission{{Name: "me", Expr: Self{}}},
	}
	team := &Type{Name: "team", Relations: []*Relation{{Name: "member", Allowed: []Allowed{{Type: "user"}}}}}
	folder := &Type{
		Name: "folder",
		Relations: []*Relation{
			{Name: "parent", Allowed: []Allowed{{Type: "folder"}}},
			{Name: "viewer", Allowed: []Allowed{{Type: "user"}, {Type: "user", Wildcard: true}, {Type: "team", Relation: "member"}}},
			{Name: "owner", Allowed: []Allowed{{Type: "user"}, {Type: "user", Relation: "me"}}},
			{Name: "banned", Allowed: []Allowed{{Type: "user"}}},
		},
		Permissions: []*Permission{
			{Name: "view", Expr: Union{Children: []Expr{Computed{Name: "viewer"}, Computed{Name: "owner"}, Arrow{Through: "parent", Target: "view"}}}},
			{Name: "open", Expr: Exclusion{Base: Computed{Name: "view"}, Subtracted: []Expr{Computed{Name: "banned"}}}},
			{Name: "both", Expr: Intersection{Children: []Expr{Computed{Name: "view"}, Computed{Name: "owner"}}}},
		},
	}
	model, err := NewModel([]*Type{user, team, folder}, nil)
	if err != nil {
		t.Fatal(err)
	}
	sample := Sample{
		Model: model,
		Relationships: []Relationship{
			rel("folder:a", "parent", "folder:b"),
			rel("folder:b", "parent", "folder:c"),
			rel("folder:c", "viewer", "user:*"),
			rel("folder:d", "viewer", "user:vic"),
			rel("folder:d", "banned", "user:vic"),
			rel("folder:e", "owner", "user:erin"),
			rel("folder:f", "parent", "folder:e"),
			rel("team:t", "member", "user:tess"),
			{Resource: Object{Type: "folder", ID: "g"}, Relation: "viewer", Subject: Subject{Object: Object{Type: "team", ID: "t"}, Relation: "member"}},
			{Resource: Object{Type: "folder", ID: "h"}, Relation: "owner", Subject: Subject{Object: Object{Type: "user", ID: "olga"}, Relation: "me"}},
			rel("folder:i", "viewer", "user:olga"),
			rel("user:olga", "friend", "user:gil"),
		},
		Now: time.Unix(0, 0),
	}

	var objects []Object
	for _, r := range sample.Relationships {
		objects = append(objects, r.Resource, r.Subject.Object)
	}
	checker := NewChecker(model, sample.Relationships, nil, sample.Now)
	var want []holding
	for _, object := range uniqueObjects(objects) {
		typ := model.Type(object.Type)
		if typ == nil || object.ID == WildcardID {
			continue
		}
		for _, subject := range realSubjects(sample.Relationships) {
			if subject == object {
				continue
			}
			for _, p := range typ.Permissions {
				got, err := checker.Check(object, p.Name, Subject{Object: subject}, nil)
				if err == nil && got.Level == Yes && !got.Cycle {
					want = append(want, holding{subject: subject, object: object, permission: p.Name})
				}
			}
		}
	}
	if len(want) == 0 {
		t.Fatal("asking everyone finds nothing, so the comparison shows nothing")
	}
	got, limits := subjectHoldings(sample, maxHoldingChecks)
	if !slices.Equal(got, want) {
		t.Errorf("subjectHoldings =\n%v\nasking everyone gives\n%v", got, want)
	}
	if limits != (Limits{}) {
		t.Errorf("under the limit it says %+v", limits)
	}
}

// Asking who holds what has a limit, and the objects past it are counted so the graph
// does not read as complete. An object is asked to its end, so a limit never gives half
// of what a subject holds on it.
func TestTheWorkOnHoldingsIsCounted(t *testing.T) {
	sample := Sample{
		Model: documents(t),
		Relationships: []Relationship{
			rel("document:a", "editor", "user:vic"),
			rel("document:b", "editor", "user:erin"),
			rel("document:c", "editor", "user:dana"),
		},
		Now: time.Unix(0, 0),
	}
	all, limits := subjectHoldings(sample, maxHoldingChecks)
	if limits.HoldingsLeftOut != 0 || len(all) != 6 {
		t.Fatalf("under the limit it finds %v and leaves out %d", all, limits.HoldingsLeftOut)
	}
	some, limits := subjectHoldings(sample, 1)
	if limits.HoldingsLeftOut != 2 {
		t.Errorf("past the limit it leaves out %d objects, want 2", limits.HoldingsLeftOut)
	}
	if !slices.Equal(some, all[:2]) {
		t.Errorf("past the limit it finds %v, want what the first object gives: %v", some, all[:2])
	}
}
