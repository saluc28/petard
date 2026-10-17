package zanzibar

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// The three levels combine the way SpiceDB combines partially evaluated
// caveats: false decides a conjunction, true decides a disjunction, and
// anything else stays conditional.
func TestLevelLogic(t *testing.T) {
	tests := []struct {
		name string
		got  Level
		want Level
	}{
		{name: "no and conditional", got: and(No, Conditional), want: No},
		{name: "conditional and yes", got: and(Conditional, Yes), want: Conditional},
		{name: "yes and yes", got: and(Yes, Yes), want: Yes},
		{name: "yes or no", got: or(Yes, No), want: Yes},
		{name: "conditional or no", got: or(Conditional, No), want: Conditional},
		{name: "no or no", got: or(No, No), want: No},
		{name: "not yes", got: not(Yes), want: No},
		{name: "not no", got: not(No), want: Yes},
		{name: "not conditional", got: not(Conditional), want: Conditional},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("%s = %s, want %s", tt.name, tt.got, tt.want)
			}
		})
	}
}

// folders is a model of folders inside folders: the viewers of a folder, and
// those of every folder it is inside, view it.
func folders(t *testing.T) *Model {
	t.Helper()

	folder := &Type{
		Name: "folder",
		Relations: []*Relation{
			{Name: "parent", Allowed: []Allowed{{Type: "folder"}}},
			{Name: "viewer", Allowed: []Allowed{{Type: "user", Expiration: true}}},
		},
		Permissions: []*Permission{{
			Name: "view",
			Expr: Union{Children: []Expr{Computed{Name: "viewer"}, Arrow{Through: "parent", Target: "view"}}},
		}},
	}
	m, err := NewModel([]*Type{{Name: "user"}, folder}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func folder(id string) Object { return Object{Type: "folder", ID: id} }

func user(id string) Subject { return Subject{Object: Object{Type: "user", ID: id}} }

// An expiration counts at the time the checker is built, the way SpiceDB stops
// returning a relationship once it has expired.
func TestNewCheckerDropsExpiredRelationships(t *testing.T) {
	expires := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	rels := []Relationship{{Resource: folder("a"), Relation: "viewer", Subject: user("tom"), Expires: &expires}}

	before := NewChecker(folders(t), rels, nil, expires.Add(-time.Hour))
	if got, err := before.Check(folder("a"), "view", user("tom"), nil); err != nil || got.Level != Yes {
		t.Errorf("before expiring = %+v, %v, want yes", got, err)
	}
	at := NewChecker(folders(t), rels, nil, expires)
	if got, err := at.Check(folder("a"), "view", user("tom"), nil); err != nil || got.Level != No {
		t.Errorf("at expiry = %+v, %v, want no", got, err)
	}
}

// A check naming something the model does not declare is an error, not a no,
// and so is a check asked for a wildcard, which SpiceDB refuses too.
func TestCheckRefuses(t *testing.T) {
	checker := NewChecker(folders(t), nil, nil, time.Now())
	tests := []struct {
		name     string
		resource Object
		asked    string
		subject  Subject
		want     error
	}{
		{name: "undeclared permission", resource: folder("a"), asked: "edit", subject: user("tom"), want: ErrUnknown},
		{name: "undeclared type", resource: Object{Type: "drive", ID: "a"}, asked: "view", subject: user("tom"), want: ErrUnknown},
		{name: "wildcard subject", resource: folder("a"), asked: "view", subject: user(WildcardID), want: ErrWildcardSubject},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := checker.Check(tt.resource, tt.asked, tt.subject, nil); !errors.Is(err, tt.want) {
				t.Errorf("Check() error = %v, want %v", err, tt.want)
			}
		})
	}
}

// groups is a model of groups inside groups, with a permission that is
// membership.
func groups(t *testing.T) *Model {
	t.Helper()

	group := &Type{
		Name:        "group",
		Relations:   []*Relation{{Name: "member", Allowed: []Allowed{{Type: "user"}, {Type: "group", Relation: "member"}}}},
		Permissions: []*Permission{{Name: "view", Expr: Computed{Name: "member"}}},
	}
	m, err := NewModel([]*Type{{Name: "user"}, group}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// The members of a group are members of it with nothing stored, and through a
// permission that is membership; the members of another group are not.
func TestCheckAUsersetHoldsItself(t *testing.T) {
	eng := Object{Type: "group", ID: "eng"}
	members := func(o Object) Subject { return Subject{Object: o, Relation: "member"} }
	checker := NewChecker(groups(t), nil, nil, time.Now())

	tests := []struct {
		name    string
		asked   string
		subject Subject
		want    Level
	}{
		{name: "its own relation", asked: "member", subject: members(eng), want: Yes},
		{name: "a permission built on it", asked: "view", subject: members(eng), want: Yes},
		{name: "another group", asked: "member", subject: members(Object{Type: "group", ID: "ops"}), want: No},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := checker.Check(eng, tt.asked, tt.subject, nil)
			if err != nil || got.Level != tt.want {
				t.Errorf("Check() = %+v, %v, want %s", got, err, tt.want)
			}
		})
	}
}

// Two folders inside each other: a check that finds a grant answers yes, and
// one that finds none answers no and says it cut the loop, which is where
// SpiceDB would fail at its depth limit instead.
func TestCheckCutsLoops(t *testing.T) {
	checker := NewChecker(folders(t), []Relationship{
		{Resource: folder("a"), Relation: "parent", Subject: Subject{Object: folder("b")}},
		{Resource: folder("b"), Relation: "parent", Subject: Subject{Object: folder("a")}},
		{Resource: folder("b"), Relation: "viewer", Subject: user("lou")},
	}, nil, time.Now())

	granted, err := checker.Check(folder("a"), "view", user("lou"), nil)
	if err != nil || granted.Level != Yes {
		t.Errorf("lou views a = %+v, %v, want yes", granted, err)
	}
	refused, err := checker.Check(folder("a"), "view", user("nobody"), nil)
	if err != nil || refused.Level != No || !refused.Cycle {
		t.Errorf("nobody views a = %+v, %v, want no and a cycle", refused, err)
	}
}

// A chain of groups longer than the engine follows is an error that says so,
// and not an exhausted stack: the relationships come from files anybody can
// write.
func TestCheckStopsAtTheDepthLimit(t *testing.T) {
	group := &Type{
		Name:      "group",
		Relations: []*Relation{{Name: "member", Allowed: []Allowed{{Type: "user"}, {Type: "group", Relation: "member"}}}},
	}
	m, err := NewModel([]*Type{{Name: "user"}, group}, nil)
	if err != nil {
		t.Fatal(err)
	}
	link := func(i int) Object { return Object{Type: "group", ID: fmt.Sprint(i)} }
	rels := make([]Relationship, 0, maxDepth+2)
	for i := 0; i <= maxDepth; i++ {
		rels = append(rels, Relationship{Resource: link(i), Relation: "member", Subject: Subject{Object: link(i + 1), Relation: "member"}})
	}
	rels = append(rels, Relationship{Resource: link(maxDepth + 1), Relation: "member", Subject: user("deep")})

	_, err = NewChecker(m, rels, nil, time.Now()).Check(link(0), "member", user("deep"), nil)
	if !errors.Is(err, ErrTooDeep) {
		t.Errorf("Check() error = %v, want ErrTooDeep", err)
	}
}

// insideOnly is a caveat evaluator for tests: the caveat holds when the
// context says the address is inside, does not when it says outside, and is
// conditional when it says nothing.
type insideOnly struct{}

func (insideOnly) Evaluate(_ string, context map[string]any) (Level, error) {
	switch context["address"] {
	case "inside":
		return Yes, nil
	case "outside":
		return No, nil
	}
	return Conditional, nil
}

// A caveat sees the context of the check with the context the relationship
// carries written over it, so a value written on the relationship cannot be
// changed by the check.
func TestCheckWritesTheRelationshipContextOverTheCheck(t *testing.T) {
	doc := &Type{
		Name:      "doc",
		Relations: []*Relation{{Name: "viewer", Allowed: []Allowed{{Type: "user", Caveat: "network"}}}},
	}
	m, err := NewModel([]*Type{{Name: "user"}, doc}, []*Caveat{{Name: "network"}})
	if err != nil {
		t.Fatal(err)
	}
	a := Object{Type: "doc", ID: "a"}
	checker := NewChecker(m, []Relationship{
		{Resource: a, Relation: "viewer", Subject: user("fixed"), Caveat: &CaveatUse{Name: "network", Context: map[string]any{"address": "inside"}}},
		{Resource: a, Relation: "viewer", Subject: user("open"), Caveat: &CaveatUse{Name: "network"}},
	}, insideOnly{}, time.Now())

	tests := []struct {
		name    string
		subject Subject
		context map[string]any
		want    Level
	}{
		{name: "written value wins over the check", subject: user("fixed"), context: map[string]any{"address": "outside"}, want: Yes},
		{name: "check fills what nothing wrote", subject: user("open"), context: map[string]any{"address": "outside"}, want: No},
		{name: "nobody says", subject: user("open"), context: nil, want: Conditional},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := checker.Check(a, "viewer", tt.subject, tt.context)
			if err != nil || got.Level != tt.want {
				t.Errorf("Check() = %+v, %v, want %s", got, err, tt.want)
			}
		})
	}
}

// A relationship that carries a caveat cannot be answered without something
// to evaluate it, and saying so beats answering no.
func TestCheckWithoutACaveatEvaluator(t *testing.T) {
	doc := &Type{
		Name:      "doc",
		Relations: []*Relation{{Name: "viewer", Allowed: []Allowed{{Type: "user", Caveat: "weekday"}}}},
	}
	m, err := NewModel([]*Type{{Name: "user"}, doc}, []*Caveat{{Name: "weekday"}})
	if err != nil {
		t.Fatal(err)
	}
	checker := NewChecker(m, []Relationship{{
		Resource: Object{Type: "doc", ID: "a"},
		Relation: "viewer",
		Subject:  user("carol"),
		Caveat:   &CaveatUse{Name: "weekday"},
	}}, nil, time.Now())

	_, err = checker.Check(Object{Type: "doc", ID: "a"}, "viewer", user("carol"), nil)
	if err == nil || !strings.Contains(err.Error(), "nothing evaluates caveats") {
		t.Errorf("Check() error = %v, want one saying nothing evaluates caveats", err)
	}
}
