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

// A loop cut under an exclusion proves nothing: the No a cut answers with is
// provisional, and negating it would grant on the strength of a question still
// being asked. A subtracted side that grants anyway decides without the loop, and
// a loop in a union keeps what the rest of the union grants.
func TestCheckALoopUnderAnExclusion(t *testing.T) {
	document := &Type{
		Name: "document",
		Relations: []*Relation{
			{Name: "direct", Allowed: []Allowed{{Type: "user"}}},
			{Name: "restricted", Allowed: []Allowed{{Type: "user"}, {Type: "document", Relation: "viewer"}}},
			{Name: "parent", Allowed: []Allowed{{Type: "document"}}},
		},
		Permissions: []*Permission{
			{Name: "viewer", Expr: Exclusion{Base: Computed{Name: "direct"}, Subtracted: []Expr{Computed{Name: "restricted"}}}},
			{Name: "inherited", Expr: Union{Children: []Expr{Computed{Name: "direct"}, Arrow{Through: "parent", Target: "inherited"}}}},
			{Name: "cleared", Expr: Exclusion{Base: Computed{Name: "direct"}, Subtracted: []Expr{Arrow{Through: "parent", Target: "inherited"}}}},
		},
	}
	model, err := NewModel([]*Type{{Name: "user"}, document}, nil)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		tuples    []Relationship
		ask       string
		want      Level
		wantCycle bool
	}{
		{
			name: "the subtracted side comes back to the permission",
			tuples: []Relationship{
				rel("document:1", "direct", "user:jon"),
				rel("document:1", "restricted", "document:1#viewer"),
			},
			ask:       "viewer",
			want:      No,
			wantCycle: true,
		},
		{
			name: "the subtracted side grants before the loop matters",
			tuples: []Relationship{
				rel("document:1", "direct", "user:jon"),
				rel("document:1", "restricted", "user:jon"),
				rel("document:1", "restricted", "document:1#viewer"),
			},
			ask:  "viewer",
			want: No,
		},
		{
			name: "a loop of objects on the subtracted side",
			tuples: []Relationship{
				rel("document:1", "direct", "user:jon"),
				rel("document:1", "parent", "document:2"),
				rel("document:2", "parent", "document:3"),
				rel("document:3", "parent", "document:2"),
			},
			ask:       "cleared",
			want:      No,
			wantCycle: true,
		},
		{
			name: "no loop on the subtracted side",
			tuples: []Relationship{
				rel("document:1", "direct", "user:jon"),
				rel("document:1", "parent", "document:2"),
			},
			ask:  "cleared",
			want: Yes,
		},
		{
			name: "a loop in a union still finds what grants",
			tuples: []Relationship{
				rel("document:1", "parent", "document:1"),
				rel("document:1", "parent", "document:2"),
				rel("document:2", "direct", "user:jon"),
			},
			ask:       "inherited",
			want:      Yes,
			wantCycle: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewChecker(model, tt.tuples, nil, time.Unix(0, 0)).Check(object("document:1"), tt.ask, subjectOf("user:jon"), nil)
			if err != nil {
				t.Fatalf("Check: %v", err)
			}
			if got.Level != tt.want || got.Cycle != tt.wantCycle {
				t.Errorf("Check() = %s (cycle %v), want %s (cycle %v)", got.Level, got.Cycle, tt.want, tt.wantCycle)
			}
		})
	}
}

// A product's walk decides what a loop on the subtracted side comes to. A loop it walks
// to a fixpoint, or leaves behind a caveat that fails, is no reason to refuse: the
// exclusion reads the real answer. A loop behind a caveat nothing decides stays open,
// since the product meets it only if the caveat holds. And with no walk said, as in
// TestCheckALoopUnderAnExclusion, the product meets every loop.
func TestCheckALoopAccordingToTheWalk(t *testing.T) {
	groups := &Type{
		Name: "group",
		Relations: []*Relation{
			{Name: "member", Allowed: []Allowed{{Type: "user"}, {Type: "group", Relation: "member"}}},
			{Name: "parent", Allowed: []Allowed{{Type: "group", Caveat: "network"}}},
		},
		Permissions: []*Permission{
			{Name: "inherited", Expr: Union{Children: []Expr{Computed{Name: "member"}, Arrow{Through: "parent", Target: "inherited"}}}},
		},
	}
	document := &Type{
		Name: "document",
		Relations: []*Relation{
			{Name: "direct", Allowed: []Allowed{{Type: "user"}}},
			{Name: "banned", Allowed: []Allowed{{Type: "group", Relation: "member"}, {Type: "group", Relation: "member", Caveat: "network"}}},
			{Name: "parent", Allowed: []Allowed{{Type: "group", Caveat: "network"}}},
		},
		Permissions: []*Permission{
			{Name: "viewer", Expr: Exclusion{Base: Computed{Name: "direct"}, Subtracted: []Expr{Computed{Name: "banned"}}}},
			{Name: "open", Expr: Exclusion{Base: Computed{Name: "direct"}, Subtracted: []Expr{Arrow{Through: "parent", Target: "inherited"}}}},
		},
	}
	build := func(walk Walk) *Model {
		m, err := NewModel([]*Type{{Name: "user"}, groups, document}, []*Caveat{{Name: "network"}})
		if err != nil {
			t.Fatal(err)
		}
		m.Walk = walk
		return m
	}
	jon := subjectOf("user:jon")
	direct := rel("document:1", "direct", "user:jon")
	loop := []Relationship{rel("group:a", "member", "group:b#member"), rel("group:b", "member", "group:a#member")}
	caveated := func(r Relationship) Relationship {
		r.Caveat = &CaveatUse{Name: "network"}
		return r
	}
	banned := rel("document:1", "banned", "group:a#member")
	walkedLoop := []Relationship{caveated(rel("group:a", "parent", "group:b")), caveated(rel("group:b", "parent", "group:a"))}
	inside, outside := map[string]any{"address": "inside"}, map[string]any{"address": "outside"}
	fixpoint := map[FixpointWalk]bool{{Type: "group", Name: "member", SubjectType: "user"}: true}

	tests := []struct {
		name      string
		walk      Walk
		tuples    []Relationship
		ask       string
		subject   Subject
		context   map[string]any
		want      Level
		wantCycle bool
	}{
		{
			name:      "no walk said: the loop is met",
			tuples:    append([]Relationship{direct, banned}, loop...),
			ask:       "viewer",
			subject:   jon,
			want:      No,
			wantCycle: true,
		},
		{
			name:      "a relation walked to a fixpoint: the loop is not met",
			walk:      Walk{Fixpoint: fixpoint},
			tuples:    append([]Relationship{direct, banned}, loop...),
			ask:       "viewer",
			subject:   jon,
			want:      Yes,
			wantCycle: true,
		},
		{
			name:    "a walk to a fixpoint still finds who is in it",
			walk:    Walk{Fixpoint: fixpoint},
			tuples:  append([]Relationship{direct, banned, rel("group:b", "member", "user:jon")}, loop...),
			ask:     "viewer",
			subject: jon,
			want:    No,
		},
		{
			name:      "a walk to a fixpoint is not what a userset gets",
			walk:      Walk{Fixpoint: map[FixpointWalk]bool{{Type: "group", Name: "member", SubjectType: "group"}: true}},
			tuples:    append([]Relationship{rel("document:1", "direct", "group:z#member"), banned}, loop...),
			ask:       "viewer",
			subject:   subjectOf("group:z#member"),
			want:      No,
			wantCycle: true,
		},
		{
			name:      "a walk to a fixpoint of another subject type",
			walk:      Walk{Fixpoint: map[FixpointWalk]bool{{Type: "group", Name: "member", SubjectType: "robot"}: true}},
			tuples:    append([]Relationship{direct, banned}, loop...),
			ask:       "viewer",
			subject:   jon,
			want:      No,
			wantCycle: true,
		},
		{
			name:      "a caveat that fails hides the loop from a product that stops at it",
			walk:      Walk{StopsAtFailedCaveat: true},
			tuples:    append([]Relationship{direct, caveated(banned)}, loop...),
			ask:       "viewer",
			subject:   jon,
			context:   outside,
			want:      Yes,
			wantCycle: false,
		},
		{
			name:      "a caveat that fails does not hide it from a product that follows anyway",
			tuples:    append([]Relationship{direct, caveated(banned)}, loop...),
			ask:       "viewer",
			subject:   jon,
			context:   outside,
			want:      No,
			wantCycle: true,
		},
		{
			name:      "a caveat that holds leaves the loop met",
			walk:      Walk{StopsAtFailedCaveat: true},
			tuples:    append([]Relationship{direct, caveated(banned)}, loop...),
			ask:       "viewer",
			subject:   jon,
			context:   inside,
			want:      No,
			wantCycle: true,
		},
		{
			name:      "a caveat nothing decides leaves the exclusion open",
			walk:      Walk{StopsAtFailedCaveat: true},
			tuples:    append([]Relationship{direct, caveated(banned)}, loop...),
			ask:       "viewer",
			subject:   jon,
			want:      Conditional,
			wantCycle: true,
		},
		{
			name:      "a walked relationship with a caveat that fails hides the loop",
			walk:      Walk{StopsAtFailedCaveat: true},
			tuples:    append([]Relationship{direct, caveated(rel("document:1", "parent", "group:a"))}, walkedLoop...),
			ask:       "open",
			subject:   jon,
			context:   outside,
			want:      Yes,
			wantCycle: false,
		},
		{
			name:      "a walked relationship with a caveat nothing decides leaves it open",
			walk:      Walk{StopsAtFailedCaveat: true},
			tuples:    append([]Relationship{direct, caveated(rel("document:1", "parent", "group:a"))}, walkedLoop...),
			ask:       "open",
			subject:   jon,
			want:      Conditional,
			wantCycle: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewChecker(build(tt.walk), tt.tuples, insideOnly{}, time.Unix(0, 0)).Check(object("document:1"), tt.ask, tt.subject, tt.context)
			if err != nil {
				t.Fatalf("Check: %v", err)
			}
			if got.Level != tt.want || got.Cycle != tt.wantCycle {
				t.Errorf("Check() = %s (cycle %v), want %s (cycle %v)", got.Level, got.Cycle, tt.want, tt.wantCycle)
			}
		})
	}
}

// A name that is both a relation and a permission answers as the permission,
// and the permission reads what is stored under the name through Stored. A
// userset that names it holds the whole permission, computed arms included, not
// only the tuples stored under it.
func TestCheckASharedName(t *testing.T) {
	doc := object("document:d")
	tests := []struct {
		name    string
		tuples  []Relationship
		ask     string
		subject string
		want    Level
	}{
		{name: "nothing stored", ask: "viewer", subject: "user:alice", want: No},
		{
			name:    "stored under the name",
			tuples:  []Relationship{rel("document:d", "viewer", "user:alice")},
			ask:     "viewer",
			subject: "user:alice",
			want:    Yes,
		},
		{
			name:    "a computed arm",
			tuples:  []Relationship{rel("document:d", "owner", "user:alice")},
			ask:     "viewer",
			subject: "user:alice",
			want:    Yes,
		},
		{
			name: "an arrow whose target shares its name",
			tuples: []Relationship{
				rel("document:d", "parent", "folder:f"),
				rel("folder:f", "viewer", "user:alice"),
			},
			ask:     "viewer",
			subject: "user:alice",
			want:    Yes,
		},
		{
			name:    "a wildcard stored under the name",
			tuples:  []Relationship{rel("document:d", "viewer", "user:*")},
			ask:     "viewer",
			subject: "user:bob",
			want:    Yes,
		},
		{
			name: "a userset holds the computed arm of what it names",
			tuples: []Relationship{
				rel("document:d", "viewer", "group:g#member"),
				rel("group:g", "admin", "user:carol"),
			},
			ask:     "viewer",
			subject: "user:carol",
			want:    Yes,
		},
		{
			name: "a ban reached through the computed arm of a userset",
			tuples: []Relationship{
				rel("document:d", "viewer", "user:carol"),
				rel("document:d", "banned", "group:g#member"),
				rel("group:g", "admin", "user:carol"),
			},
			ask:     "viewer",
			subject: "user:carol",
			want:    No,
		},
		{
			name:    "a userset holds itself",
			ask:     "viewer",
			subject: "document:d#viewer",
			want:    Yes,
		},
		{
			name:    "a relation alone answers from what is stored",
			tuples:  []Relationship{rel("document:d", "parent", "folder:f")},
			ask:     "parent",
			subject: "folder:f",
			want:    Yes,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewChecker(sharedNames(t), tt.tuples, nil, time.Unix(0, 0)).Check(doc, tt.ask, subjectOf(tt.subject), nil)
			if err != nil {
				t.Fatalf("Check: %v", err)
			}
			if got.Level != tt.want {
				t.Errorf("Check(%s, %s) = %s, want %s", tt.ask, tt.subject, got.Level, tt.want)
			}
		})
	}
}
