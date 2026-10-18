package zanzibar

import (
	"slices"
	"testing"
	"time"
)

// documents is the schema the closure tests write against: a document with an
// owner, an editor, a viewer that also admits a team's members and a wildcard,
// edit over owner and editor, and view over the viewer and edit.
func documents(t *testing.T) *Model {
	t.Helper()
	document := &Type{
		Name: "document",
		Relations: []*Relation{
			{Name: "owner", Allowed: []Allowed{{Type: "user"}}},
			{Name: "editor", Allowed: []Allowed{{Type: "user"}}},
			{Name: "viewer", Allowed: []Allowed{
				{Type: "user"},
				{Type: "team", Relation: "member"},
				{Type: "user", Wildcard: true},
			}},
		},
		Permissions: []*Permission{
			{Name: "edit", Expr: Union{Children: []Expr{Computed{Name: "owner"}, Computed{Name: "editor"}}}},
			{Name: "view", Expr: Union{Children: []Expr{Computed{Name: "viewer"}, Computed{Name: "edit"}}}},
		},
	}
	team := &Type{Name: "team", Relations: []*Relation{{Name: "member", Allowed: []Allowed{{Type: "user"}}}}}
	m, err := NewModel([]*Type{{Name: "user"}, team, document}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func rel(resource, relation, subject string) Relationship {
	return Relationship{
		Resource: object(resource),
		Relation: relation,
		Subject:  subjectOf(subject),
	}
}

func object(s string) Object {
	for i := range len(s) {
		if s[i] == ':' {
			return Object{Type: s[:i], ID: s[i+1:]}
		}
	}
	return Object{Type: s}
}

func subjectOf(s string) Subject {
	for i := range len(s) {
		if s[i] == '#' {
			return Subject{Object: object(s[:i]), Relation: s[i+1:]}
		}
	}
	return Subject{Object: object(s)}
}

func TestClosure(t *testing.T) {
	model := documents(t)
	roadmap := object("document:roadmap")
	mallory := object("user:mallory")

	tests := []struct {
		name      string
		writes    []*WriteRule
		creates   []*CreationRule
		start     []Relationship
		coalition []Object
		wantAdded []Relationship
		wantView  Level
	}{
		{
			name: "self-write into viewer",
			writes: []*WriteRule{
				{Resource: "document", Relation: "viewer", Operations: []Operation{Create}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Self: true}},
			},
			start:     []Relationship{rel("document:roadmap", "owner", "user:olivia")},
			coalition: []Object{mallory},
			wantAdded: []Relationship{rel("document:roadmap", "viewer", "user:mallory")},
			wantView:  Yes,
		},
		{
			name: "gate opens after a write",
			writes: []*WriteRule{
				{Resource: "document", Relation: "editor", Operations: []Operation{Create}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Self: true}},
				{Resource: "document", Relation: "viewer", Operations: []Operation{Create}, Gate: Gate{Holds: "edit"}, Subject: SubjectSpec{Self: true}},
			},
			start:     []Relationship{rel("document:roadmap", "owner", "user:olivia")},
			coalition: []Object{mallory},
			wantAdded: []Relationship{
				rel("document:roadmap", "editor", "user:mallory"),
				rel("document:roadmap", "viewer", "user:mallory"),
			},
			wantView: Yes,
		},
		{
			name: "wildcard subject is a global switch",
			writes: []*WriteRule{
				{Resource: "document", Relation: "viewer", Operations: []Operation{Create}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Any: true}, Wildcard: true},
			},
			start:     []Relationship{rel("document:roadmap", "owner", "user:olivia")},
			coalition: []Object{mallory},
			wantAdded: []Relationship{
				rel("document:roadmap", "viewer", "user:mallory"),
				rel("document:roadmap", "viewer", "user:*"),
			},
			wantView: Yes,
		},
		{
			name: "created team assumed into viewer",
			writes: []*WriteRule{
				{Resource: "document", Relation: "viewer", Operations: []Operation{Create}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Types: []string{"team#member"}}},
			},
			creates: []*CreationRule{
				{Creates: "team", Gate: Gate{Anyone: true}, Writes: []CreationWrite{
					{Resource: CreatedPlaceholder, Relation: "member", Subject: CreatorPlaceholder},
				}},
			},
			start:     []Relationship{rel("document:roadmap", "owner", "user:olivia")},
			coalition: []Object{mallory},
			wantAdded: []Relationship{
				rel("team:created-0", "member", "user:mallory"),
				rel("document:roadmap", "viewer", "team:created-0#member"),
			},
			wantView: Yes,
		},
		{
			name: "service gate is out of reach",
			writes: []*WriteRule{
				{Resource: "document", Relation: "viewer", Operations: []Operation{Create}, Gate: Gate{Service: "sharing"}, Subject: SubjectSpec{Self: true}},
			},
			start:     []Relationship{rel("document:roadmap", "owner", "user:olivia")},
			coalition: []Object{mallory},
			wantAdded: nil,
			wantView:  No,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wm := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: tt.writes, Creates: tt.creates}
			reach, err := Closure(model, wm, nil, tt.start, tt.coalition, Options{Now: time.Unix(0, 0)})
			if err != nil {
				t.Fatalf("Closure: %v", err)
			}

			added := addedTuples(tt.start, reach.State)
			if !sameTuples(added, tt.wantAdded) {
				t.Errorf("added tuples = %v, want %v", keysOf(added), keysOf(tt.wantAdded))
			}

			view, err := reach.Holds(roadmap, "view")
			if err != nil {
				t.Fatalf("Holds view: %v", err)
			}
			if view != tt.wantView {
				t.Errorf("coalition view = %s, want %s", view, tt.wantView)
			}

			assertSaturated(t, model, wm, nil, tt.start, tt.coalition, reach)
		})
	}
}

// A deny by exclusion is lifted by deleting the tuple that denies. Mallory is a
// viewer but banned, so view does not hold; a delete rule on banned lets the
// coalition remove its own ban, and view rises. banned occurs only negatively
// and viewer only positively, so E1 holds and the closure is exact.
func TestClosureDeletesLiftADeny(t *testing.T) {
	document := &Type{
		Name: "document",
		Relations: []*Relation{
			{Name: "viewer", Allowed: []Allowed{{Type: "user"}}},
			{Name: "banned", Allowed: []Allowed{{Type: "user"}}},
		},
		Permissions: []*Permission{
			{Name: "view", Expr: Exclusion{Base: Computed{Name: "viewer"}, Subtracted: []Expr{Computed{Name: "banned"}}}},
		},
	}
	model, err := NewModel([]*Type{{Name: "user"}, document}, nil)
	if err != nil {
		t.Fatal(err)
	}
	wm := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: []*WriteRule{
		{Resource: "document", Relation: "viewer", Operations: []Operation{Create}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Self: true}},
		{Resource: "document", Relation: "banned", Operations: []Operation{Delete}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Self: true}},
	}}
	roadmap := object("document:roadmap")
	mallory := object("user:mallory")
	start := []Relationship{rel("document:roadmap", "viewer", "user:mallory"), rel("document:roadmap", "banned", "user:mallory")}

	reach, err := Closure(model, wm, nil, start, []Object{mallory}, Options{Now: time.Unix(0, 0)})
	if err != nil {
		t.Fatalf("Closure: %v", err)
	}
	if !reach.Exact {
		t.Fatal("E1 holds for this schema, so the closure should be exact")
	}
	for _, r := range reach.State {
		if r.Relation == "banned" {
			t.Errorf("the ban %s should have been deleted", r)
		}
	}
	view, err := reach.Holds(roadmap, "view")
	if err != nil {
		t.Fatalf("Holds view: %v", err)
	}
	if view != Yes {
		t.Errorf("coalition view = %s, want yes once the ban is lifted", view)
	}
	assertSaturated(t, model, wm, nil, start, []Object{mallory}, reach)
}

// A relation that occurs in both polarities is mixed, so E1 fails: adding
// editor raises edit but lowers flagged, and no single state holds both at
// once. The closure then searches up to the bound and reports each raise it can
// reach, edit by adding editor and flagged already in the starting state.
func TestClosureE1Fails(t *testing.T) {
	document := &Type{
		Name: "document",
		Relations: []*Relation{
			{Name: "editor", Allowed: []Allowed{{Type: "user"}}},
			{Name: "reviewer", Allowed: []Allowed{{Type: "user"}}},
		},
		Permissions: []*Permission{
			{Name: "edit", Expr: Computed{Name: "editor"}},
			{Name: "flagged", Expr: Exclusion{Base: Computed{Name: "reviewer"}, Subtracted: []Expr{Computed{Name: "editor"}}}},
		},
	}
	model, err := NewModel([]*Type{{Name: "user"}, document}, nil)
	if err != nil {
		t.Fatal(err)
	}
	wm := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: []*WriteRule{
		{Resource: "document", Relation: "editor", Operations: []Operation{Create}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Self: true}},
	}}
	report := object("document:report")
	mallory := object("user:mallory")
	start := []Relationship{rel("document:report", "reviewer", "user:mallory")}

	ok, mixed := CheckE1(model, wm)
	if ok {
		t.Fatal("editor is mixed, so E1 should fail")
	}
	if len(mixed) != 1 || mixed[0].String() != "document#editor (occurs in both polarities)" {
		t.Errorf("mixed = %v, want [document#editor (occurs in both polarities)]", mixed)
	}

	reach, err := Closure(model, wm, nil, start, []Object{mallory}, Options{Now: time.Unix(0, 0)})
	if err != nil {
		t.Fatalf("Closure: %v", err)
	}
	if reach.Exact {
		t.Fatal("E1 fails, so the closure should not be exact")
	}
	if reach.Bound != DefaultMaxWrites {
		t.Errorf("bound = %d, want %d", reach.Bound, DefaultMaxWrites)
	}
	if len(reach.Mixed) != 1 || reach.Mixed[0].Relation != "editor" {
		t.Errorf("reach.Mixed = %v, want document#editor", reach.Mixed)
	}

	edit, err := reach.Holds(report, "edit")
	if err != nil {
		t.Fatalf("Holds edit: %v", err)
	}
	if edit != Yes {
		t.Errorf("edit = %s, want yes: it is reached by adding editor", edit)
	}
	flagged, err := reach.Holds(report, "flagged")
	if err != nil {
		t.Fatalf("Holds flagged: %v", err)
	}
	if flagged != Yes {
		t.Errorf("flagged = %s, want yes: it holds in the starting state", flagged)
	}
}

// E2 holding, the closure makes one object per choice of the On objects. The
// coalition is a member of two folders and the rule creates a document in a
// folder, owned by its creator, so the coalition ends up with a document it
// owns in each folder.
func TestClosureCreatesPerOnObject(t *testing.T) {
	folder := &Type{Name: "folder", Relations: []*Relation{{Name: "member", Allowed: []Allowed{{Type: "user"}}}}}
	document := &Type{
		Name:        "document",
		Relations:   []*Relation{{Name: "owner", Allowed: []Allowed{{Type: "user"}}}},
		Permissions: []*Permission{{Name: "edit", Expr: Computed{Name: "owner"}}},
	}
	model, err := NewModel([]*Type{{Name: "user"}, folder, document}, nil)
	if err != nil {
		t.Fatal(err)
	}
	wm := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Creates: []*CreationRule{{
		Creates: "document",
		Gate:    Gate{Anyone: true},
		On:      []OnSpec{{Type: "folder", Gate: Gate{Holds: "member"}}},
		Writes:  []CreationWrite{{Resource: CreatedPlaceholder, Relation: "owner", Subject: CreatorPlaceholder}},
	}}}
	mallory := object("user:mallory")
	start := []Relationship{rel("folder:a", "member", "user:mallory"), rel("folder:b", "member", "user:mallory")}

	reach, err := Closure(model, wm, nil, start, []Object{mallory}, Options{Now: time.Unix(0, 0)})
	if err != nil {
		t.Fatalf("Closure: %v", err)
	}
	if !reach.Exact {
		t.Fatal("this schema holds E1 and E2, so the closure should be exact")
	}
	for _, id := range []string{"created-0-folder-a", "created-0-folder-b"} {
		doc := Object{Type: "document", ID: id}
		if !slices.Contains(reach.Objects, doc) {
			t.Errorf("coalition should hold the created document %s, objects: %v", doc, reach.Objects)
		}
		edit, err := reach.Holds(doc, "edit")
		if err != nil {
			t.Fatalf("Holds edit on %s: %v", doc, err)
		}
		if edit != Yes {
			t.Errorf("coalition edit of %s = %s, want yes", doc, edit)
		}
	}
	assertSaturated(t, model, wm, nil, start, []Object{mallory}, reach)
}

// A folder created inside a folder is recursive, so E2 fails and the objects it
// makes are merged into one per rule rather than nesting without end. The
// closure is not exact, and it names the merged rule.
func TestClosureMergesRecursiveCreations(t *testing.T) {
	folder := &Type{
		Name: "folder",
		Relations: []*Relation{
			{Name: "parent", Allowed: []Allowed{{Type: "folder"}}},
			{Name: "viewer", Allowed: []Allowed{{Type: "user"}}},
		},
		Permissions: []*Permission{
			{Name: "view", Expr: Union{Children: []Expr{Computed{Name: "viewer"}, Arrow{Through: "parent", Target: "view"}}}},
		},
	}
	model, err := NewModel([]*Type{{Name: "user"}, folder}, nil)
	if err != nil {
		t.Fatal(err)
	}
	wm := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Creates: []*CreationRule{{
		Creates: "folder",
		Gate:    Gate{Anyone: true},
		On:      []OnSpec{{Type: "folder", Gate: Gate{Anyone: true}}},
		Writes:  []CreationWrite{{Resource: CreatedPlaceholder, Relation: "parent", Subject: "folder"}},
	}}}
	mallory := object("user:mallory")
	start := []Relationship{rel("folder:root", "viewer", "user:mallory")}

	reach, err := Closure(model, wm, nil, start, []Object{mallory}, Options{Now: time.Unix(0, 0)})
	if err != nil {
		t.Fatalf("Closure: %v", err)
	}
	if reach.Exact {
		t.Fatal("a recursive creation fails E2, so the closure should not be exact")
	}
	if !slices.Equal(reach.CreatedMerged, []string{"folder"}) {
		t.Errorf("CreatedMerged = %v, want [folder]", reach.CreatedMerged)
	}
	created := 0
	for _, o := range reach.Objects {
		if o.Type == "folder" {
			created++
		}
	}
	if created != 1 {
		t.Errorf("recursion made %d folders, want 1 merged object", created)
	}
	assertSaturated(t, model, wm, nil, start, []Object{mallory}, reach)
}

// A creation that writes a negative tuple fails E2, so the closure keeps k
// copies of the object and searches up to the bound rather than saturating.
func TestClosureKeepsCopiesForNegativeWrite(t *testing.T) {
	document := &Type{
		Name: "document",
		Relations: []*Relation{
			{Name: "viewer", Allowed: []Allowed{{Type: "user"}}},
			{Name: "banned", Allowed: []Allowed{{Type: "user"}}},
		},
		Permissions: []*Permission{
			{Name: "view", Expr: Exclusion{Base: Computed{Name: "viewer"}, Subtracted: []Expr{Computed{Name: "banned"}}}},
		},
	}
	model, err := NewModel([]*Type{{Name: "user"}, document}, nil)
	if err != nil {
		t.Fatal(err)
	}
	wm := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Creates: []*CreationRule{{
		Creates: "document",
		Gate:    Gate{Anyone: true},
		Writes: []CreationWrite{
			{Resource: CreatedPlaceholder, Relation: "viewer", Subject: CreatorPlaceholder},
			{Resource: CreatedPlaceholder, Relation: "banned", Subject: CreatorPlaceholder},
		},
	}}}
	mallory := object("user:mallory")

	reach, err := Closure(model, wm, nil, nil, []Object{mallory}, Options{Now: time.Unix(0, 0)})
	if err != nil {
		t.Fatalf("Closure: %v", err)
	}
	if reach.Exact {
		t.Fatal("a negative creation write fails E2, so the closure should not be exact")
	}
	if reach.CreatedCopies != DefaultCreatedCopies {
		t.Errorf("CreatedCopies = %d, want %d", reach.CreatedCopies, DefaultCreatedCopies)
	}
	created := 0
	for _, o := range reach.Objects {
		if o.Type == "document" {
			created++
		}
	}
	if created != DefaultCreatedCopies {
		t.Errorf("kept %d documents, want %d copies", created, DefaultCreatedCopies)
	}
}

// addedTuples is the tuples of the reachable state that the start did not have.
func addedTuples(start, state []Relationship) []Relationship {
	was := map[string]bool{}
	for _, r := range start {
		was[tupleKey(r)] = true
	}
	var added []Relationship
	for _, r := range state {
		if !was[tupleKey(r)] {
			added = append(added, r)
		}
	}
	return added
}

func sameTuples(a, b []Relationship) bool {
	ka, kb := keysOf(a), keysOf(b)
	slices.Sort(ka)
	slices.Sort(kb)
	return slices.Equal(ka, kb)
}

func keysOf(rels []Relationship) []string {
	out := make([]string, 0, len(rels))
	for _, r := range rels {
		out = append(out, tupleKey(r))
	}
	return out
}
