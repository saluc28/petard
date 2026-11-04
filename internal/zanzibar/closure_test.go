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
// A subject held to a caveat cannot write the same tuple without it under a rule that
// only creates: the product refuses a create of a tuple that is there already, whatever
// the caveat on it. A touch overwrites it, and a delete makes room, so either of those
// lifts the condition.
func TestAWriteOverATupleNeedsARuleThatReplaces(t *testing.T) {
	document := &Type{
		Name: "document",
		Relations: []*Relation{
			{Name: "viewer", Allowed: []Allowed{{Type: "user"}, {Type: "user", Caveat: "held"}}},
		},
		Permissions: []*Permission{{Name: "view", Expr: Computed{Name: "viewer"}}},
	}
	model, err := NewModel([]*Type{{Name: "user"}, document}, []*Caveat{{Name: "held"}})
	if err != nil {
		t.Fatal(err)
	}
	held := rel("document:roadmap", "viewer", "user:vic")
	held.Caveat = &CaveatUse{Name: "held"}
	vic := Object{Type: "user", ID: "vic"}

	tests := []struct {
		name       string
		operations []Operation
		raises     bool
	}{
		{name: "create alone", operations: []Operation{Create}, raises: false},
		{name: "create and touch", operations: []Operation{Create, Touch}, raises: true},
		{name: "touch alone", operations: []Operation{Touch}, raises: true},
		{name: "create and delete", operations: []Operation{Create, Delete}, raises: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wm := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: []*WriteRule{
				{Resource: "document", Relation: "viewer", Operations: tt.operations, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Self: true}},
			}}
			escalations, err := Escalations(model, wm, stubCaveats{}, []Relationship{held}, []Object{vic}, Options{Now: time.Unix(0, 0)})
			if err != nil {
				t.Fatalf("Escalations: %v", err)
			}
			if got := len(escalations) > 0; got != tt.raises {
				t.Errorf("raises = %v, want %v: %+v", got, tt.raises, escalations)
			}
		})
	}
}

// A create is still free to write a tuple that is not there. What it cannot do is land on
// one that is, so another subject's conditional tuple stops nobody.
func TestACreateIsHeldBackOnlyByTheSameTuple(t *testing.T) {
	document := &Type{
		Name: "document",
		Relations: []*Relation{
			{Name: "viewer", Allowed: []Allowed{{Type: "user"}, {Type: "user", Caveat: "held"}}},
		},
		Permissions: []*Permission{{Name: "view", Expr: Computed{Name: "viewer"}}},
	}
	model, err := NewModel([]*Type{{Name: "user"}, document}, []*Caveat{{Name: "held"}})
	if err != nil {
		t.Fatal(err)
	}
	held := rel("document:roadmap", "viewer", "user:vic")
	held.Caveat = &CaveatUse{Name: "held"}
	wm := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: []*WriteRule{
		{Resource: "document", Relation: "viewer", Operations: []Operation{Create}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Self: true}},
	}}
	escalations, err := Escalations(model, wm, stubCaveats{}, []Relationship{held}, []Object{{Type: "user", ID: "mallory"}}, Options{Now: time.Unix(0, 0)})
	if err != nil {
		t.Fatalf("Escalations: %v", err)
	}
	if len(escalations) == 0 {
		t.Error("another subject's conditional tuple stopped a create of a tuple that is not there")
	}
}

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

// A ban can reach its relation through a userset of a permission: banned admits
// group#membership, and membership reads member. Deleting oneself from member
// lifts the ban, so member occurs negatively in view even though no permission
// names it directly. It also occurs positively in membership, which makes it
// mixed: the run says it is not exact, and the raise is still found.
func TestClosureDeletesADenyThroughAUsersetOfAPermission(t *testing.T) {
	group := &Type{
		Name:        "group",
		Relations:   []*Relation{{Name: "member", Allowed: []Allowed{{Type: "user"}}}},
		Permissions: []*Permission{{Name: "membership", Expr: Computed{Name: "member"}}},
	}
	document := &Type{
		Name: "document",
		Relations: []*Relation{
			{Name: "viewer", Allowed: []Allowed{{Type: "user"}}},
			{Name: "banned", Allowed: []Allowed{{Type: "group", Relation: "membership"}}},
		},
		Permissions: []*Permission{
			{Name: "view", Expr: Exclusion{Base: Computed{Name: "viewer"}, Subtracted: []Expr{Computed{Name: "banned"}}}},
		},
	}
	model, err := NewModel([]*Type{{Name: "user"}, group, document}, nil)
	if err != nil {
		t.Fatal(err)
	}
	wm := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: []*WriteRule{
		{Resource: "group", Relation: "member", Operations: []Operation{Delete}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Self: true}},
	}}
	start := []Relationship{
		rel("document:roadmap", "viewer", "user:mallory"),
		rel("document:roadmap", "banned", "group:trolls#membership"),
		rel("group:trolls", "member", "user:mallory"),
	}
	mallory := object("user:mallory")

	exact, mixed := CheckE1(model, wm)
	if exact {
		t.Errorf("CheckE1 holds, but deleting group#member both lowers membership and lifts the ban on view")
	}
	if len(mixed) != 1 || mixed[0].Relation != "member" {
		t.Errorf("CheckE1 names %v, want group#member", mixed)
	}

	reach, err := Closure(model, wm, nil, start, []Object{mallory}, Options{Now: time.Unix(0, 0)})
	if err != nil {
		t.Fatalf("Closure: %v", err)
	}
	if reach.Exact {
		t.Error("the closure called itself exact over a mixed relation")
	}
	view, err := reach.Holds(object("document:roadmap"), "view")
	if err != nil {
		t.Fatalf("Holds view: %v", err)
	}
	if view != Yes {
		t.Errorf("coalition view = %s, want yes once the ban is lifted", view)
	}
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

// A write to the relation behind a shared name raises the permission of that
// name, and a delete lifts a ban read through it. Both are held to brute force.
func TestClosureOverASharedName(t *testing.T) {
	model := sharedNames(t)
	mallory := object("user:mallory")

	tests := []struct {
		name   string
		writes []*WriteRule
		start  []Relationship
	}{
		{
			name: "a write under the name",
			writes: []*WriteRule{
				{Resource: "document", Relation: "viewer", Operations: []Operation{Create}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Self: true}},
			},
			start: []Relationship{rel("document:d", "owner", "user:alice")},
		},
		{
			name: "a gate on a shared name",
			writes: []*WriteRule{
				{Resource: "document", Relation: "viewer", Operations: []Operation{Create}, Gate: Gate{Holds: "owner"}, Subject: SubjectSpec{Self: true}},
			},
			start: []Relationship{rel("document:d", "owner", "user:mallory")},
		},
		{
			name: "a ban lifted by deleting it",
			writes: []*WriteRule{
				{Resource: "document", Relation: "banned", Operations: []Operation{Delete}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Any: true}},
			},
			start: []Relationship{
				rel("document:d", "viewer", "user:mallory"),
				rel("document:d", "banned", "group:g#member"),
				rel("group:g", "member", "user:mallory"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wm := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: tt.writes}
			reach, err := Closure(model, wm, nil, tt.start, []Object{mallory}, Options{Now: time.Unix(0, 0)})
			if err != nil {
				t.Fatalf("Closure: %v", err)
			}
			if !reach.Exact {
				t.Fatalf("E1 holds for these writes, so the closure should be exact; mixed: %v", reach.Mixed)
			}
			assertSaturated(t, model, wm, nil, tt.start, []Object{mallory}, reach)
		})
	}
}

// gapModel is a folder a user views, a team a user is in, and a document that takes its
// view from its folder, its viewers, and its viewer teams, less the teams it bans.
func gapModel(t *testing.T) *Model {
	t.Helper()
	team := &Type{Name: "team", Relations: []*Relation{{Name: "member", Allowed: []Allowed{{Type: "user"}}}}}
	folder := &Type{
		Name:        "folder",
		Relations:   []*Relation{{Name: "viewer", Allowed: []Allowed{{Type: "user"}}}},
		Permissions: []*Permission{{Name: "view", Expr: Computed{Name: "viewer"}}},
	}
	document := &Type{
		Name: "document",
		Relations: []*Relation{
			{Name: "parent", Allowed: []Allowed{{Type: "folder"}}},
			{Name: "viewer", Allowed: []Allowed{{Type: "user"}, {Type: "team", Relation: "member"}}},
			{Name: "editor", Allowed: []Allowed{{Type: "user"}}},
			{Name: "banned", Allowed: []Allowed{{Type: "team", Relation: "member"}}},
		},
		Permissions: []*Permission{
			{Name: "view", Expr: Union{Children: []Expr{Computed{Name: "viewer"}, Arrow{Through: "parent", Target: "view"}}}},
			{Name: "edit", Expr: Computed{Name: "editor"}},
			{Name: "access", Expr: Exclusion{Base: Computed{Name: "view"}, Subtracted: []Expr{Computed{Name: "banned"}}}},
		},
	}
	m, err := NewModel([]*Type{{Name: "user"}, team, folder, document}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// A write can name an object the coalition does not own and still raise its access: a
// folder it views, a team it is in, a ban on a team it is in. Each is a move the write
// model allows, so leaving it out would miss the raise. Each case also says the category
// the raise is read as.
func TestAWriteNamingAnObjectTheCoalitionReachesRaises(t *testing.T) {
	vic := Object{Type: "user", ID: "vic"}
	rule := func(relation string, ops ...Operation) *WriteRule {
		return &WriteRule{Resource: "document", Relation: relation, Operations: ops, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Any: true}}
	}
	tests := []struct {
		name       string
		start      []Relationship
		rule       *WriteRule
		permission string
		category   Category
	}{
		{
			name:       "linking the document to a folder the coalition views",
			start:      []Relationship{rel("folder:shared", "viewer", "user:vic"), rel("document:roadmap", "editor", "user:olivia")},
			rule:       rule("parent", Create),
			permission: "view",
			category:   CategoryTransitiveGrant,
		},
		{
			name: "granting the document to a team the coalition is in",
			start: []Relationship{
				rel("team:design", "member", "user:vic"),
				rel("document:roadmap", "editor", "user:olivia"),
			},
			rule:       &WriteRule{Resource: "document", Relation: "viewer", Operations: []Operation{Create}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Types: []string{"team#member"}}},
			permission: "view",
			category:   CategoryDelegationNotNarrowed,
		},
		{
			name: "deleting the ban on a team the coalition is in",
			start: []Relationship{
				rel("team:design", "member", "user:vic"),
				rel("document:roadmap", "viewer", "user:vic"),
				{Resource: Object{Type: "document", ID: "roadmap"}, Relation: "banned", Subject: Subject{Object: Object{Type: "team", ID: "design"}, Relation: "member"}},
			},
			rule:       rule("banned", Delete),
			permission: "access",
			category:   CategoryFailOpenOnAbsence,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wm := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: []*WriteRule{tt.rule}}
			classified, err := Classify(gapModel(t), wm, nil, tt.start, []Object{vic}, Options{Now: time.Unix(0, 0)})
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, c := range classified {
				if c.Object.ID == "roadmap" && c.Permission == tt.permission {
					found = true
					if c.Category != tt.category {
						t.Errorf("the raise reads as %s, want %s", c.Category, tt.category)
					}
				}
			}
			if !found {
				t.Errorf("no raise of %s on the document: %+v", tt.permission, classified)
			}
		})
	}
}

// A tuple naming an object that is neither the coalition's nor a userset nor across an
// arrow grants or denies that object alone, so it is never a move: weighing it would cost
// the search and raise nothing.
func TestAWriteForAnotherUserIsNotAMove(t *testing.T) {
	wm := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: []*WriteRule{
		{Resource: "document", Relation: "editor", Operations: []Operation{Create}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Any: true}},
	}}
	model := gapModel(t)
	start := []Relationship{rel("document:roadmap", "editor", "user:olivia")}
	vic := Object{Type: "user", ID: "vic"}
	e := newEngine(model, wm, nil, start, []Object{vic}, Options{Now: time.Unix(0, 0)})
	checker := NewChecker(model, start, nil, time.Unix(0, 0))
	objects := []Object{vic}
	got, err := e.subjects(checker, wm.Writes[0], model.Type("document").Relation("editor"), Object{Type: "document", ID: "roadmap"}, vic, objects, e.domain(e.start, objects))
	if err != nil {
		t.Fatal(err)
	}
	if want := []writtenSubject{{subject: Subject{Object: vic}}}; !slices.Equal(got, want) {
		t.Errorf("subjects = %v, want the coalition alone %v", got, want)
	}
}

// A rule can let the writer name only a subject that holds a permission on the resource,
// adding an editor from among the viewers. It writes the subjects that hold it, and none
// that do not.
func TestASubjectThatHoldsAPermissionIsWritten(t *testing.T) {
	wm := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: []*WriteRule{
		{Resource: "document", Relation: "editor", Operations: []Operation{Create}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Holds: "view"}},
	}}
	vic := Object{Type: "user", ID: "vic"}
	raises := func(start []Relationship) bool {
		escalations, err := Escalations(gapModel(t), wm, nil, start, []Object{vic}, Options{Now: time.Unix(0, 0)})
		if err != nil {
			t.Fatal(err)
		}
		return slices.ContainsFunc(escalations, func(e Escalation) bool { return e.Object.ID == "roadmap" && e.Permission == "edit" })
	}
	if !raises([]Relationship{rel("document:roadmap", "viewer", "user:vic")}) {
		t.Error("a viewer the rule lets be made editor does not raise edit")
	}
	if raises([]Relationship{rel("document:roadmap", "viewer", "user:olivia")}) {
		t.Error("a subject that does not hold view is made editor")
	}
}

// A relation the schema admits only behind a caveat is written with it. When the rule
// leaves a parameter to the application, the grant waits on the check, so the raise is to
// conditional and not to yes. When the writer fills every parameter, the default, or the
// schema also admits the relation bare, the writer makes it hold.
func TestAWriteBehindACaveatTheApplicationFillsRaisesToConditional(t *testing.T) {
	model := func(bare bool) *Model {
		allowed := []Allowed{{Type: "user", Caveat: "ip"}}
		if bare {
			allowed = append(allowed, Allowed{Type: "user"})
		}
		document := &Type{
			Name:        "document",
			Relations:   []*Relation{{Name: "viewer", Allowed: allowed}},
			Permissions: []*Permission{{Name: "view", Expr: Computed{Name: "viewer"}}},
		}
		m, err := NewModel([]*Type{{Name: "user"}, document}, []*Caveat{{Name: "ip", Parameters: []Parameter{{Name: "addr", Type: "string"}}}})
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	rule := func(filler Filler) *WriteModel {
		return &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: []*WriteRule{{
			Resource: "document", Relation: "viewer", Operations: []Operation{Create}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Self: true},
			Caveats: []CaveatWrite{{Name: "ip", Parameters: map[string]Filler{"addr": filler}}},
		}}}
	}
	tests := []struct {
		name     string
		bare     bool
		filler   Filler
		expected Level
	}{
		{name: "the application fills it", filler: FillerApplication, expected: Conditional},
		{name: "the writer fills it", filler: FillerWriter, expected: Yes},
		{name: "the schema also admits it bare", bare: true, filler: FillerApplication, expected: Yes},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			start := []Relationship{rel("document:roadmap", "viewer", "user:olivia")}
			escalations, err := Escalations(model(tt.bare), rule(tt.filler), stubCaveats{}, start, []Object{{Type: "user", ID: "vic"}}, Options{Now: time.Unix(0, 0)})
			if err != nil {
				t.Fatal(err)
			}
			if len(escalations) != 1 || escalations[0].After != tt.expected {
				t.Errorf("escalations = %+v, want one raise of view to %s", escalations, tt.expected)
			}
		})
	}
}

// A coalition that joins an object the object under attack reads across an arrow, an org
// whose members view its documents, raises the document. The rows that tell kinds of write
// apart do not name that one, and the raise is still reported, as taking on what the
// joined object passes on.
func TestJoiningWhatAnArrowReadsIsReported(t *testing.T) {
	org := &Type{Name: "org", Relations: []*Relation{{Name: "member", Allowed: []Allowed{{Type: "user"}}}}}
	document := &Type{
		Name:        "document",
		Relations:   []*Relation{{Name: "org", Allowed: []Allowed{{Type: "org"}}}},
		Permissions: []*Permission{{Name: "view", Expr: Arrow{Through: "org", Target: "member"}}},
	}
	model, err := NewModel([]*Type{{Name: "user"}, org, document}, nil)
	if err != nil {
		t.Fatal(err)
	}
	wm := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: []*WriteRule{
		{Resource: "org", Relation: "member", Operations: []Operation{Create}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Self: true}},
	}}
	sample := Sample{Model: model, Relationships: []Relationship{rel("document:roadmap", "org", "org:acme")}, Now: time.Unix(0, 0)}
	if !slices.ContainsFunc(Run(sample, wm), func(m Match) bool {
		return m.PatternID == "PTD-ZAN-005" && m.Raise.Type == "document" && m.Raise.Permission == "view"
	}) {
		t.Errorf("joining the org a document reads is not reported: %+v", Run(sample, wm))
	}
}

// A subject held to a permission is read the way a gate is: a viewer behind a caveat the
// coalition may meet holds view, so the rule lets it be made editor.
func TestASubjectThatHoldsAPermissionBehindACaveatIsWritten(t *testing.T) {
	document := &Type{
		Name: "document",
		Relations: []*Relation{
			{Name: "viewer", Allowed: []Allowed{{Type: "user", Caveat: "open"}}},
			{Name: "editor", Allowed: []Allowed{{Type: "user"}}},
		},
		Permissions: []*Permission{
			{Name: "view", Expr: Computed{Name: "viewer"}},
			{Name: "edit", Expr: Computed{Name: "editor"}},
		},
	}
	model, err := NewModel([]*Type{{Name: "user"}, document}, []*Caveat{{Name: "open", Parameters: []Parameter{{Name: "x", Type: "int"}}}})
	if err != nil {
		t.Fatal(err)
	}
	wm := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: []*WriteRule{
		{Resource: "document", Relation: "editor", Operations: []Operation{Create}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Holds: "view"}},
	}}
	viewer := rel("document:roadmap", "viewer", "user:vic")
	viewer.Caveat = &CaveatUse{Name: "open"}
	escalations, err := Escalations(model, wm, stubCaveats{}, []Relationship{viewer}, []Object{{Type: "user", ID: "vic"}}, Options{Now: time.Unix(0, 0)})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(escalations, func(e Escalation) bool { return e.Permission == "edit" }) {
		t.Errorf("a viewer behind a caveat is not made editor: %+v", escalations)
	}
}

// A delete a rule allows is still only a move when the tuple can matter to the coalition,
// and a holds constraint on the subject holds for a delete as for a write.
func TestWhichDeletesAreMoves(t *testing.T) {
	model := gapModel(t)
	vic := Object{Type: "user", ID: "vic"}
	start := []Relationship{
		rel("document:roadmap", "viewer", "user:olivia"),
		rel("document:roadmap", "viewer", "user:vic"),
		rel("document:roadmap", "parent", "folder:shared"),
		{Resource: Object{Type: "document", ID: "roadmap"}, Relation: "banned", Subject: Subject{Object: Object{Type: "team", ID: "design"}, Relation: "member"}},
	}
	e := newEngine(model, &WriteModel{}, nil, start, []Object{vic}, Options{Now: time.Unix(0, 0)})
	checker := NewChecker(model, start, nil, time.Unix(0, 0))
	tests := []struct {
		name     string
		spec     SubjectSpec
		tuple    Relationship
		expected bool
	}{
		{name: "another user", spec: SubjectSpec{Any: true}, tuple: start[0]},
		{name: "the coalition", spec: SubjectSpec{Any: true}, tuple: start[1], expected: true},
		{name: "an object across an arrow", spec: SubjectSpec{Any: true}, tuple: start[2], expected: true},
		{name: "a userset", spec: SubjectSpec{Any: true}, tuple: start[3], expected: true},
		{name: "a subject that holds view", spec: SubjectSpec{Holds: "view"}, tuple: start[1], expected: true},
		{name: "a subject that does not hold edit", spec: SubjectSpec{Holds: "edit"}, tuple: start[1]},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := e.mayDelete(checker, tt.spec, tt.tuple, []Object{vic})
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.expected {
				t.Errorf("mayDelete(%s) = %v, want %v", tt.tuple, got, tt.expected)
			}
		})
	}
}
