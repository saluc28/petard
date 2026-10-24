package zanzibar

import (
	"slices"
	"testing"
	"time"
)

// categoriesOn returns the categories of the classified escalations on an
// object and permission.
func categoriesOn(cs []ClassifiedEscalation, object Object, permission string) []Category {
	var out []Category
	for _, c := range cs {
		if c.Object == object && c.Permission == permission {
			out = append(out, c.Category)
		}
	}
	return out
}

func TestClassify(t *testing.T) {
	// A team whose members a document grants view to, for ASSUMABLE-IDENTITY.
	teamDocuments := func(t *testing.T) *Model {
		t.Helper()
		team := &Type{Name: "team", Relations: []*Relation{{Name: "member", Allowed: []Allowed{{Type: "user"}}}}}
		document := &Type{
			Name:        "document",
			Relations:   []*Relation{{Name: "owner", Allowed: []Allowed{{Type: "user"}}}, {Name: "viewer", Allowed: []Allowed{{Type: "user"}, {Type: "team", Relation: "member"}}}},
			Permissions: []*Permission{{Name: "view", Expr: Union{Children: []Expr{Computed{Name: "viewer"}, Computed{Name: "owner"}}}}},
		}
		m, err := NewModel([]*Type{{Name: "user"}, team, document}, nil)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	// manage gates writing owner, for SPLIT-GRANT.
	managed := func(t *testing.T) *Model {
		t.Helper()
		doc := &Type{
			Name:        "doc",
			Relations:   []*Relation{{Name: "manager", Allowed: []Allowed{{Type: "user"}}}, {Name: "owner", Allowed: []Allowed{{Type: "user"}}}},
			Permissions: []*Permission{{Name: "manage", Expr: Computed{Name: "manager"}}, {Name: "own", Expr: Computed{Name: "owner"}}},
		}
		m, err := NewModel([]*Type{{Name: "user"}, doc}, nil)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	// view = viewer - banned, for FAIL-OPEN-ON-ABSENCE.
	banning := func(t *testing.T) *Model {
		t.Helper()
		doc := &Type{
			Name:        "doc",
			Relations:   []*Relation{{Name: "viewer", Allowed: []Allowed{{Type: "user"}}}, {Name: "banned", Allowed: []Allowed{{Type: "user"}}}},
			Permissions: []*Permission{{Name: "view", Expr: Exclusion{Base: Computed{Name: "viewer"}, Subtracted: []Expr{Computed{Name: "banned"}}}}},
		}
		m, err := NewModel([]*Type{{Name: "user"}, doc}, nil)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}

	tests := []struct {
		name      string
		model     *Model
		writes    []*WriteRule
		creates   []*CreationRule
		start     []Relationship
		coalition []Object
		object    Object
		perm      string
		want      Category
	}{
		{
			name:      "attr self write",
			model:     documents(t),
			writes:    []*WriteRule{{Resource: "document", Relation: "viewer", Operations: []Operation{Create}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Self: true}}},
			start:     []Relationship{rel("document:roadmap", "owner", "user:olivia")},
			coalition: []Object{object("user:mallory")},
			object:    object("document:roadmap"),
			perm:      "view",
			want:      CategoryAttrSelfWrite,
		},
		{
			name:      "split grant",
			model:     managed(t),
			writes:    []*WriteRule{{Resource: "doc", Relation: "owner", Operations: []Operation{Create}, Gate: Gate{Holds: "manage"}, Subject: SubjectSpec{Self: true}}},
			start:     []Relationship{rel("doc:x", "manager", "user:mallory")},
			coalition: []Object{object("user:mallory")},
			object:    object("doc:x"),
			perm:      "own",
			want:      CategorySplitGrant,
		},
		{
			name:      "global switch",
			model:     documents(t),
			writes:    []*WriteRule{{Resource: "document", Relation: "viewer", Operations: []Operation{Create}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Any: true}, Wildcard: true}},
			start:     []Relationship{rel("document:roadmap", "owner", "user:olivia")},
			coalition: []Object{object("user:mallory")},
			object:    object("document:roadmap"),
			perm:      "view",
			want:      CategoryGlobalSwitch,
		},
		{
			name:      "transitive grant",
			model:     recursiveFolders(t),
			writes:    []*WriteRule{{Resource: "folder", Relation: "parent", Operations: []Operation{Create}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Types: []string{"folder"}}}},
			start:     []Relationship{rel("folder:evil", "viewer", "user:mallory"), rel("folder:target", "viewer", "user:olivia")},
			coalition: []Object{object("user:mallory"), object("folder:evil")},
			object:    object("folder:target"),
			perm:      "view",
			want:      CategoryTransitiveGrant,
		},
		{
			name:      "assumable identity",
			model:     teamDocuments(t),
			writes:    []*WriteRule{{Resource: "team", Relation: "member", Operations: []Operation{Create}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Self: true}}},
			start:     []Relationship{rel("document:roadmap", "viewer", "team:design#member"), rel("document:roadmap", "owner", "user:olivia")},
			coalition: []Object{object("user:mallory")},
			object:    object("document:roadmap"),
			perm:      "view",
			want:      CategoryAssumableIdentity,
		},
		{
			name:      "delegation not narrowed",
			model:     documents(t),
			writes:    []*WriteRule{{Resource: "document", Relation: "editor", Operations: []Operation{Create}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Types: []string{"user"}}}},
			creates:   []*CreationRule{{Creates: "user", Gate: Gate{Anyone: true}}},
			start:     []Relationship{rel("document:roadmap", "owner", "user:olivia")},
			coalition: []Object{object("user:mallory")},
			object:    object("document:roadmap"),
			perm:      "edit",
			want:      CategoryDelegationNotNarrowed,
		},
		{
			name:      "fail open on absence",
			model:     banning(t),
			writes:    []*WriteRule{{Resource: "doc", Relation: "banned", Operations: []Operation{Delete}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Self: true}}},
			start:     []Relationship{rel("doc:x", "viewer", "user:mallory"), rel("doc:x", "banned", "user:mallory")},
			coalition: []Object{object("user:mallory")},
			object:    object("doc:x"),
			perm:      "view",
			want:      CategoryFailOpenOnAbsence,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wm := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: tt.writes, Creates: tt.creates}
			cs, err := Classify(tt.model, wm, nil, tt.start, tt.coalition, Options{Now: time.Unix(0, 0)})
			if err != nil {
				t.Fatalf("Classify: %v", err)
			}
			got := categoriesOn(cs, tt.object, tt.perm)
			if !slices.Contains(got, tt.want) {
				t.Errorf("categories on %s#%s = %v, want %s among them", tt.object, tt.perm, got, tt.want)
			}
		})
	}
}

// A created object is one a creation made on the witness, not one whose
// identifier happens to start the way createdID writes them. An input object
// named like a synthetic one must not be taken for the coalition's, or a write
// of it would be classified as a self-write it is not.
func TestControlsRecognizesCreatedObjectsByTheWitnessNotTheName(t *testing.T) {
	e := &engine{coalition: []Object{object("user:mallory")}}
	writer := Subject{Object: object("user:mallory")}

	made := object("folder:created-0")
	witness := []move{{creates: &CreationRule{Creates: "folder"}, created: made}}
	if !e.controls(Subject{Object: made}, writer, createdObjects(witness)) {
		t.Error("an object a creation made on the witness should be controlled")
	}

	lookalike := object("user:created-0")
	if e.controls(Subject{Object: lookalike}, writer, createdObjects(nil)) {
		t.Error("an input object named created-0 that no creation made must not be controlled")
	}
}

// classify reads what the writer held with a check, and a check can fail. A
// decisive write that names a relation the model does not declare makes it
// fail; such an escalation is one the search would never produce, built here by
// hand to prove the error travels out rather than being read as "not a
// delegation".
func TestClassifyPropagatesACheckError(t *testing.T) {
	m, err := NewModel([]*Type{
		{Name: "user"},
		{Name: "doc", Relations: []*Relation{{Name: "editor", Allowed: []Allowed{{Type: "user"}}}}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine(m, &WriteModel{SchemaVersion: 1, Kind: "relationship-writes"}, nil, nil,
		[]Object{object("user:mallory")}, Options{Now: time.Unix(0, 0)})

	// doc#undeclared is not in the model, so the writer check returns an error.
	// The subject is not the writer, so the delegation case is the one reached.
	decisive := WriteStep{
		Relationship: rel("doc:x", "undeclared", "user:victim"),
		Writer:       Subject{Object: object("user:mallory")},
	}
	esc := Escalation{
		Object:     object("doc:x"),
		Permission: "edit",
		Writes:     []WriteStep{decisive},
		moves:      []move{{rel: decisive.Relationship, writer: decisive.Writer}},
	}
	if _, _, _, err := e.classify(esc); err == nil {
		t.Error("classify should return the check error, not swallow it")
	}
}

// rolebindingRBAC is a minimal user-defined-roles schema: a role carries a
// permission through a wildcard relation, a binding ties a bearer to a role,
// and an org reads a binding through `granted`. It is the shape every
// RBAC-via-rolebinding SpiceDB schema shares, reduced to what an escalation
// turns on, so the test is about the create-and-link path and not one repo.
func rolebindingRBAC(t *testing.T) *Model {
	t.Helper()
	role := &Type{Name: "role", Relations: []*Relation{
		{Name: "admin_perm", Allowed: []Allowed{{Type: "user", Wildcard: true}}},
		{Name: "pm_perm", Allowed: []Allowed{{Type: "user", Wildcard: true}}},
	}}
	binding := &Type{Name: "binding",
		Relations: []*Relation{
			{Name: "bearer", Allowed: []Allowed{{Type: "user"}}},
			{Name: "role", Allowed: []Allowed{{Type: "role"}}},
		},
		Permissions: []*Permission{
			{Name: "administer", Expr: Intersection{Children: []Expr{Computed{Name: "bearer"}, Arrow{Through: "role", Target: "admin_perm"}}}},
			{Name: "policymanage", Expr: Intersection{Children: []Expr{Computed{Name: "bearer"}, Arrow{Through: "role", Target: "pm_perm"}}}},
		},
	}
	org := &Type{Name: "org",
		Relations: []*Relation{{Name: "granted", Allowed: []Allowed{{Type: "binding"}}}},
		Permissions: []*Permission{
			{Name: "update", Expr: Arrow{Through: "granted", Target: "administer"}},
			{Name: "policymanage", Expr: Union{Children: []Expr{Arrow{Through: "granted", Target: "administer"}, Arrow{Through: "granted", Target: "policymanage"}}}},
		},
	}
	m, err := NewModel([]*Type{{Name: "user"}, role, binding, org}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// A coalition that starts holding policymanage on an org, writing only what the
// write model allows, can create a binding to the admin role and link the org
// to it with a `granted` write, raising org#update it did not hold. The raise
// takes three writes, and the witness can leave a setup creation (binding#role)
// last, so the positional decisive write is a creation. The escalation is still
// real, and its category is read from the `granted` rule write that links the
// pre-existing org to the controlled binding: a transitive grant. Before the
// classifier looked past a trailing creation, this escalation was found and
// then dropped, a permission raise the run stayed silent on.
func TestClassifyLinksThroughATrailingCreation(t *testing.T) {
	model := rolebindingRBAC(t)
	wm := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes",
		Creates: []*CreationRule{{
			Creates: "binding",
			Gate:    Gate{Anyone: true},
			On:      []OnSpec{{Type: "role", Gate: Gate{Anyone: true}}},
			Writes: []CreationWrite{
				{Resource: CreatedPlaceholder, Relation: "bearer", Subject: CreatorPlaceholder},
				{Resource: CreatedPlaceholder, Relation: "role", Subject: "role"},
			},
		}},
		Writes: []*WriteRule{{
			Resource: "org", Relation: "granted", Operations: []Operation{Create, Touch},
			Gate: Gate{Holds: "policymanage"}, Subject: SubjectSpec{Types: []string{"binding"}},
		}},
	}
	// The attacker is a policy manager: bound to a role that carries only
	// policymanage. The admin role is present for the attacker to bind itself to.
	start := []Relationship{
		rel("role:admin", "admin_perm", "user:*"),
		rel("role:pm", "pm_perm", "user:*"),
		rel("binding:b_att", "bearer", "user:attacker"),
		rel("binding:b_att", "role", "role:pm"),
		rel("org:o", "granted", "binding:b_att"),
	}
	coalition := []Object{object("user:attacker")}

	cs, err := Classify(model, wm, nil, start, coalition, Options{Now: time.Unix(0, 0)})
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}

	cats := categoriesOn(cs, object("org:o"), "update")
	if !slices.Contains(cats, CategoryTransitiveGrant) {
		t.Fatalf("org:o#update: want a %s finding, got %v", CategoryTransitiveGrant, cats)
	}

	// The category rests on the granted link, not on the trailing creation.
	var found bool
	for _, c := range cs {
		if c.Object != object("org:o") || c.Permission != "update" || c.Category != CategoryTransitiveGrant {
			continue
		}
		found = true
		dw := c.DecisiveWrite
		if dw.Creation != nil || dw.Rule == nil || dw.Relationship.Resource.Type != "org" || dw.Relationship.Relation != "granted" {
			t.Errorf("decisive write = %+v, want the org#granted rule write", dw)
		}
	}
	if !found {
		t.Fatal("no TRANSITIVE-GRANT escalation on org:o#update to inspect")
	}
}
