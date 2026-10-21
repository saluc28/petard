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
