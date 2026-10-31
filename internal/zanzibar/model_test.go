package zanzibar

import (
	"strings"
	"testing"
)

// A name declared twice makes every later lookup a coin toss, so the model
// refuses it wherever it happens.
func TestNewModelRefusesANameDeclaredTwice(t *testing.T) {
	tests := []struct {
		name    string
		types   []*Type
		caveats []*Caveat
		want    string
	}{
		{
			name:  "type",
			types: []*Type{{Name: "user"}, {Name: "user"}},
			want:  "type user declared twice",
		},
		{
			name: "relation and permission",
			types: []*Type{{
				Name:        "doc",
				Relations:   []*Relation{{Name: "view"}},
				Permissions: []*Permission{{Name: "view", Expr: Nil{}}},
			}},
			want: "doc#view declared twice",
		},
		{
			name:    "caveat",
			caveats: []*Caveat{{Name: "weekday"}, {Name: "weekday"}},
			want:    "caveat weekday declared twice",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewModel(tt.types, tt.caveats)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("NewModel() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestModelLooksUpByName(t *testing.T) {
	doc := &Type{
		Name:        "doc",
		Relations:   []*Relation{{Name: "owner", Allowed: []Allowed{{Type: "user"}}}},
		Permissions: []*Permission{{Name: "edit", Expr: Computed{Name: "owner"}}},
	}
	m, err := NewModel([]*Type{{Name: "user"}, doc}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if m.Type("doc") != doc || m.Type("folder") != nil {
		t.Error("Type() does not look up by name")
	}
	if doc.Relation("owner") == nil || doc.Relation("edit") != nil {
		t.Error("Relation() answers for a permission, or not for a relation")
	}
	if doc.Permission("edit") == nil || doc.Permission("owner") != nil {
		t.Error("Permission() answers for a relation, or not for a permission")
	}
}

// sharedNames is a schema of a product that keeps one name for what is written
// and what is asked, as OpenFGA does: a relation and a permission of one name,
// the permission reading the relation with Stored. member is written directly
// and also held through admin; viewer is written directly, held through owner
// and through the parent folder, and subtracted by banned. parent is only walked
// and banned is only subtracted, so they stay relations alone, what a schema that
// separates the two would declare.
func sharedNames(t *testing.T) *Model {
	t.Helper()
	team := &Type{
		Name:        "team",
		Relations:   []*Relation{{Name: "lead", Allowed: []Allowed{{Type: "user"}}}},
		Permissions: []*Permission{{Name: "lead", Expr: Stored{Name: "lead"}}},
	}
	group := &Type{
		Name: "group",
		Relations: []*Relation{
			{Name: "admin", Allowed: []Allowed{{Type: "user"}}},
			{Name: "member", Allowed: []Allowed{{Type: "user"}, {Type: "team", Relation: "lead"}}},
		},
		Permissions: []*Permission{
			{Name: "admin", Expr: Stored{Name: "admin"}},
			{Name: "member", Expr: Union{Children: []Expr{Stored{Name: "member"}, Computed{Name: "admin"}}}},
		},
	}
	folder := &Type{
		Name:        "folder",
		Relations:   []*Relation{{Name: "viewer", Allowed: []Allowed{{Type: "user"}}}},
		Permissions: []*Permission{{Name: "viewer", Expr: Stored{Name: "viewer"}}},
	}
	document := &Type{
		Name: "document",
		Relations: []*Relation{
			{Name: "parent", Allowed: []Allowed{{Type: "folder"}}},
			{Name: "owner", Allowed: []Allowed{{Type: "user"}}},
			{Name: "banned", Allowed: []Allowed{{Type: "group", Relation: "member"}}},
			{Name: "viewer", Allowed: []Allowed{
				{Type: "user"},
				{Type: "group", Relation: "member"},
				{Type: "user", Wildcard: true},
			}},
		},
		Permissions: []*Permission{
			{Name: "owner", Expr: Stored{Name: "owner"}},
			{Name: "viewer", Expr: Exclusion{
				Base: Union{Children: []Expr{
					Stored{Name: "viewer"},
					Computed{Name: "owner"},
					Arrow{Through: "parent", Target: "viewer"},
				}},
				Subtracted: []Expr{Computed{Name: "banned"}},
			}},
		},
	}
	m, err := NewModel([]*Type{{Name: "user"}, team, group, folder, document}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// A relation and a permission may share a name only when the permission reads
// that relation, which is what makes the two one thing. Stored reaches a
// relation of the type and nothing else, so a name it cannot find is refused
// here rather than read as a relation nobody writes.
func TestNewModelLetsAPermissionShareTheNameOfWhatItReads(t *testing.T) {
	tests := []struct {
		name string
		doc  *Type
		want string
	}{
		{
			name: "read at the top",
			doc: &Type{
				Name:        "doc",
				Relations:   []*Relation{{Name: "view", Allowed: []Allowed{{Type: "user"}}}},
				Permissions: []*Permission{{Name: "view", Expr: Stored{Name: "view"}}},
			},
		},
		{
			name: "read under an exclusion",
			doc: &Type{
				Name: "doc",
				Relations: []*Relation{
					{Name: "view", Allowed: []Allowed{{Type: "user"}}},
					{Name: "ban", Allowed: []Allowed{{Type: "user"}}},
				},
				Permissions: []*Permission{{Name: "view", Expr: Exclusion{
					Base:       Union{Children: []Expr{Stored{Name: "view"}}},
					Subtracted: []Expr{Computed{Name: "ban"}},
				}}},
			},
		},
		{
			name: "another relation is read",
			doc: &Type{
				Name: "doc",
				Relations: []*Relation{
					{Name: "view", Allowed: []Allowed{{Type: "user"}}},
					{Name: "other", Allowed: []Allowed{{Type: "user"}}},
				},
				Permissions: []*Permission{{Name: "view", Expr: Stored{Name: "other"}}},
			},
			want: "doc#view declared twice",
		},
		{
			name: "nothing of that name is stored",
			doc: &Type{
				Name:        "doc",
				Permissions: []*Permission{{Name: "view", Expr: Stored{Name: "view"}}},
			},
			want: "doc#view reads doc#view as stored, and no relation of that name is declared",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewModel([]*Type{{Name: "user"}, tt.doc}, nil)
			switch {
			case tt.want == "" && err != nil:
				t.Errorf("NewModel() error = %v", err)
			case tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)):
				t.Errorf("NewModel() error = %v, want %q", err, tt.want)
			}
		})
	}
}
