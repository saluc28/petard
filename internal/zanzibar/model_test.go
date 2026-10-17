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
