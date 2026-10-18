package zanzibar

import (
	"slices"
	"testing"
)

func TestCheckE2(t *testing.T) {
	// A schema with a folder that can hold a parent folder, a document with an
	// owner and a banned relation that view subtracts.
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
	document := &Type{
		Name: "document",
		Relations: []*Relation{
			{Name: "owner", Allowed: []Allowed{{Type: "user"}}},
			{Name: "banned", Allowed: []Allowed{{Type: "user"}}},
		},
		Permissions: []*Permission{
			{Name: "view", Expr: Exclusion{Base: Computed{Name: "owner"}, Subtracted: []Expr{Computed{Name: "banned"}}}},
		},
	}
	model, err := NewModel([]*Type{{Name: "user"}, folder, document}, nil)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		creates    []*CreationRule
		wantOK     bool
		wantFailed []string
	}{
		{
			name: "a flat creation holds E2",
			creates: []*CreationRule{{Creates: "document", Gate: Gate{Anyone: true}, Writes: []CreationWrite{
				{Resource: CreatedPlaceholder, Relation: "owner", Subject: CreatorPlaceholder},
			}}},
			wantOK: true,
		},
		{
			name: "a folder created inside a folder is recursive",
			creates: []*CreationRule{{Creates: "folder", Gate: Gate{Anyone: true}, On: []OnSpec{{Type: "folder", Gate: Gate{Anyone: true}}}, Writes: []CreationWrite{
				{Resource: CreatedPlaceholder, Relation: "parent", Subject: "folder"},
			}}},
			wantOK:     false,
			wantFailed: []string{"creation of folder (recursive)"},
		},
		{
			name: "a creation that writes a negative tuple fails E2",
			creates: []*CreationRule{{Creates: "document", Gate: Gate{Anyone: true}, Writes: []CreationWrite{
				{Resource: CreatedPlaceholder, Relation: "owner", Subject: CreatorPlaceholder},
				{Resource: CreatedPlaceholder, Relation: "banned", Subject: CreatorPlaceholder},
			}}},
			wantOK:     false,
			wantFailed: []string{"creation of document (writes the negative relation document#banned)"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wm := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Creates: tt.creates}
			ok, failures := CheckE2(model, wm)
			if ok != tt.wantOK {
				t.Errorf("CheckE2 ok = %v, want %v (failures: %v)", ok, tt.wantOK, failures)
			}
			var got []string
			for _, f := range failures {
				got = append(got, f.String())
			}
			slices.Sort(got)
			slices.Sort(tt.wantFailed)
			if !slices.Equal(got, tt.wantFailed) {
				t.Errorf("failures = %v, want %v", got, tt.wantFailed)
			}
		})
	}
}
