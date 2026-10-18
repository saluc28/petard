package zanzibar

import (
	"slices"
	"testing"
)

// polaritySchema is a schema with a relation in each position: editor only
// positive, banned only negative, owner in both (positive in view, negative in
// audit), parent positive through an any arrow and mixed through an all arrow.
func polaritySchema(t *testing.T) *Model {
	t.Helper()
	document := &Type{
		Name: "document",
		Relations: []*Relation{
			{Name: "owner", Allowed: []Allowed{{Type: "user"}}},
			{Name: "editor", Allowed: []Allowed{{Type: "user"}}},
			{Name: "banned", Allowed: []Allowed{{Type: "user"}}},
		},
		Permissions: []*Permission{
			{Name: "edit", Expr: Union{Children: []Expr{Computed{Name: "owner"}, Computed{Name: "editor"}}}},
			{Name: "view", Expr: Exclusion{Base: Computed{Name: "edit"}, Subtracted: []Expr{Computed{Name: "banned"}}}},
			{Name: "audit", Expr: Exclusion{Base: Computed{Name: "view"}, Subtracted: []Expr{Computed{Name: "owner"}}}},
		},
	}
	folder := &Type{
		Name: "folder",
		Relations: []*Relation{
			{Name: "parent", Allowed: []Allowed{{Type: "folder"}}},
			{Name: "viewer", Allowed: []Allowed{{Type: "user"}}},
		},
		Permissions: []*Permission{
			{Name: "view", Expr: Union{Children: []Expr{Computed{Name: "viewer"}, Arrow{Through: "parent", Target: "view"}}}},
			{Name: "strict", Expr: Arrow{Through: "parent", Target: "view", All: true}},
		},
	}
	m, err := NewModel([]*Type{{Name: "user"}, document, folder}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestPolarities(t *testing.T) {
	p := analyzePolarities(polaritySchema(t), nil)

	tests := []struct {
		typ, relation           string
		pos, neg, mixedAll, mix bool
	}{
		{"document", "editor", true, false, false, false},
		{"document", "banned", false, true, false, false},
		{"document", "owner", true, true, false, true},
		{"folder", "viewer", true, false, false, false},
		{"folder", "parent", true, false, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.typ+"#"+tt.relation, func(t *testing.T) {
			o := p.at(relKey{Type: tt.typ, Relation: tt.relation})
			if o.pos != tt.pos || o.neg != tt.neg || o.mixedAll != tt.mixedAll {
				t.Errorf("occurrence = %+v, want pos=%v neg=%v mixedAll=%v", o, tt.pos, tt.neg, tt.mixedAll)
			}
			if o.mixed() != tt.mix {
				t.Errorf("mixed = %v, want %v", o.mixed(), tt.mix)
			}
		})
	}
}

// A gate counts as a positive occurrence, so a relation only otherwise negative
// becomes mixed once a gate reads it.
func TestPolaritiesGateCounts(t *testing.T) {
	m := polaritySchema(t)
	wm := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: []*WriteRule{
		// A gate that holds document#banned turns banned, otherwise negative
		// only, into a relation that also occurs positively.
		{Resource: "document", Relation: "editor", Operations: []Operation{Create}, Gate: Gate{Holds: "banned"}, Subject: SubjectSpec{Self: true}},
	}}
	p := analyzePolarities(m, wm)
	o := p.at(relKey{Type: "document", Relation: "banned"})
	if !o.pos || !o.neg || !o.mixed() {
		t.Errorf("banned with a gate on it = %+v, want positive, negative and mixed", o)
	}
}

func TestCheckE1(t *testing.T) {
	m := polaritySchema(t)
	write := func(resource, relation string, ops ...Operation) *WriteRule {
		return &WriteRule{Resource: resource, Relation: relation, Operations: ops, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Self: true}}
	}

	tests := []struct {
		name      string
		writes    []*WriteRule
		wantOK    bool
		wantMixed []string
	}{
		{
			name:   "only positive and negative relations are writable",
			writes: []*WriteRule{write("document", "editor", Create), write("document", "banned", Delete)},
			wantOK: true,
		},
		{
			name:      "a mixed relation is writable",
			writes:    []*WriteRule{write("document", "owner", Create)},
			wantOK:    false,
			wantMixed: []string{"document#owner (occurs in both polarities)"},
		},
		{
			name:      "the walked relation of an all arrow is writable",
			writes:    []*WriteRule{write("folder", "parent", Create)},
			wantOK:    false,
			wantMixed: []string{"folder#parent (walked by an all arrow)"},
		},
		{
			name:   "a mixed relation with no write rule does not break E1",
			writes: []*WriteRule{write("document", "editor", Touch)},
			wantOK: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wm := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: tt.writes}
			ok, mixed := CheckE1(m, wm)
			if ok != tt.wantOK {
				t.Errorf("CheckE1 ok = %v, want %v (mixed: %v)", ok, tt.wantOK, mixed)
			}
			var got []string
			for _, mr := range mixed {
				got = append(got, mr.String())
			}
			slices.Sort(got)
			slices.Sort(tt.wantMixed)
			if !slices.Equal(got, tt.wantMixed) {
				t.Errorf("mixed = %v, want %v", got, tt.wantMixed)
			}
		})
	}
}
