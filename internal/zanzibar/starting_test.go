package zanzibar

import (
	"slices"
	"testing"
	"time"
)

var attacker = Object{Type: "user", ID: "attacker"}

// holdsOn is the level the attacker reaches for a name on an object over a set
// of tuples, the independent reading a starting position is checked against.
func holdsOn(t *testing.T, model *Model, tuples []Relationship, obj Object, name string) Level {
	t.Helper()
	result, err := NewChecker(model, tuples, nil, time.Unix(0, 0)).Check(obj, name, Subject{Object: attacker}, nil)
	if err != nil {
		t.Fatalf("Check %s#%s: %v", obj, name, err)
	}
	return result.Level
}

// Every starting position must do what it claims: the attacker holds the target
// on the object over the position's tuples, and the set is minimal, so dropping
// any one tuple drops the grant. The checker reads this independently of the
// generator, which is the test oracle for the starting states.
func TestStartingPositionsGrantAndMinimal(t *testing.T) {
	schemas := map[string]*Model{
		"documents": documents(t),
		"folders":   recursiveFolders(t),
	}
	for name, model := range schemas {
		t.Run(name, func(t *testing.T) {
			positions := StartingPositions(model, attacker, Options{})
			if len(positions) == 0 {
				t.Fatal("no starting positions generated")
			}
			for _, p := range positions {
				full := holdsOn(t, model, p.Tuples, p.Object, p.Target)
				if full == No {
					t.Errorf("%s does not grant its target: %v", p, keysOf(p.Tuples))
					continue
				}
				for i := range p.Tuples {
					without := slices.Concat(p.Tuples[:i:i], p.Tuples[i+1:])
					if holdsOn(t, model, without, p.Object, p.Target) >= full {
						t.Errorf("%s is not minimal: dropping %s keeps the grant", p, p.Tuples[i])
					}
				}
			}
		})
	}
}

func TestStartingPositionsContent(t *testing.T) {
	model := documents(t)
	positions := StartingPositions(model, attacker, Options{})

	// Group the sets generated for each target by a sorted signature.
	byTarget := map[string][][]string{}
	for _, p := range positions {
		if p.Object.Type != "document" {
			continue
		}
		keys := keysOf(p.Tuples)
		slices.Sort(keys)
		byTarget[p.Target] = append(byTarget[p.Target], keys)
	}

	tests := []struct {
		target string
		want   [][]string
	}{
		{
			target: "owner",
			want:   [][]string{{"document:target#owner@user:attacker"}},
		},
		{
			target: "viewer",
			want: [][]string{
				{"document:target#viewer@user:attacker"},
				{"document:target#viewer@user:*"},
				{"document:target#viewer@team:aux-0#member", "team:aux-0#member@user:attacker"},
			},
		},
		{
			target: "view",
			want: [][]string{
				{"document:target#viewer@user:attacker"},
				{"document:target#viewer@user:*"},
				{"document:target#viewer@team:aux-0#member", "team:aux-0#member@user:attacker"},
				{"document:target#owner@user:attacker"},
				{"document:target#editor@user:attacker"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.target, func(t *testing.T) {
			got := byTarget[tt.target]
			if !sameSets(got, tt.want) {
				t.Errorf("sets for %s =\n %v\nwant\n %v", tt.target, got, tt.want)
			}
		})
	}
}

// A recursive permission is unfolded to the depth bound, and the positions for
// it say the bound was reached.
func TestStartingPositionsDepthBound(t *testing.T) {
	model := recursiveFolders(t)
	positions := StartingPositions(model, attacker, Options{StartingDepth: 2})

	var views []StartingPosition
	for _, p := range positions {
		if p.Target == "view" {
			views = append(views, p)
		}
	}
	if len(views) < 3 {
		t.Fatalf("got %d view positions, want at least 3 (direct and two levels of parent)", len(views))
	}
	for _, p := range views {
		if p.Depth != 2 {
			t.Errorf("%s depth = %d, want 2", p, p.Depth)
		}
		if !p.Truncated {
			t.Errorf("%s should be marked truncated: the parent chain is deeper than the bound", p)
		}
	}
	// The deepest set follows parent twice before reaching a viewer.
	deepest := 0
	for _, p := range views {
		if len(p.Tuples) > deepest {
			deepest = len(p.Tuples)
		}
	}
	if deepest != 3 {
		t.Errorf("deepest view set has %d tuples, want 3 (parent, parent, viewer)", deepest)
	}
}

// A starting position is the state the closure runs from. The closure only
// raises, so whatever the attacker held at the start it still holds in the
// reachable state. This wires the generator to the closure and checks that
// invariant on every position.
func TestStartingPositionsFeedClosure(t *testing.T) {
	model := documents(t)
	wm := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: []*WriteRule{
		{Resource: "document", Relation: "viewer", Operations: []Operation{Create}, Gate: Gate{Holds: "edit"}, Subject: SubjectSpec{Self: true}},
		{Resource: "document", Relation: "editor", Operations: []Operation{Create}, Gate: Gate{Holds: "owner"}, Subject: SubjectSpec{Self: true}},
	}}

	for _, p := range StartingPositions(model, attacker, Options{}) {
		reach, err := Closure(model, wm, nil, p.Tuples, []Object{p.Attacker}, Options{Now: time.Unix(0, 0)})
		if err != nil {
			t.Fatalf("Closure from %s: %v", p, err)
		}
		level, err := reach.Holds(p.Object, p.Target)
		if err != nil {
			t.Fatalf("Holds %s#%s: %v", p.Object, p.Target, err)
		}
		if level == No {
			t.Errorf("%s: the closure lost the starting grant", p)
		}
	}
}

// recursiveFolders is a folder whose view is its viewers and the viewers of
// every folder above it, an any arrow that recurses through parent.
func recursiveFolders(t *testing.T) *Model {
	t.Helper()
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
	m, err := NewModel([]*Type{{Name: "user"}, folder}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// sameSets reports whether two lists of tuple-key sets hold the same sets,
// order aside.
func sameSets(got, want [][]string) bool {
	if len(got) != len(want) {
		return false
	}
	used := make([]bool, len(want))
	for _, g := range got {
		found := false
		for i, w := range want {
			if !used[i] && slices.Equal(g, w) {
				used[i] = true
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
