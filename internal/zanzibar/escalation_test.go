package zanzibar

import (
	"slices"
	"testing"
	"time"
)

// findEscalation returns the escalation on an object and permission whose
// decisive write is the given relationship, or reports that none matched.
func findEscalation(escs []Escalation, object Object, permission string, decisive Relationship) (Escalation, bool) {
	for _, e := range escs {
		if e.Object != object || e.Permission != permission {
			continue
		}
		step, ok := e.Decisive()
		if ok && step.Relationship.String() == decisive.String() && !step.Delete {
			return e, true
		}
	}
	return Escalation{}, false
}

// A coalition that writes itself a viewer raises its view of a document it did
// not own, and the witness is that one write.
func TestEscalationsSelfWrite(t *testing.T) {
	model := documents(t)
	wm := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: []*WriteRule{
		{Resource: "document", Relation: "viewer", Operations: []Operation{Create}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Self: true}},
	}}
	roadmap := object("document:roadmap")
	mallory := object("user:mallory")
	start := []Relationship{rel("document:roadmap", "owner", "user:olivia")}

	escs, err := Escalations(model, wm, nil, start, []Object{mallory}, Options{Now: time.Unix(0, 0)})
	if err != nil {
		t.Fatalf("Escalations: %v", err)
	}

	esc, ok := findEscalation(escs, roadmap, "view", rel("document:roadmap", "viewer", "user:mallory"))
	if !ok {
		t.Fatalf("no escalation on document:roadmap#view by writing viewer@mallory; got %+v", escs)
	}
	if esc.Before != No || esc.After != Yes {
		t.Errorf("view goes from %s to %s, want no to yes", esc.Before, esc.After)
	}
	if len(esc.Writes) != 1 {
		t.Fatalf("witness has %d writes, want 1: %+v", len(esc.Writes), esc.Writes)
	}
	step := esc.Writes[0]
	if step.Rule == nil || step.Rule.Relation != "viewer" || step.Delete {
		t.Errorf("the decisive write = %+v, want an add of viewer by the viewer rule", step)
	}
}

// A gate that only opens after a first write gives a two-write witness, and the
// decisive write is the second. Writing a viewer is open to anyone and raises
// view in one write; writing an editor is gated on holding view, so edit rises
// only after the viewer is written, and its witness is those two writes.
func TestEscalationsGateChain(t *testing.T) {
	model := documents(t)
	wm := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: []*WriteRule{
		{Resource: "document", Relation: "viewer", Operations: []Operation{Create}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Self: true}},
		{Resource: "document", Relation: "editor", Operations: []Operation{Create}, Gate: Gate{Holds: "view"}, Subject: SubjectSpec{Self: true}},
	}}
	roadmap := object("document:roadmap")
	mallory := object("user:mallory")
	start := []Relationship{rel("document:roadmap", "owner", "user:olivia")}

	escs, err := Escalations(model, wm, nil, start, []Object{mallory}, Options{Now: time.Unix(0, 0)})
	if err != nil {
		t.Fatalf("Escalations: %v", err)
	}

	// view rises on the viewer write, which anyone may make, so its witness is
	// that one write.
	if esc, ok := findEscalation(escs, roadmap, "view", rel("document:roadmap", "viewer", "user:mallory")); !ok {
		t.Errorf("no escalation on view by writing viewer@mallory; got %+v", escs)
	} else if len(esc.Writes) != 1 {
		t.Errorf("view witness has %d writes, want 1", len(esc.Writes))
	}

	// edit rises on the editor write, whose gate holds only once view is held, so
	// that witness is the viewer write and then the editor.
	esc, ok := findEscalation(escs, roadmap, "edit", rel("document:roadmap", "editor", "user:mallory"))
	if !ok {
		t.Fatalf("no escalation on edit by writing editor@mallory; got %+v", escs)
	}
	if len(esc.Writes) != 2 {
		t.Errorf("edit-through-editor witness has %d writes, want 2: %+v", len(esc.Writes), esc.Writes)
	}
}

// A write gated on a permission held on the tuple's subject, not on the
// resource, is the shape of granting a group a right by editing the group: the
// tuple lands on the resource with the group's members as the subject, and the
// right to edit the group authorizes it. A coalition that may edit a group it
// belongs to writes the group a right it never held and rises to it. Without the
// right to edit the group the subject gate does not hold, the write is no move,
// and nothing rises.
func TestEscalationsSubjectGate(t *testing.T) {
	grp := &Type{
		Name: "grp",
		Relations: []*Relation{
			{Name: "member", Allowed: []Allowed{{Type: "user"}}},
			{Name: "can_edit", Allowed: []Allowed{{Type: "user"}, {Type: "grp", Relation: "member"}}},
		},
	}
	thing := &Type{
		Name: "thing",
		Relations: []*Relation{
			{Name: "admin", Allowed: []Allowed{{Type: "user"}, {Type: "grp", Relation: "member"}}},
		},
		Permissions: []*Permission{{Name: "use", Expr: Computed{Name: "admin"}}},
	}
	model, err := NewModel([]*Type{{Name: "user"}, grp, thing}, nil)
	if err != nil {
		t.Fatal(err)
	}

	wm := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: []*WriteRule{
		{Resource: "thing", Relation: "admin", Operations: []Operation{Create}, Gate: Gate{HoldsOnSubject: "can_edit"}, Subject: SubjectSpec{Types: []string{"grp#member"}}},
	}}

	attacker := object("user:attacker")
	target := object("thing:t1")
	decisive := rel("thing:t1", "admin", "grp:g1#member")

	// Held: the attacker belongs to g1 and may edit it, so it writes g1 the admin
	// of a thing it did not hold, and rises to use through its membership.
	held := []Relationship{
		rel("grp:g1", "member", "user:attacker"),
		rel("grp:g1", "can_edit", "user:attacker"),
		rel("thing:t1", "admin", "user:victim"),
	}
	escs, err := Escalations(model, wm, nil, held, []Object{attacker}, Options{Now: time.Unix(0, 0)})
	if err != nil {
		t.Fatalf("Escalations: %v", err)
	}
	esc, ok := findEscalation(escs, target, "use", decisive)
	if !ok {
		t.Fatalf("no escalation on thing:t1#use by writing admin@grp:g1#member; got %+v", escs)
	}
	if esc.Before != No || esc.After != Yes {
		t.Errorf("use goes from %s to %s, want no to yes", esc.Before, esc.After)
	}

	// Not held: the attacker belongs to g1 but may not edit it, so the subject
	// gate does not hold, the write is no move, and the same raise does not occur.
	notHeld := []Relationship{
		rel("grp:g1", "member", "user:attacker"),
		rel("thing:t1", "admin", "user:victim"),
	}
	escs, err = Escalations(model, wm, nil, notHeld, []Object{attacker}, Options{Now: time.Unix(0, 0)})
	if err != nil {
		t.Fatalf("Escalations (not held): %v", err)
	}
	if _, ok := findEscalation(escs, target, "use", decisive); ok {
		t.Errorf("escalation found though the attacker cannot edit g1; got %+v", escs)
	}
}

// The subject gate applies to a delete too: lifting a deny by deleting a tuple
// is gated by the right to edit the object the tuple's subject names. A coalition
// banned through a group it may edit deletes its own ban and access rises; without
// the right to edit the group the delete is no move and the ban stands.
func TestEscalationsSubjectGateDelete(t *testing.T) {
	grp := &Type{
		Name: "grp",
		Relations: []*Relation{
			{Name: "member", Allowed: []Allowed{{Type: "user"}}},
			{Name: "can_edit", Allowed: []Allowed{{Type: "user"}, {Type: "grp", Relation: "member"}}},
		},
	}
	thing := &Type{
		Name: "thing",
		Relations: []*Relation{
			{Name: "viewer", Allowed: []Allowed{{Type: "user"}, {Type: "grp", Relation: "member"}}},
			{Name: "banned", Allowed: []Allowed{{Type: "grp", Relation: "member"}}},
		},
		Permissions: []*Permission{{Name: "access", Expr: Exclusion{Base: Computed{Name: "viewer"}, Subtracted: []Expr{Computed{Name: "banned"}}}}},
	}
	model, err := NewModel([]*Type{{Name: "user"}, grp, thing}, nil)
	if err != nil {
		t.Fatal(err)
	}

	wm := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: []*WriteRule{
		{Resource: "thing", Relation: "banned", Operations: []Operation{Delete}, Gate: Gate{HoldsOnSubject: "can_edit"}, Subject: SubjectSpec{Types: []string{"grp#member"}}},
	}}

	attacker := object("user:attacker")
	target := object("thing:t1")
	ban := rel("thing:t1", "banned", "grp:g1#member")

	// deletedBanRaisesAccess reports whether an escalation raises thing:t1#access
	// with the decisive write being the delete of the ban on grp:g1#member.
	deletedBanRaisesAccess := func(escs []Escalation) bool {
		for _, e := range escs {
			if e.Object != target || e.Permission != "access" {
				continue
			}
			if step, ok := e.Decisive(); ok && step.Delete && step.Relationship.String() == ban.String() {
				return true
			}
		}
		return false
	}

	// Held: the attacker is a viewer but banned through g1, and may edit g1, so it
	// deletes its own ban and access rises.
	held := []Relationship{
		rel("grp:g1", "member", "user:attacker"),
		rel("grp:g1", "can_edit", "user:attacker"),
		rel("thing:t1", "viewer", "user:attacker"),
		ban,
	}
	escs, err := Escalations(model, wm, nil, held, []Object{attacker}, Options{Now: time.Unix(0, 0)})
	if err != nil {
		t.Fatalf("Escalations: %v", err)
	}
	if !deletedBanRaisesAccess(escs) {
		t.Fatalf("no escalation on thing:t1#access by deleting the ban; got %+v", escs)
	}

	// Not held: the attacker cannot edit g1, so the subject gate does not hold, the
	// delete is no move, and the ban stands.
	notHeld := []Relationship{
		rel("grp:g1", "member", "user:attacker"),
		rel("thing:t1", "viewer", "user:attacker"),
		ban,
	}
	escs, err = Escalations(model, wm, nil, notHeld, []Object{attacker}, Options{Now: time.Unix(0, 0)})
	if err != nil {
		t.Fatalf("Escalations (not held): %v", err)
	}
	if deletedBanRaisesAccess(escs) {
		t.Errorf("ban lifted though the attacker cannot edit g1; got %+v", escs)
	}
}

// One write can raise the same permission on two objects at once: joining a team
// that views two documents raises view on both. The escalations come out in the
// order of their targets on every run, since the caller keeps the first of a type
// and permission, and an order that moved would change the witness kept and the
// edge the graph draws for it.
func TestEscalationsOfOneWriteComeInTheOrderOfTheirTargets(t *testing.T) {
	model := documents(t)
	wm := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: []*WriteRule{
		{Resource: "team", Relation: "member", Operations: []Operation{Create}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Self: true}},
	}}
	start := []Relationship{
		rel("document:b", "viewer", "team:t#member"),
		rel("document:a", "viewer", "team:t#member"),
	}

	var first []string
	for run := range 40 {
		escs, err := Escalations(model, wm, nil, start, []Object{object("user:mallory")}, Options{Now: time.Unix(0, 0)})
		if err != nil {
			t.Fatalf("Escalations: %v", err)
		}
		var got []string
		for _, e := range escs {
			got = append(got, e.Object.String()+"#"+e.Permission)
		}
		if run == 0 {
			first = got
			if len(got) < 2 || got[0] != "document:a#view" || got[1] != "document:b#view" {
				t.Fatalf("escalations = %v, want view on document:a, then on document:b", got)
			}
			continue
		}
		if !slices.Equal(got, first) {
			t.Fatalf("run %d gave %v, and the first run gave %v", run, got, first)
		}
	}
}

// A relation only a service can write is out of a coalition's reach, so nothing
// escalates.
func TestEscalationsServiceGate(t *testing.T) {
	model := documents(t)
	wm := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: []*WriteRule{
		{Resource: "document", Relation: "viewer", Operations: []Operation{Create}, Gate: Gate{Service: "sharing"}, Subject: SubjectSpec{Self: true}},
	}}
	mallory := object("user:mallory")
	start := []Relationship{rel("document:roadmap", "owner", "user:olivia")}

	escs, err := Escalations(model, wm, nil, start, []Object{mallory}, Options{Now: time.Unix(0, 0)})
	if err != nil {
		t.Fatalf("Escalations: %v", err)
	}
	if len(escs) != 0 {
		t.Errorf("a service gate should let nothing escalate, got %+v", escs)
	}
}

// An intended rule is a raise the write model allows by design, so a witness
// made only of intended writes is not an escalation.
func TestEscalationsIntendedIsNotReported(t *testing.T) {
	model := documents(t)
	wm := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: []*WriteRule{
		{Resource: "document", Relation: "viewer", Operations: []Operation{Create}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Self: true}, Intended: true},
	}}
	mallory := object("user:mallory")
	start := []Relationship{rel("document:roadmap", "owner", "user:olivia")}

	escs, err := Escalations(model, wm, nil, start, []Object{mallory}, Options{Now: time.Unix(0, 0)})
	if err != nil {
		t.Fatalf("Escalations: %v", err)
	}
	if len(escs) != 0 {
		t.Errorf("an intended write is not an escalation, got %+v", escs)
	}
}

// decisiveWrite reads past a trailing creation to the rule write a raise rests
// on, so a report and a gate check name the link rather than a setup write the
// witness order left last. A witness of only creations falls back to the last.
func TestDecisiveWrite(t *testing.T) {
	link := WriteStep{Relationship: rel("org:o", "granted", "binding:b"), Rule: &WriteRule{}}
	create1 := WriteStep{Relationship: rel("binding:b", "bearer", "user:x"), Creation: &CreationRule{}}
	create2 := WriteStep{Relationship: rel("binding:b", "role", "role:admin"), Creation: &CreationRule{}}

	tests := []struct {
		name   string
		writes []WriteStep
		want   string // the decisive relationship, or "" when none
		ok     bool
	}{
		{name: "no writes", writes: nil, ok: false},
		{name: "link last", writes: []WriteStep{create1, link}, want: link.Relationship.String(), ok: true},
		{name: "creation last, link earlier", writes: []WriteStep{link, create2}, want: link.Relationship.String(), ok: true},
		{name: "all creations fall back to the last", writes: []WriteStep{create1, create2}, want: create2.Relationship.String(), ok: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := Escalation{Writes: tt.writes}.decisiveWrite()
			if ok != tt.ok {
				t.Fatalf("ok = %v, want %v", ok, tt.ok)
			}
			if ok && got.Relationship.String() != tt.want {
				t.Errorf("decisiveWrite = %s, want %s", got.Relationship, tt.want)
			}
		})
	}
}
