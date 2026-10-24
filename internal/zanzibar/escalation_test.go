package zanzibar

import (
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
