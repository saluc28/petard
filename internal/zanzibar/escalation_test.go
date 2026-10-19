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
// decisive write is the second.
func TestEscalationsGateChain(t *testing.T) {
	model := documents(t)
	wm := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: []*WriteRule{
		{Resource: "document", Relation: "editor", Operations: []Operation{Create}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Self: true}},
		{Resource: "document", Relation: "viewer", Operations: []Operation{Create}, Gate: Gate{Holds: "edit"}, Subject: SubjectSpec{Self: true}},
	}}
	roadmap := object("document:roadmap")
	mallory := object("user:mallory")
	start := []Relationship{rel("document:roadmap", "owner", "user:olivia")}

	escs, err := Escalations(model, wm, nil, start, []Object{mallory}, Options{Now: time.Unix(0, 0)})
	if err != nil {
		t.Fatalf("Escalations: %v", err)
	}

	// edit rises on the first write, so its shortest witness is that one write.
	if esc, ok := findEscalation(escs, roadmap, "edit", rel("document:roadmap", "editor", "user:mallory")); !ok {
		t.Errorf("no escalation on edit by writing editor@mallory; got %+v", escs)
	} else if len(esc.Writes) != 1 {
		t.Errorf("edit witness has %d writes, want 1", len(esc.Writes))
	}

	// view is reachable through the written viewer, whose rule's gate holds only
	// after edit is written, so that witness is two writes.
	esc, ok := findEscalation(escs, roadmap, "view", rel("document:roadmap", "viewer", "user:mallory"))
	if !ok {
		t.Fatalf("no escalation on view by writing viewer@mallory; got %+v", escs)
	}
	if len(esc.Writes) != 2 {
		t.Errorf("view-through-viewer witness has %d writes, want 2: %+v", len(esc.Writes), esc.Writes)
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
