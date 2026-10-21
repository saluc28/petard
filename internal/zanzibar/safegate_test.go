package zanzibar

import (
	"slices"
	"testing"
	"time"
)

// gateProposalFor returns the proposal for a relation, or reports none.
func gateProposalFor(ps []GateProposal, typ, relation string) (GateProposal, bool) {
	for _, p := range ps {
		if p.Type == typ && p.Relation == relation {
			return p, true
		}
	}
	return GateProposal{}, false
}

func unsafeFor(p GateProposal, permission string) (UnsafeGate, bool) {
	for _, u := range p.Unsafe {
		if u.Permission == permission {
			return u, true
		}
	}
	return UnsafeGate{}, false
}

// owner has no write rule, so petard proposes a gate for it. edit is a safe
// gate, since an editor who makes itself owner gains nothing it did not already
// hold; view is not, since a viewer who makes itself owner gains edit.
func TestSafeGates(t *testing.T) {
	model := documents(t)
	wm := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: []*WriteRule{
		{Resource: "document", Relation: "viewer", Operations: []Operation{Create}, Gate: Gate{Holds: "edit"}, Subject: SubjectSpec{Types: []string{"user"}}},
		{Resource: "document", Relation: "editor", Operations: []Operation{Create}, Gate: Gate{Holds: "owner"}, Subject: SubjectSpec{Types: []string{"user"}}},
	}}

	proposals, err := SafeGates(model, wm, nil, Options{Now: time.Unix(0, 0)})
	if err != nil {
		t.Fatalf("SafeGates: %v", err)
	}

	owner, ok := gateProposalFor(proposals, "document", "owner")
	if !ok {
		t.Fatalf("no proposal for document#owner; got %+v", proposals)
	}
	if !slices.Contains(owner.Safe, "edit") {
		t.Errorf("edit should be a safe gate for owner, safe = %v", owner.Safe)
	}
	if slices.Contains(owner.Safe, "view") {
		t.Errorf("view should not be a safe gate for owner, safe = %v", owner.Safe)
	}
	unsafe, ok := unsafeFor(owner, "view")
	if !ok {
		t.Fatalf("view should be an unsafe gate for owner, unsafe = %+v", owner.Unsafe)
	}
	if unsafe.Escalation.Permission != "edit" || unsafe.Escalation.After <= unsafe.Escalation.Before {
		t.Errorf("the view gate should open an escalation to edit, got %+v", unsafe.Escalation)
	}

	// The write model already gives viewer and editor a rule, so they are not
	// proposed.
	if _, ok := gateProposalFor(proposals, "document", "viewer"); ok {
		t.Error("viewer has a write rule and should not be proposed")
	}
	if _, ok := gateProposalFor(proposals, "document", "editor"); ok {
		t.Error("editor has a write rule and should not be proposed")
	}
}
