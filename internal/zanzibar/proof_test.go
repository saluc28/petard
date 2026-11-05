package zanzibar

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

// proofOfOne is the proof of the one escalation of a permission a coalition raises
// from a start under a write model.
func proofOfOne(t *testing.T, s Sample, wm *WriteModel, coalition Object, permission string) *Proof {
	t.Helper()
	escalations, err := Escalations(s.Model, wm, s.Caveats, s.Relationships, []Object{coalition}, Options{Now: s.Now})
	if err != nil {
		t.Fatal(err)
	}
	for _, esc := range escalations {
		if esc.Permission != permission {
			continue
		}
		proof, err := proofOf(s, esc)
		if err != nil {
			t.Fatalf("proofOf: %v", err)
		}
		return proof
	}
	t.Fatalf("no escalation of %s among %+v", permission, escalations)
	return nil
}

// checksOf are the checks of a state as their assertions, level included.
func checksOf(state ProofState) []string {
	out := make([]string, 0, len(state.Checks))
	for _, c := range state.Checks {
		out = append(out, c.String()+" "+c.Level.String())
	}
	return out
}

// A proof starts where the witness starts, asks before each write behind a gate whether
// the coalition holds the gate, and ends after the last write, where the permission is
// held. The store of each state is the one the product would hold.
func TestAProofAsksWhatEachWriteRestsOn(t *testing.T) {
	start := []Relationship{
		rel("document:roadmap", "viewer", "user:vic"),
		rel("document:roadmap", "editor", "user:olivia"),
	}
	wm := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: []*WriteRule{
		{Resource: "document", Relation: "editor", Operations: []Operation{Create}, Gate: Gate{Holds: "view"}, Subject: SubjectSpec{Self: true}, Position: Position{File: "writes.yaml", Line: 4, Column: 3}},
	}}
	s := Sample{Model: gapModel(t), Relationships: start, Now: time.Unix(0, 0)}
	proof := proofOfOne(t, s, wm, Object{Type: "user", ID: "vic"}, "edit")

	if len(proof.States) != 2 {
		t.Fatalf("%d states, want the one before the write and the one after: %+v", len(proof.States), proof.States)
	}
	before, after := proof.States[0], proof.States[1]
	if !slices.Equal(before.Relationships, start) {
		t.Errorf("the first state holds %v, want the start %v", before.Relationships, start)
	}
	if want := []string{"document:roadmap#edit@user:vic no", "document:roadmap#view@user:vic yes"}; !slices.Equal(checksOf(before), want) {
		t.Errorf("before the write it asks %v, want %v", checksOf(before), want)
	}
	if why := before.Checks[1].Why; !strings.Contains(why, "whoever holds view") || !strings.Contains(why, "writes.yaml:4:3") {
		t.Errorf("the gate says %q, want the rule and where it is declared", why)
	}
	if after.Writes != 1 || !slices.Equal(after.Made, []string{"write document:roadmap#editor@user:vic (whoever holds view)"}) {
		t.Errorf("the last state comes after %d writes, %v", after.Writes, after.Made)
	}
	if want := append(slices.Clone(start), rel("document:roadmap", "editor", "user:vic")); !slices.Equal(after.Relationships, want) {
		t.Errorf("the last state holds %v, want %v", after.Relationships, want)
	}
	if want := []string{"document:roadmap#edit@user:vic yes"}; !slices.Equal(checksOf(after), want) {
		t.Errorf("after the write it asks %v, want %v", checksOf(after), want)
	}
}

// A creation is gated on the objects it is made in, so the proof asks that gate on the
// object the witness made it in.
func TestAProofAsksTheGateOfACreation(t *testing.T) {
	wm := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes",
		Creates: []*CreationRule{{
			Creates: "team",
			On:      []OnSpec{{Type: "folder", Gate: Gate{Holds: "view"}}},
			Writes:  []CreationWrite{{Resource: CreatedPlaceholder, Relation: "member", Subject: CreatorPlaceholder}},
		}},
		Writes: []*WriteRule{
			{Resource: "document", Relation: "viewer", Operations: []Operation{Create}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Types: []string{"team#member"}}},
		},
	}
	s := Sample{
		Model: gapModel(t),
		Relationships: []Relationship{
			rel("folder:shared", "viewer", "user:vic"),
			rel("document:roadmap", "editor", "user:olivia"),
		},
		Now: time.Unix(0, 0),
	}
	proof := proofOfOne(t, s, wm, Object{Type: "user", ID: "vic"}, "view")

	var asked []string
	for _, state := range proof.States {
		for _, c := range state.Checks {
			if strings.Contains(c.Why, "create") {
				asked = append(asked, c.String()+" "+c.Level.String())
			}
		}
	}
	if len(asked) == 0 || asked[0] != "folder:shared#view@user:vic yes" {
		t.Errorf("the gate of the creation is asked as %v, want folder:shared#view@user:vic yes", asked)
	}

	// The witness is the tuple the creation writes and the grant, which anyone may
	// write: the state between them asks nothing, so it has no state of its own, and
	// the last state says both writes made since the first.
	if len(proof.States) != 2 {
		t.Fatalf("%d states, want 2: %+v", len(proof.States), proof.States)
	}
	if last := proof.States[1]; last.Writes != 2 || len(last.Made) != 2 {
		t.Errorf("the last state comes after %d writes and says %v", last.Writes, last.Made)
	}
}

// What has expired when the analysis reads the store is not in it, for the checker
// and for the product alike.
func TestAProofLeavesOutWhatHasExpired(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	gone := now.Add(-time.Hour)
	expired := rel("document:roadmap", "viewer", "user:dana")
	expired.Expires = &gone
	wm := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: []*WriteRule{
		{Resource: "document", Relation: "editor", Operations: []Operation{Create}, Gate: Gate{Holds: "view"}, Subject: SubjectSpec{Self: true}},
	}}
	s := Sample{
		Model:         gapModel(t),
		Relationships: []Relationship{rel("document:roadmap", "viewer", "user:vic"), expired},
		Now:           now,
	}
	proof := proofOfOne(t, s, wm, Object{Type: "user", ID: "vic"}, "edit")
	for _, state := range proof.States {
		if slices.ContainsFunc(state.Relationships, func(r Relationship) bool { return r.Expires != nil }) {
			t.Errorf("a state holds what has expired: %v", state.Relationships)
		}
	}
}

// A check follows a userset to its subject, so two teams each in the other are a loop;
// it only compares a plain subject, so a document and a user naming each other are not.
func TestALoopIsWhatACheckCanFollow(t *testing.T) {
	model := gapModel(t)
	member := func(team, of string) Relationship {
		return Relationship{Resource: object(team), Relation: "member", Subject: Subject{Object: object(of), Relation: "member"}}
	}
	tests := []struct {
		name          string
		relationships []Relationship
		expected      string
	}{
		{name: "two teams in each other", relationships: []Relationship{rel("document:roadmap", "banned", "team:a#member"), member("team:a", "team:b"), member("team:b", "team:a")}, expected: "team:a"},
		{name: "a team in another", relationships: []Relationship{rel("document:roadmap", "banned", "team:a#member"), member("team:a", "team:b")}},
		{name: "plain subjects", relationships: []Relationship{rel("document:roadmap", "viewer", "user:vic"), rel("document:roadmap", "editor", "user:vic")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := model.LoopFrom(tt.relationships, object("document:roadmap")); got != tt.expected {
				t.Errorf("LoopFrom = %q, want %q", got, tt.expected)
			}
		})
	}
}

// A check that cuts a loop without granting is one a product fails at its depth limit
// rather than answering no, so a proof cannot ask it.
func TestAProofCannotAskACheckThatCutsALoop(t *testing.T) {
	folder := &Type{
		Name: "folder",
		Relations: []*Relation{
			{Name: "viewer", Allowed: []Allowed{{Type: "user"}}},
			{Name: "parent", Allowed: []Allowed{{Type: "folder"}}},
		},
		Permissions: []*Permission{{Name: "view", Expr: Union{Children: []Expr{Computed{Name: "viewer"}, Arrow{Through: "parent", Target: "view"}}}}},
	}
	model, err := NewModel([]*Type{{Name: "user"}, folder}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := replay{sample: Sample{Model: model}}
	checker := r.checker([]Relationship{rel("folder:a", "parent", "folder:b"), rel("folder:b", "parent", "folder:a")})
	_, err = r.ask(checker, Assertion{Resource: Object{Type: "folder", ID: "a"}, Name: "view", Subject: Subject{Object: Object{Type: "user", ID: "vic"}}}, Yes)
	if err == nil || !strings.Contains(err.Error(), "loop") {
		t.Errorf("ask = %v, want an error naming the loop", err)
	}
}

// A rule that holds its subject to a permission is a check the application makes, so the
// proof asks it of the subject the write names.
func TestAProofAsksWhatARuleHoldsItsSubjectTo(t *testing.T) {
	wm := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: []*WriteRule{
		{Resource: "document", Relation: "editor", Operations: []Operation{Create}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Holds: "view"}},
	}}
	s := Sample{
		Model:         gapModel(t),
		Relationships: []Relationship{rel("document:roadmap", "viewer", "user:vic")},
		Now:           time.Unix(0, 0),
	}
	proof := proofOfOne(t, s, wm, Object{Type: "user", ID: "vic"}, "edit")

	first := proof.States[0]
	if !slices.Contains(checksOf(first), "document:roadmap#view@user:vic yes") {
		t.Errorf("before the write it asks %v, want what the rule holds the subject to", checksOf(first))
	}
}

// The product keeps one tuple to a resource, relation and subject: a write of a tuple in
// another form replaces it, and a delete takes it whatever it carries.
func TestAProofStoreKeepsATupleOnce(t *testing.T) {
	plain := rel("document:roadmap", "viewer", "user:vic")
	caveated := plain
	caveated.Caveat = &CaveatUse{Name: "open"}

	var store productState
	store.put(caveated)
	store.put(rel("document:roadmap", "editor", "user:olivia"))
	store.put(plain)
	if got := store.list(); len(got) != 2 || got[0].Caveat != nil {
		t.Errorf("after a write of the same tuple without its caveat the store holds %v", got)
	}
	store.drop(caveated)
	if got := store.list(); len(got) != 1 || got[0].Relation != "editor" {
		t.Errorf("after a delete the store holds %v", got)
	}
}

// contextCaveats decides a caveat on the value of open: yes when it is true, no when it
// is false, and waiting when the check does not say.
type contextCaveats struct{}

func (contextCaveats) Evaluate(_ string, values map[string]any) (Level, error) {
	switch values["open"] {
	case true:
		return Yes, nil
	case false:
		return No, nil
	}
	return Conditional, nil
}

// A check that waits on a condition is also asked under the contexts the sample's own
// checks supply, and the first that gives what the proof needs is kept with it.
func TestAProofDecidesAConditionWithAContextOfTheSample(t *testing.T) {
	document := &Type{
		Name: "document",
		Relations: []*Relation{
			{Name: "viewer", Allowed: []Allowed{{Type: "user", Caveat: "gate"}}},
			{Name: "editor", Allowed: []Allowed{{Type: "user"}}},
		},
		Permissions: []*Permission{
			{Name: "view", Expr: Computed{Name: "viewer"}},
			{Name: "edit", Expr: Computed{Name: "editor"}},
		},
	}
	model, err := NewModel([]*Type{{Name: "user"}, document}, []*Caveat{{Name: "gate", Parameters: []Parameter{{Name: "open", Type: "bool"}}}})
	if err != nil {
		t.Fatal(err)
	}
	viewer := rel("document:roadmap", "viewer", "user:vic")
	viewer.Caveat = &CaveatUse{Name: "gate"}
	wm := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: []*WriteRule{
		{Resource: "document", Relation: "editor", Operations: []Operation{Create}, Gate: Gate{Holds: "view"}, Subject: SubjectSpec{Self: true}},
	}}
	vic := Object{Type: "user", ID: "vic"}
	ask := func(context map[string]any) Assertion {
		return Assertion{Resource: Object{Type: "document", ID: "roadmap"}, Name: "view", Subject: Subject{Object: vic}, Context: context}
	}

	tests := []struct {
		name      string
		contexts  []map[string]any
		decidedBy map[string]any
	}{
		{name: "a context that opens it", contexts: []map[string]any{{"open": false}, {"open": true}}, decidedBy: map[string]any{"open": true}},
		{name: "no context that opens it", contexts: []map[string]any{{"open": false}}},
		{name: "no context at all"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Sample{Model: model, Relationships: []Relationship{viewer}, Caveats: contextCaveats{}, Now: time.Unix(0, 0)}
			for _, context := range tt.contexts {
				s.Assertions = append(s.Assertions, ask(context))
			}
			proof := proofOfOne(t, s, wm, vic, "edit")
			gate := proof.States[0].Checks[1]
			if gate.Level != Conditional {
				t.Fatalf("the gate is %v, want conditional", gate.Level)
			}
			switch {
			case tt.decidedBy == nil && gate.Decided != nil:
				t.Errorf("decided by %v, want no context", gate.Decided)
			case tt.decidedBy != nil && (gate.Decided == nil || gate.Decided.Level != Yes || gate.Decided.Context["open"] != tt.decidedBy["open"]):
				t.Errorf("decided by %+v, want %v at yes", gate.Decided, tt.decidedBy)
			}
		})
	}
}

// A witness whose writes, applied as the product applies them, do not give the levels
// the search found has no proof: the proof would claim what the product does not answer.
func TestAProofThatDoesNotReplayIsNotWritten(t *testing.T) {
	s := Sample{Model: gapModel(t), Now: time.Unix(0, 0)}
	tests := []struct {
		name          string
		before, after Level
		write         Relationship
		gate          Gate
	}{
		{name: "it held the permission already", before: Yes, after: Yes, write: rel("document:roadmap", "editor", "user:vic"), gate: Gate{Anyone: true}},
		{name: "the writes do not give it", before: No, after: Yes, write: rel("document:roadmap", "viewer", "user:vic"), gate: Gate{Anyone: true}},
		{name: "the gate does not hold", before: No, after: Yes, write: rel("document:roadmap", "editor", "user:vic"), gate: Gate{Holds: "view"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			esc := Escalation{
				Object:     Object{Type: "document", ID: "roadmap"},
				Permission: "edit",
				Before:     tt.before,
				After:      tt.after,
				Writes:     []WriteStep{{Relationship: tt.write, Rule: &WriteRule{Gate: tt.gate}}},
				start:      []Relationship{rel("document:roadmap", "editor", "user:olivia")},
				coalition:  []Object{{Type: "user", ID: "vic"}},
			}
			if _, err := proofOf(s, esc); !errors.Is(err, errNoReplay) {
				t.Errorf("proofOf = %v, want %v", err, errNoReplay)
			}
		})
	}
}
