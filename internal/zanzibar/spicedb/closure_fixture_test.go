package spicedb

import (
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/saluc28/petard/internal/zanzibar"
)

// fixtureWrites is the write model of the vulnerable SpiceDB fixture.
var fixtureWrites = filepath.Join("..", "..", "..", "fixtures", "vulnerable-spicedb", "writes.yaml")

// The closure runs the real fixture through the real caveat evaluator. Erin is
// an editor of the roadmap until the first of November, which the editor tuple
// carries as not_expired; the time of the request is not on the tuple, so her
// edit is conditional. Whoever can edit may share, so the coalition writes Erin
// in as a plain viewer, which holds with no condition: her access stops
// depending on the date. The sign-up rule puts a sybil account in the
// coalition, and it is shared the roadmap the same way.
func TestFixtureClosure(t *testing.T) {
	now := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	sample := findOne(t, fixtureValidation).Sample(now)

	wm, err := zanzibar.LoadWriteModel(fixtureWrites)
	if err != nil {
		t.Fatalf("LoadWriteModel: %v", err)
	}

	erin := zanzibar.Object{Type: "user", ID: "erin"}
	roadmap := zanzibar.Object{Type: "document", ID: "roadmap"}

	// Every relation of the fixture occurs only positively, so E1 holds and the
	// closure is exact.
	if ok, mixed := zanzibar.CheckE1(sample.Model, wm); !ok {
		t.Fatalf("E1 should hold for the fixture, mixed: %v", mixed)
	}

	reach, err := zanzibar.Closure(sample.Model, wm, sample.Caveats, sample.Relationships, []zanzibar.Object{erin}, zanzibar.Options{Now: now})
	if err != nil {
		t.Fatalf("Closure: %v", err)
	}
	if !reach.Exact {
		t.Fatal("the fixture closure should be exact")
	}

	sybil := zanzibar.Object{Type: "user", ID: "created-0"}
	if !slices.Contains(reach.Objects, sybil) {
		t.Errorf("coalition %v should include the sybil account %s", reach.Objects, sybil)
	}

	added := addedKeys(sample.Relationships, reach.State)
	want := []string{
		"document:roadmap#viewer@user:created-0",
		"document:roadmap#viewer@user:erin",
	}
	slices.Sort(added)
	if !slices.Equal(added, want) {
		t.Errorf("added tuples = %v, want %v", added, want)
	}

	view, err := reach.Holds(roadmap, "view")
	if err != nil {
		t.Fatalf("Holds view: %v", err)
	}
	if view != zanzibar.Yes {
		t.Errorf("coalition view of the roadmap = %s, want yes", view)
	}

	edit, err := reach.Holds(roadmap, "edit")
	if err != nil {
		t.Fatalf("Holds edit: %v", err)
	}
	if edit != zanzibar.Conditional {
		t.Errorf("coalition edit of the roadmap = %s, want conditional: it rests on a caveat the check fills", edit)
	}
}

// From every starting position the schema offers, the coalition must not reach
// owner of the roadmap unless it started holding it: owner has no write rule in
// the fixture, so no coalition can write its way to it. This runs the whole
// pipeline, schema to starting positions to closure, on the real files.
func TestFixtureStartingPositionsCannotReachOwner(t *testing.T) {
	now := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	sample := findOne(t, fixtureValidation).Sample(now)
	wm, err := zanzibar.LoadWriteModel(fixtureWrites)
	if err != nil {
		t.Fatalf("LoadWriteModel: %v", err)
	}
	attacker := zanzibar.Object{Type: "user", ID: "attacker"}

	positions := zanzibar.StartingPositions(sample.Model, attacker, zanzibar.Options{})
	documentPositions := 0
	for _, p := range positions {
		if p.Object.Type != "document" {
			continue
		}
		documentPositions++

		startOwner, err := zanzibar.NewChecker(sample.Model, p.Tuples, sample.Caveats, now).Check(p.Object, "owner", zanzibar.Subject{Object: attacker}, nil)
		if err != nil {
			t.Fatalf("start owner of %s: %v", p, err)
		}
		reach, err := zanzibar.Closure(sample.Model, wm, sample.Caveats, p.Tuples, []zanzibar.Object{attacker}, zanzibar.Options{Now: now})
		if err != nil {
			t.Fatalf("Closure from %s: %v", p, err)
		}
		endOwner, err := reach.Holds(p.Object, "owner")
		if err != nil {
			t.Fatalf("reached owner of %s: %v", p, err)
		}
		if startOwner.Level == zanzibar.No && endOwner != zanzibar.No {
			t.Errorf("%s: coalition escalated to owner (owner has no write rule)", p)
		}
	}
	if documentPositions == 0 {
		t.Fatal("no document starting positions generated")
	}
}

// addedKeys is the string form of the tuples the reachable state holds that the
// start did not.
func addedKeys(start, state []zanzibar.Relationship) []string {
	was := map[string]bool{}
	for _, r := range start {
		was[r.String()] = true
	}
	var added []string
	for _, r := range state {
		if !was[r.String()] {
			added = append(added, r.String())
		}
	}
	return added
}

// The fixture leaves document#owner without a write rule, so petard proposes a
// gate for it. Over the real schema edit is a safe gate and view is not: an
// editor who makes itself owner gains nothing, a viewer gains edit.
func TestFixtureSafeGates(t *testing.T) {
	now := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	sample := findOne(t, fixtureValidation).Sample(now)
	wm, err := zanzibar.LoadWriteModel(fixtureWrites)
	if err != nil {
		t.Fatalf("LoadWriteModel: %v", err)
	}

	proposals, err := zanzibar.SafeGates(sample.Model, wm, sample.Caveats, zanzibar.Options{Now: now})
	if err != nil {
		t.Fatalf("SafeGates: %v", err)
	}

	var owner *zanzibar.GateProposal
	for i := range proposals {
		if proposals[i].Type == "document" && proposals[i].Relation == "owner" {
			owner = &proposals[i]
		}
	}
	if owner == nil {
		t.Fatalf("no gate proposal for document#owner; got %+v", proposals)
	}
	if !slices.Contains(owner.Safe, "edit") {
		t.Errorf("edit should be a safe gate for owner, safe = %v", owner.Safe)
	}
	unsafe := false
	for _, u := range owner.Unsafe {
		if u.Permission == "view" {
			unsafe = true
		}
	}
	if !unsafe {
		t.Errorf("view should be an unsafe gate for owner, unsafe = %+v", owner.Unsafe)
	}
}
