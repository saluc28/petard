package zanzibar

import (
	"slices"
	"strings"
	"sync/atomic"
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

// A relation on a type with no permission to gate on has no gate candidate, so
// its proposal is empty. Raises tells the two such relations apart: one no
// permission reads raises nothing and is safe to write, while one read across
// types raises a permission with no local gate to hold it. The report rests on
// this to avoid claiming an escalation where none was computed.
func TestSafeGatesRaises(t *testing.T) {
	types := []*Type{
		{Name: "user"},
		{Name: "tag", Relations: []*Relation{{Name: "label", Allowed: []Allowed{{Type: "user"}}}}},
		{Name: "group", Relations: []*Relation{{Name: "member", Allowed: []Allowed{{Type: "user"}}}}},
		{
			Name: "document",
			Relations: []*Relation{
				{Name: "owner", Allowed: []Allowed{{Type: "user"}}},
				{Name: "viewer", Allowed: []Allowed{{Type: "user"}, {Type: "group", Relation: "member"}}},
			},
			Permissions: []*Permission{
				{Name: "view", Expr: Union{Children: []Expr{Computed{Name: "viewer"}, Computed{Name: "owner"}}}},
				{Name: "edit", Expr: Computed{Name: "owner"}},
			},
		},
	}
	model, err := NewModel(types, nil)
	if err != nil {
		t.Fatal(err)
	}
	proposals, _, err := SafeGates(model, &WriteModel{}, nil, Options{Now: time.Unix(0, 0)})
	if err != nil {
		t.Fatalf("SafeGates: %v", err)
	}

	group, ok := gateProposalFor(proposals, "group", "member")
	if !ok {
		t.Fatalf("no proposal for group#member; got %+v", proposals)
	}
	if len(group.Safe) != 0 || len(group.Unsafe) != 0 {
		t.Errorf("group has no permission, so group#member has no gate candidate; safe=%v unsafe=%v", group.Safe, group.Unsafe)
	}
	if !slices.Equal(group.Raises, []string{"document#view"}) {
		t.Errorf("writing group#member is read by document#view across types; Raises = %v, want [document#view]", group.Raises)
	}

	tag, ok := gateProposalFor(proposals, "tag", "label")
	if !ok {
		t.Fatalf("no proposal for tag#label; got %+v", proposals)
	}
	if len(tag.Raises) != 0 {
		t.Errorf("tag#label is read by no permission, so it raises nothing; Raises = %v", tag.Raises)
	}
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

	proposals, _, err := SafeGates(model, wm, nil, Options{Now: time.Unix(0, 0)})
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

// A raise the declared rules reach on their own is a finding against them, and says
// nothing about the gate being weighed. Anyone may write reader, so a holder of admin
// can raise read whatever owner is gated on, and admin stays a safe gate for owner. A
// holder of read who makes itself owner gains admin, through the proposed rule, so
// read is not.
func TestSafeGatesLeaveARaiseTheDeclaredRulesReachAlone(t *testing.T) {
	doc := &Type{
		Name: "doc",
		Relations: []*Relation{
			{Name: "reader", Allowed: []Allowed{{Type: "user"}}},
			{Name: "owner", Allowed: []Allowed{{Type: "user"}}},
		},
		Permissions: []*Permission{
			{Name: "read", Expr: Computed{Name: "reader"}},
			{Name: "admin", Expr: Computed{Name: "owner"}},
		},
	}
	model, err := NewModel([]*Type{{Name: "user"}, doc}, nil)
	if err != nil {
		t.Fatal(err)
	}
	wm := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: []*WriteRule{
		{Resource: "doc", Relation: "reader", Operations: []Operation{Create}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Types: []string{"user"}}},
	}}

	proposals, _, err := SafeGates(model, wm, nil, Options{Now: time.Unix(0, 0)})
	if err != nil {
		t.Fatalf("SafeGates: %v", err)
	}
	owner, ok := gateProposalFor(proposals, "doc", "owner")
	if !ok {
		t.Fatalf("no proposal for doc#owner; got %+v", proposals)
	}
	if !slices.Equal(owner.Safe, []string{"admin"}) {
		t.Errorf("admin alone is a safe gate for owner, safe = %v, unsafe = %+v", owner.Safe, owner.Unsafe)
	}
	unsafe, ok := unsafeFor(owner, "read")
	if !ok || unsafe.Escalation.Permission != "admin" {
		t.Errorf("the read gate should open an escalation to admin, got %+v", owner.Unsafe)
	}
}

// Two relations without a rule can each be a safe gate alone yet unsafe once both
// are writable. p needs both a and b, so gating a on `gate` raises nothing while b
// stays unwritable, and the same for b; but a holder of `gate` that can write both
// reaches p. The combined check demotes one of the two, deterministically the same
// one, so the set it proposes holds together.
func TestSafeGatesCheckedTogether(t *testing.T) {
	doc := &Type{
		Name: "doc",
		Relations: []*Relation{
			{Name: "w", Allowed: []Allowed{{Type: "user"}}},
			{Name: "a", Allowed: []Allowed{{Type: "user"}}},
			{Name: "b", Allowed: []Allowed{{Type: "user"}}},
		},
		Permissions: []*Permission{
			{Name: "gate", Expr: Computed{Name: "w"}},
			{Name: "p", Expr: Intersection{Children: []Expr{Computed{Name: "a"}, Computed{Name: "b"}}}},
		},
	}
	model, err := NewModel([]*Type{{Name: "user"}, doc}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// w is service-gated, so `gate` is held only through a starting position; a and
	// b have no rule, so both are proposed.
	wm := &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: []*WriteRule{
		{Resource: "doc", Relation: "w", Operations: []Operation{Create}, Gate: Gate{Service: "provisioner"}, Subject: SubjectSpec{Types: []string{"user"}}},
	}}

	proposals, _, err := SafeGates(model, wm, nil, Options{Now: time.Unix(0, 0)})
	if err != nil {
		t.Fatalf("SafeGates: %v", err)
	}
	a, ok := gateProposalFor(proposals, "doc", "a")
	if !ok {
		t.Fatalf("no proposal for doc#a; got %+v", proposals)
	}
	b, ok := gateProposalFor(proposals, "doc", "b")
	if !ok {
		t.Fatalf("no proposal for doc#b; got %+v", proposals)
	}

	// Exactly one keeps `gate` as a safe gate; dropping either breaks the
	// combination, so the check demotes one and leaves the other.
	aSafe := slices.Contains(a.Safe, "gate")
	bSafe := slices.Contains(b.Safe, "gate")
	if aSafe == bSafe {
		t.Fatalf("checked together, exactly one of a, b keeps gate safe; a.Safe=%v b.Safe=%v", a.Safe, b.Safe)
	}

	demoted := a
	if aSafe {
		demoted = b
	}
	unsafe, ok := unsafeFor(demoted, "gate")
	if !ok {
		t.Fatalf("the demoted relation should carry gate as unsafe; got %+v", demoted.Unsafe)
	}
	if unsafe.Escalation.Permission != "p" {
		t.Errorf("the combination should raise p, got %+v", unsafe.Escalation)
	}
}

// checkTogether reuses a safe verdict across rebuilds instead of reweighing every
// pair after each demotion. The reuse must leave the proposals exactly as
// reweighing everything would, so it is held against a reference that does. The
// models force more than one demotion, so the reuse spans several passes.
func TestCheckTogetherReuseMatchesFullRecheck(t *testing.T) {
	cases := []struct {
		name  string
		model *Model
		wm    *WriteModel
	}{
		{name: "one demotion", model: checkedTogetherModel(t), wm: serviceGatedW(t)},
		{name: "two independent demotions", model: twoConflictModel(t), wm: serviceGatedW(t)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := Options{Now: time.Unix(0, 0)}
			rc := newReach(tc.model, tc.wm)
			byGate := positionsByGate(startingPositionsForSubjects(tc.model, opts))
			base := phase1Proposals(t, tc.model, tc.wm, nil, byGate, rc, opts)

			reuse := cloneProposals(base)
			if _, err := checkTogether(tc.model, tc.wm, nil, reuse, byGate, rc, opts); err != nil {
				t.Fatalf("checkTogether: %v", err)
			}
			full := cloneProposals(base)
			if err := checkTogetherFullRecheck(tc.model, tc.wm, nil, full, byGate, rc, opts); err != nil {
				t.Fatalf("reference: %v", err)
			}
			if got, want := proposalVerdicts(reuse), proposalVerdicts(full); !slices.Equal(got, want) {
				t.Errorf("reuse changed the proposals:\n got:  %v\n want: %v", got, want)
			}
		})
	}
}

// SafeGates stops the whole pass at its work budget: a tiny budget leaves
// proposal gates unverified and counted, while the default finishes a small
// model with none left. This covers the per-relation pass and the Limits count,
// which TestCheckTogetherBudget below does not reach.
func TestSafeGatesBudget(t *testing.T) {
	model := twoConflictModel(t)
	wm := serviceGatedW(t)

	tiny := &atomic.Int64{}
	tiny.Store(5)
	_, limits, err := SafeGates(model, wm, nil, Options{Now: time.Unix(0, 0), budget: tiny})
	if err != nil {
		t.Fatalf("SafeGates (tiny budget): %v", err)
	}
	if limits.ProposalsLeftOut == 0 {
		t.Error("a tiny budget should leave proposal gates unverified")
	}

	_, full, err := SafeGates(model, wm, nil, Options{Now: time.Unix(0, 0)})
	if err != nil {
		t.Fatalf("SafeGates (default budget): %v", err)
	}
	if full.ProposalsLeftOut != 0 {
		t.Errorf("a small model finishes within the budget, left = %d, want 0", full.ProposalsLeftOut)
	}
}

// The combined check stops at its work budget instead of running without end: a
// tiny budget leaves safe gates unverified in company, and no budget finishes
// with none left. The findings do not pass through this check and are unaffected.
func TestCheckTogetherBudget(t *testing.T) {
	model := twoConflictModel(t)
	wm := serviceGatedW(t)
	opts := Options{Now: time.Unix(0, 0)}
	rc := newReach(model, wm)
	byGate := positionsByGate(startingPositionsForSubjects(model, opts))
	base := phase1Proposals(t, model, wm, nil, byGate, rc, opts)

	tiny := &atomic.Int64{}
	tiny.Store(1)
	budgeted := opts
	budgeted.budget = tiny
	left, err := checkTogether(model, wm, nil, cloneProposals(base), byGate, rc, budgeted)
	if err != nil {
		t.Fatalf("checkTogether (budgeted): %v", err)
	}
	if left == 0 {
		t.Error("a tiny budget should leave safe gates unverified in company")
	}

	done, err := checkTogether(model, wm, nil, cloneProposals(base), byGate, rc, opts)
	if err != nil {
		t.Fatalf("checkTogether (no budget): %v", err)
	}
	if done != 0 {
		t.Errorf("with no budget the check finishes, left = %d, want 0", done)
	}
}

// phase1Proposals is the per-relation pass of safeGates, in the same order, so
// the reference and the real checkTogether weigh the same proposals.
func phase1Proposals(t testing.TB, model *Model, wm *WriteModel, caveats CaveatEvaluator, byGate map[gateKey][]StartingPosition, rc reach, opts Options) []GateProposal {
	t.Helper()
	var out []GateProposal
	for _, ty := range model.Types {
		for _, r := range ty.Relations {
			if hasWriteRule(wm, ty.Name, r.Name) {
				continue
			}
			p, _, err := relationGates(model, wm, caveats, ty, r, byGate, rc, opts)
			if err != nil {
				t.Fatalf("relationGates: %v", err)
			}
			out = append(out, p)
		}
	}
	return out
}

// cloneProposals copies the safe and unsafe sets each checkTogether mutates, so a
// run does not disturb the proposals a later run reads.
func cloneProposals(ps []GateProposal) []GateProposal {
	out := make([]GateProposal, len(ps))
	for i, p := range ps {
		p.Safe = slices.Clone(p.Safe)
		p.Unsafe = slices.Clone(p.Unsafe)
		out[i] = p
	}
	return out
}

// proposalVerdicts renders the safe and unsafe gate of every proposal as sorted
// lines, so two runs are compared as the classification they reached.
func proposalVerdicts(ps []GateProposal) []string {
	var out []string
	for _, p := range ps {
		safe := slices.Clone(p.Safe)
		slices.Sort(safe)
		var unsafe []string
		for _, u := range p.Unsafe {
			unsafe = append(unsafe, u.Permission)
		}
		slices.Sort(unsafe)
		out = append(out, p.Type+"#"+p.Relation+" safe="+strings.Join(safe, ",")+" unsafe="+strings.Join(unsafe, ","))
	}
	slices.Sort(out)
	return out
}

// checkTogetherFullRecheck is checkTogether before the reuse: it reweighs every
// pair after each demotion. It is the reference the reuse is held to.
func checkTogetherFullRecheck(model *Model, wm *WriteModel, caveats CaveatEvaluator, proposals []GateProposal, byGate map[gateKey][]StartingPosition, rc reach, opts Options) error {
	for {
		combined := withProposals(model, wm, proposals)
		scope := rc.scopeOf(model, combined)
		gates := map[gateKey]map[string]Escalation{}
		demoted := false
		for i := range proposals {
			for _, gate := range proposals[i].Safe {
				k := gateKey{typ: proposals[i].Type, target: gate}
				byRel, ok := gates[k]
				if !ok {
					var err error
					byRel, err = combinedGate(model, combined, caveats, byGate[k], scope, k, opts)
					if err != nil {
						return err
					}
					gates[k] = byRel
				}
				if esc, found := byRel[proposals[i].Relation]; found {
					demoteGate(proposals, proposals[i].Type, proposals[i].Relation, gate, esc)
					demoted = true
					break
				}
			}
			if demoted {
				break
			}
		}
		if !demoted {
			return nil
		}
	}
}

// checkedTogetherModel is the one-demotion model: p needs both a and b, both
// without a rule, reachable from a holder of gate.
func checkedTogetherModel(t *testing.T) *Model {
	t.Helper()
	doc := &Type{
		Name: "doc",
		Relations: []*Relation{
			{Name: "w", Allowed: []Allowed{{Type: "user"}}},
			{Name: "a", Allowed: []Allowed{{Type: "user"}}},
			{Name: "b", Allowed: []Allowed{{Type: "user"}}},
		},
		Permissions: []*Permission{
			{Name: "gate", Expr: Computed{Name: "w"}},
			{Name: "p", Expr: Intersection{Children: []Expr{Computed{Name: "a"}, Computed{Name: "b"}}}},
		},
	}
	m, err := NewModel([]*Type{{Name: "user"}, doc}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// twoConflictModel has two independent intersections, p1 over a and b and p2 over
// c and d, all reachable from a holder of gate, so the combined check demotes one
// gate for each conflict: two demotions over more than one pass.
func twoConflictModel(t *testing.T) *Model {
	t.Helper()
	doc := &Type{
		Name: "doc",
		Relations: []*Relation{
			{Name: "w", Allowed: []Allowed{{Type: "user"}}},
			{Name: "a", Allowed: []Allowed{{Type: "user"}}},
			{Name: "b", Allowed: []Allowed{{Type: "user"}}},
			{Name: "c", Allowed: []Allowed{{Type: "user"}}},
			{Name: "d", Allowed: []Allowed{{Type: "user"}}},
		},
		Permissions: []*Permission{
			{Name: "gate", Expr: Computed{Name: "w"}},
			{Name: "p1", Expr: Intersection{Children: []Expr{Computed{Name: "a"}, Computed{Name: "b"}}}},
			{Name: "p2", Expr: Intersection{Children: []Expr{Computed{Name: "c"}, Computed{Name: "d"}}}},
		},
	}
	m, err := NewModel([]*Type{{Name: "user"}, doc}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// serviceGatedW gives w a service gate, so gate is held only through a starting
// position and the relations without a rule are all proposed.
func serviceGatedW(t testing.TB) *WriteModel {
	t.Helper()
	return &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: []*WriteRule{
		{Resource: "doc", Relation: "w", Operations: []Operation{Create}, Gate: Gate{Service: "provisioner"}, Subject: SubjectSpec{Types: []string{"user"}}},
	}}
}
