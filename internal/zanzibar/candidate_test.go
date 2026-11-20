package zanzibar

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

// escalationsAllTargets is the escalation search without the candidateTargets
// prune: it weighs every pre-existing target in the bounded search, which is what
// escalationsScoped did before the saturation short-circuit. The short-circuit
// must leave the result identical to this, whatever it drops being a target the
// search would return nothing for.
func escalationsAllTargets(model *Model, wm *WriteModel, caveats CaveatEvaluator, start []Relationship, coalition []Object, scope map[permRef]bool, opts Options) ([]Escalation, error) {
	e := newEngine(model, wm, caveats, start, coalition, opts)
	targets := e.preExistingTargets()
	if scope != nil {
		targets = slices.DeleteFunc(targets, func(q target) bool {
			return !scope[permRef{typ: q.resource.Type, name: q.name}]
		})
	}
	before := make(map[string]Level, len(targets))
	raised := make(map[string]target, len(targets))
	checker0 := NewChecker(model, start, caveats, opts.now())
	for _, q := range targets {
		lvl, err := e.coalitionLevel(checker0, q.resource, q.name, coalition)
		if err != nil {
			return nil, err
		}
		before[q.key()] = lvl
		raised[q.key()] = q
	}
	return e.witnesses(raised, before, opts.maxWrites())
}

// escSig renders an escalation so two searches can be compared as sets: the
// object, permission, levels and the ordered writes, which is everything a
// witness carries. The output order of the search is map driven, so the test
// sorts the signatures rather than comparing slices position by position.
func escSig(e Escalation) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s#%s %s->%s |", e.Object, e.Permission, e.Before, e.After)
	for _, w := range e.Writes {
		verb := "add"
		if w.Delete {
			verb = "del"
		}
		fmt.Fprintf(&b, " %s:%s", verb, tupleKey(w.Relationship))
	}
	return b.String()
}

func escSigs(escs []Escalation) []string {
	out := make([]string, len(escs))
	for i, e := range escs {
		out[i] = escSig(e)
	}
	slices.Sort(out)
	return out
}

// broadGrantModel is a role type whose `super` relation grants every permission,
// each permission also readable through its own relation. An attacker that holds
// super holds every permission already, so writing any of those relations is an
// available move, since the relation occurs positively, that raises nothing. That
// is the shape that made the combined search branch wide and find nothing: the
// writes commute, so the bounded search walks every subset of them. With a
// viewer, view is reachable only through its relation, not super, so writing it
// does raise, a real escalation among the noise.
func broadGrantModel(t *testing.T, grants int, withViewer bool) *Model {
	t.Helper()
	role := &Type{
		Name:        "role",
		Relations:   []*Relation{{Name: "super", Allowed: []Allowed{{Type: "user"}}}},
		Permissions: []*Permission{{Name: "admin", Expr: Computed{Name: "super"}}},
	}
	for i := range grants {
		role.Relations = append(role.Relations, &Relation{Name: fmt.Sprintf("grant%d", i), Allowed: []Allowed{{Type: "user", Wildcard: true}}})
		role.Permissions = append(role.Permissions, &Permission{Name: fmt.Sprintf("perm%d", i), Expr: Union{Children: []Expr{Computed{Name: fmt.Sprintf("grant%d", i)}, Computed{Name: "super"}}}})
	}
	if withViewer {
		role.Relations = append(role.Relations, &Relation{Name: "viewer", Allowed: []Allowed{{Type: "user"}}})
		role.Permissions = append(role.Permissions, &Permission{Name: "view", Expr: Computed{Name: "viewer"}})
	}
	m, err := NewModel([]*Type{{Name: "user"}, role}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// broadGrantWrites lets a holder of admin write every grant relation, and anyone
// write viewer, so from a position holding super every grant write is available
// at once.
func broadGrantWrites(grants int, withViewer bool) *WriteModel {
	var writes []*WriteRule
	for i := range grants {
		writes = append(writes, &WriteRule{Resource: "role", Relation: fmt.Sprintf("grant%d", i), Operations: []Operation{Create, Touch}, Gate: Gate{Holds: "admin"}, Subject: SubjectSpec{Any: true}, Wildcard: true})
	}
	if withViewer {
		writes = append(writes, &WriteRule{Resource: "role", Relation: "viewer", Operations: []Operation{Create, Touch}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Any: true}})
	}
	return &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: writes}
}

// The saturation short-circuit must return exactly what the full bounded search
// returns: it may skip a target only when no reachable state raises it, so no
// witness is lost and none is invented. This checks the two agree across an E1
// schema with high branching and nothing to raise (the exploding shape), the
// same with a real raise mixed in, a plain raise, and a non-E1 schema where the
// short-circuit does not apply and every target is weighed either way.
func TestCandidateTargetsMatchesFullSearch(t *testing.T) {
	opts := Options{Now: time.Unix(0, 0)}
	attacker := object("user:attacker")

	cases := []struct {
		name      string
		model     *Model
		wm        *WriteModel
		start     []Relationship
		wantEmpty bool
	}{
		{
			// Holding super unlocks eight grant writes at once, but super already
			// grants every permission, so the greatest state raises nothing and the
			// search is skipped. Both paths return nothing.
			name:      "E1 high branching, nothing rises",
			model:     broadGrantModel(t, 8, false),
			wm:        broadGrantWrites(8, false),
			start:     []Relationship{rel("role:target", "super", "user:attacker")},
			wantEmpty: true,
		},
		{
			// The same noise, but viewer is writable by anyone and raises view, which
			// super does not grant, so one target rises among the writes that do not.
			name:  "E1 high branching, one real raise",
			model: broadGrantModel(t, 8, true),
			wm:    broadGrantWrites(8, true),
			start: []Relationship{rel("role:target", "super", "user:attacker")},
		},
		{
			// A plain raise with no noise: a coalition writes itself a viewer and
			// gains view on a document it did not own.
			name:  "plain raise",
			model: documents(t),
			wm: &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: []*WriteRule{
				{Resource: "document", Relation: "viewer", Operations: []Operation{Create}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Self: true}},
			}},
			start: []Relationship{rel("document:roadmap", "owner", "user:olivia")},
		},
		{
			// A mixed relation breaks E1, so the short-circuit does not apply and both
			// paths weigh every target. Deleting flag, which occurs negatively in q,
			// lifts the deny and raises q.
			name:  "non-E1 mixed relation, raise by delete",
			model: mixedFlagModel(t),
			wm: &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: []*WriteRule{
				{Resource: "res", Relation: "flag", Operations: []Operation{Create, Touch, Delete}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Any: true}},
			}},
			start: []Relationship{rel("res:target", "member", "user:attacker"), rel("res:target", "flag", "user:attacker")},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := escalationsScoped(tc.model, tc.wm, nil, tc.start, []Object{attacker}, nil, opts)
			if err != nil {
				t.Fatalf("escalationsScoped: %v", err)
			}
			want, err := escalationsAllTargets(tc.model, tc.wm, nil, tc.start, []Object{attacker}, nil, opts)
			if err != nil {
				t.Fatalf("escalationsAllTargets: %v", err)
			}
			if !slices.Equal(escSigs(got), escSigs(want)) {
				t.Errorf("short-circuit changed the escalations:\n got:  %v\n want: %v", escSigs(got), escSigs(want))
			}
			if tc.wantEmpty && len(got) != 0 {
				t.Errorf("expected no escalation, got %v", escSigs(got))
			}
			if !tc.wantEmpty && len(got) == 0 {
				t.Error("expected a raise, got none")
			}
		})
	}
}

// The scaled proposal search must return exactly what the full one returns. The
// scaling touches only the scoped path (the proposal pass), so the guard runs
// with a scope, the permissions a write could raise, as SafeGates passes it, and
// holds the scaled path (the default) against the full one (fullProposalSearch),
// which weighs every scoped target and branches on every move. The models are
// non-E1, where the two paths part: on an E1 model both saturate the same.
func TestProposalSearchScaledMatchesFull(t *testing.T) {
	attacker := object("user:attacker")

	cases := []struct {
		name      string
		model     *Model
		wm        *WriteModel
		start     []Relationship
		wantRaise bool
	}{
		{
			// Eight commuting grant writes a holder of super can make at once, plus a
			// mixed guard that breaks E1 but is gated on a permission the position
			// cannot reach, so the search is monotone in effect and decided by
			// saturation rather than by walking every subset of the grant writes.
			// Writing viewer still raises view, the one raise among the noise.
			name:      "mixed guard unreachable, monotone raise",
			model:     nonMonotoneGrantModel(t, 8),
			wm:        nonMonotoneGrantWrites(8),
			start:     []Relationship{rel("role:target", "super", "user:attacker")},
			wantRaise: true,
		},
		{
			// The same, but guard is gated on admin, which a holder of super has, so
			// the mixed relation is reachable and the search is not monotone: every
			// target is weighed in the bounded search, as the full path does.
			name:      "mixed guard reachable",
			model:     nonMonotoneGrantModel(t, 8),
			wm:        nonMonotoneGrantWritesReachable(8),
			start:     []Relationship{rel("role:target", "super", "user:attacker")},
			wantRaise: true,
		},
		{
			// The mixed relation reaches a target only through the gate of a write, not
			// by being read: writing secret needs p, and p reads flag. The cone has to
			// follow that gate, or reads_secret looks monotone and its raise is missed.
			name:      "mixed relation reached through a gate",
			model:     gatedByMixedModel(t),
			wm:        gatedByMixedWrites(),
			start:     []Relationship{rel("res:target", "member", "user:bystander")},
			wantRaise: true,
		},
		{
			// A mixed relation with nothing else writable: every target that can rise
			// does so through it, so none is pruned and the two paths weigh the same.
			// Deleting flag lifts the deny and raises q.
			name:  "mixed relation alone",
			model: mixedFlagModel(t),
			wm: &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: []*WriteRule{
				{Resource: "res", Relation: "flag", Operations: []Operation{Create, Touch, Delete}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Any: true}},
			}},
			start:     []Relationship{rel("res:target", "member", "user:attacker"), rel("res:target", "flag", "user:attacker")},
			wantRaise: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scope := newReach(tc.model, tc.wm).scopeOf(tc.model, tc.wm)
			scaled := Options{Now: time.Unix(0, 0)}
			full := Options{Now: time.Unix(0, 0), fullProposalSearch: true}
			got, err := escalationsScoped(tc.model, tc.wm, nil, tc.start, []Object{attacker}, scope, scaled)
			if err != nil {
				t.Fatalf("scaled: %v", err)
			}
			want, err := escalationsScoped(tc.model, tc.wm, nil, tc.start, []Object{attacker}, scope, full)
			if err != nil {
				t.Fatalf("full: %v", err)
			}
			if !slices.Equal(escSigs(got), escSigs(want)) {
				t.Errorf("scaled search changed the escalations:\n got:  %v\n want: %v", escSigs(got), escSigs(want))
			}
			if tc.wantRaise && len(want) == 0 {
				t.Fatal("test is vacuous: the full search found no raise to compare against")
			}
		})
	}
}

// nonMonotoneGrantModel is broadGrantModel with a mixed guard relation, positive
// in needguard and negative in safe, and a viewer relation super does not grant.
// The grant permissions read guard in neither, so they stay monotone while guard
// breaks E1 for the model, and view is a raise a monotone write still opens.
func nonMonotoneGrantModel(t *testing.T, grants int) *Model {
	t.Helper()
	role := &Type{
		Name: "role",
		Relations: []*Relation{
			{Name: "super", Allowed: []Allowed{{Type: "user"}}},
			{Name: "guard", Allowed: []Allowed{{Type: "user"}}},
			{Name: "viewer", Allowed: []Allowed{{Type: "user", Wildcard: true}}},
		},
		Permissions: []*Permission{
			{Name: "admin", Expr: Computed{Name: "super"}},
			{Name: "needguard", Expr: Computed{Name: "guard"}},
			{Name: "safe", Expr: Exclusion{Base: Computed{Name: "admin"}, Subtracted: []Expr{Computed{Name: "guard"}}}},
			{Name: "view", Expr: Computed{Name: "viewer"}},
		},
	}
	for i := range grants {
		role.Relations = append(role.Relations, &Relation{Name: fmt.Sprintf("grant%d", i), Allowed: []Allowed{{Type: "user", Wildcard: true}}})
		role.Permissions = append(role.Permissions, &Permission{Name: fmt.Sprintf("perm%d", i), Expr: Union{Children: []Expr{Computed{Name: fmt.Sprintf("grant%d", i)}, Computed{Name: "super"}}}})
	}
	m, err := NewModel([]*Type{{Name: "user"}, role}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// nonMonotoneGrantWrites gates guard on needguard, which needs guard, so a
// coalition that does not already hold guard can never write it: from a position
// holding super the search is monotone in effect. The grants and viewer are
// writable, viewer by anyone, so a monotone raise (view) is still reachable.
func nonMonotoneGrantWrites(grants int) *WriteModel {
	return nonMonotoneGrantWritesGated(grants, "needguard")
}

// nonMonotoneGrantWritesReachable gates guard on admin, which a holder of super
// has, so the mixed relation is reachable and the search is not monotone.
func nonMonotoneGrantWritesReachable(grants int) *WriteModel {
	return nonMonotoneGrantWritesGated(grants, "admin")
}

func nonMonotoneGrantWritesGated(grants int, guardGate string) *WriteModel {
	writes := []*WriteRule{
		{Resource: "role", Relation: "guard", Operations: []Operation{Create, Touch}, Gate: Gate{Holds: guardGate}, Subject: SubjectSpec{Any: true}},
		{Resource: "role", Relation: "viewer", Operations: []Operation{Create, Touch}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Any: true}, Wildcard: true},
	}
	for i := range grants {
		writes = append(writes, &WriteRule{Resource: "role", Relation: fmt.Sprintf("grant%d", i), Operations: []Operation{Create, Touch}, Gate: Gate{Holds: "admin"}, Subject: SubjectSpec{Any: true}, Wildcard: true})
	}
	return &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: writes}
}

// gatedByMixedModel reads flag positively in p and negatively in q, so flag is
// mixed, and reads secret in reads_secret. secret is not mixed, so reads_secret
// looks monotone until the write model gates writing secret on p, which reads
// flag: the raise of reads_secret then runs through the mixed relation.
func gatedByMixedModel(t *testing.T) *Model {
	t.Helper()
	res := &Type{
		Name: "res",
		Relations: []*Relation{
			{Name: "member", Allowed: []Allowed{{Type: "user"}}},
			{Name: "flag", Allowed: []Allowed{{Type: "user"}}},
			{Name: "secret", Allowed: []Allowed{{Type: "user"}}},
		},
		Permissions: []*Permission{
			{Name: "p", Expr: Computed{Name: "flag"}},
			{Name: "q", Expr: Exclusion{Base: Computed{Name: "member"}, Subtracted: []Expr{Computed{Name: "flag"}}}},
			{Name: "reads_secret", Expr: Computed{Name: "secret"}},
		},
	}
	m, err := NewModel([]*Type{{Name: "user"}, res}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// gatedByMixedWrites lets anyone write flag and lets a holder of p write secret,
// so raising reads_secret means first writing flag to hold p. The gate is why the
// cone of reads_secret has to reach flag.
func gatedByMixedWrites() *WriteModel {
	return &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: []*WriteRule{
		{Resource: "res", Relation: "flag", Operations: []Operation{Create, Touch, Delete}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Any: true}},
		{Resource: "res", Relation: "secret", Operations: []Operation{Create, Touch}, Gate: Gate{Holds: "p"}, Subject: SubjectSpec{Any: true}},
	}}
}

// mixedFlagModel reads flag positively in p and negatively in q, so a rule that
// both writes and deletes flag is a mixed relation and E1 does not hold.
func mixedFlagModel(t *testing.T) *Model {
	t.Helper()
	res := &Type{
		Name: "res",
		Relations: []*Relation{
			{Name: "member", Allowed: []Allowed{{Type: "user"}}},
			{Name: "flag", Allowed: []Allowed{{Type: "user"}}},
		},
		Permissions: []*Permission{
			{Name: "p", Expr: Computed{Name: "flag"}},
			{Name: "q", Expr: Exclusion{Base: Computed{Name: "member"}, Subtracted: []Expr{Computed{Name: "flag"}}}},
		},
	}
	m, err := NewModel([]*Type{{Name: "user"}, res}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return m
}
