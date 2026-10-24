package zanzibar

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// raisesOf reads the permissions a write to one relation could raise out of the
// index, as a set to assert membership on.
func raisesOf(index map[relRef][]permRef, typ, rel string) map[permRef]bool {
	out := map[permRef]bool{}
	for _, pr := range index[relRef{typ: typ, name: rel}] {
		out[pr] = true
	}
	return out
}

// The index must follow a permission through every arrow and userset to the
// relations it reads, so that a write to any of them lists the permission as one
// that could rise. The role-binding model is the hard case: a permission on org
// reads a relation on role across two arrows, through binding.
func TestRaisableIndexFollowsArrowsAcrossTypes(t *testing.T) {
	index := raisableIndex(rolebindingRBAC(t))

	admin := raisesOf(index, "role", "admin_perm")
	for _, want := range []permRef{
		{typ: "binding", name: "administer"},
		{typ: "org", name: "update"},
		{typ: "org", name: "policymanage"},
	} {
		if !admin[want] {
			t.Errorf("writing role#admin_perm should be able to raise %s#%s, but the index does not list it", want.typ, want.name)
		}
	}

	// pm_perm feeds policymanage, not update: a write to it must not list org#update,
	// or a safe gate for granting pm would be checked against a raise it cannot cause.
	pm := raisesOf(index, "role", "pm_perm")
	if !pm[permRef{typ: "org", name: "policymanage"}] {
		t.Error("writing role#pm_perm should be able to raise org#policymanage")
	}
	if pm[permRef{typ: "org", name: "update"}] {
		t.Error("writing role#pm_perm must not list org#update: update reads admin_perm, not pm_perm")
	}
}

// A relation reached only through a userset, and one read only inside an
// exclusion, must both be followed: deleting a banned tuple lifts a deny, and
// joining a team a document grants to takes its view.
func TestRaisableIndexFollowsUsersetsAndExclusions(t *testing.T) {
	index := raisableIndex(documents(t))
	if !raisesOf(index, "team", "member")[permRef{typ: "document", name: "view"}] {
		t.Error("writing team#member should be able to raise document#view through the viewer userset")
	}

	banned := &Type{
		Name: "resource",
		Relations: []*Relation{
			{Name: "viewer", Allowed: []Allowed{{Type: "user"}}},
			{Name: "banned", Allowed: []Allowed{{Type: "user"}}},
		},
		Permissions: []*Permission{
			{Name: "access", Expr: Exclusion{Base: Computed{Name: "viewer"}, Subtracted: []Expr{Computed{Name: "banned"}}}},
		},
	}
	m, err := NewModel([]*Type{{Name: "user"}, banned}, nil)
	if err != nil {
		t.Fatal(err)
	}
	index = raisableIndex(m)
	if !raisesOf(index, "resource", "banned")[permRef{typ: "resource", name: "access"}] {
		t.Error("deleting resource#banned should be able to raise access, which subtracts it")
	}
	if !raisesOf(index, "resource", "viewer")[permRef{typ: "resource", name: "access"}] {
		t.Error("writing resource#viewer should be able to raise access")
	}
}

// Scoping the raise check must leave every proposal exactly as it was: the
// permissions it skips are ones a write to the relation could not reach, so they
// read the same either way. Running SafeGates with the reach and with an empty
// one, which checks every permission, must give identical proposals.
func TestSafeGatesScopingMatchesUnscoped(t *testing.T) {
	cases := []struct {
		name  string
		model *Model
	}{
		{"documents", documents(t)},
		{"role-binding RBAC", rolebindingRBAC(t)},
		{"many flat permissions", wideFlatModel(t, 12)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wm := &WriteModel{}
			opts := Options{}

			scoped, err := safeGates(tc.model, wm, stubCaveats{}, newReach(tc.model, wm), opts)
			if err != nil {
				t.Fatalf("scoped: %v", err)
			}
			unscoped, err := safeGates(tc.model, wm, stubCaveats{}, reach{}, opts)
			if err != nil {
				t.Fatalf("unscoped: %v", err)
			}
			if got, want := proposalsDigest(scoped), proposalsDigest(unscoped); got != want {
				t.Errorf("scoping changed the proposals:\nscoped:\n%s\nunscoped:\n%s", got, want)
			}
		})
	}
}

// wideFlatModel is a type carrying many permissions, each fed by its own
// relation to every user at once, the shape a write to one relation reaches
// exactly one permission, so scoping skips the most.
func wideFlatModel(t *testing.T, perms int) *Model {
	t.Helper()
	doc := &Type{
		Name:        "doc",
		Relations:   []*Relation{{Name: "member", Allowed: []Allowed{{Type: "user"}}}},
		Permissions: []*Permission{{Name: "use", Expr: Computed{Name: "member"}}},
	}
	for i := range perms {
		doc.Relations = append(doc.Relations, &Relation{Name: fmt.Sprintf("t%d", i), Allowed: []Allowed{{Type: "user", Wildcard: true}}})
		doc.Permissions = append(doc.Permissions, &Permission{Name: fmt.Sprintf("p%d", i), Expr: Computed{Name: fmt.Sprintf("t%d", i)}})
	}
	m, err := NewModel([]*Type{{Name: "user"}, doc}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// proposalsDigest renders the proposals so two runs can be compared: the
// relation, and its safe and unsafe permissions sorted, since only the verdict
// per permission matters, not the order it was reached in.
func proposalsDigest(proposals []GateProposal) string {
	var b strings.Builder
	for _, p := range proposals {
		safe := slices.Clone(p.Safe)
		slices.Sort(safe)
		unsafe := make([]string, len(p.Unsafe))
		for i, u := range p.Unsafe {
			unsafe[i] = u.Permission
		}
		slices.Sort(unsafe)
		fmt.Fprintf(&b, "%s#%s safe=[%s] unsafe=[%s]\n", p.Type, p.Relation, strings.Join(safe, ","), strings.Join(unsafe, ","))
	}
	return b.String()
}
