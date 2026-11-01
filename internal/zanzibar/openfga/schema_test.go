package openfga

import (
	"errors"
	"reflect"
	"testing"

	"github.com/saluc28/petard/internal/zanzibar"
)

// compile compiles a model that has to compile.
func compile(t *testing.T, text string) *Schema {
	t.Helper()
	s, err := Compile("model.fga", text)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return s
}

// One name in OpenFGA is what is written and what is asked. It lowers to a relation
// where the rewrite holds _this, and to a permission where the name answers a check
// as an access. A relation an arrow walks, or that is read only to subtract it,
// stays a relation alone.
func TestCompileSplitsWhatIsWrittenFromWhatIsAsked(t *testing.T) {
	const model = `model
  schema 1.1
type user
type team
  relations
    define lead: [user]
type group
  relations
    define admin: [user]
    define member: [user, team#lead] or admin
type folder
  relations
    define viewer: [user]
type document
  relations
    define parent: [folder]
    define owner: [user]
    define banned: [user]
    define viewer: [user, group#member, user:*] or owner or viewer from parent
    define commenter: [user] but not banned
    define editor: [user] and owner
    define can_read: viewer
    define can_audit: can_read and owner
`
	doc := compile(t, model).Model.Type("document")

	tests := []struct {
		name     string
		relation bool
		perm     zanzibar.Expr
	}{
		{name: "parent", relation: true},
		{name: "banned", relation: true},
		{name: "owner", relation: true, perm: zanzibar.Stored{Name: "owner"}},
		{name: "viewer", relation: true, perm: zanzibar.Union{Children: []zanzibar.Expr{
			zanzibar.Stored{Name: "viewer"},
			zanzibar.Computed{Name: "owner"},
			zanzibar.Arrow{Through: "parent", Target: "viewer"},
		}}},
		{name: "commenter", relation: true, perm: zanzibar.Exclusion{
			Base:       zanzibar.Stored{Name: "commenter"},
			Subtracted: []zanzibar.Expr{zanzibar.Computed{Name: "banned"}},
		}},
		{name: "editor", relation: true, perm: zanzibar.Intersection{Children: []zanzibar.Expr{
			zanzibar.Stored{Name: "editor"},
			zanzibar.Computed{Name: "owner"},
		}}},
		{name: "can_read", perm: zanzibar.Computed{Name: "viewer"}},
		{name: "can_audit", perm: zanzibar.Intersection{Children: []zanzibar.Expr{
			zanzibar.Computed{Name: "can_read"},
			zanzibar.Computed{Name: "owner"},
		}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := doc.Relation(tt.name) != nil; got != tt.relation {
				t.Errorf("relation declared = %v, want %v", got, tt.relation)
			}
			p := doc.Permission(tt.name)
			switch {
			case tt.perm == nil && p != nil:
				t.Errorf("permission = %#v, want none", p.Expr)
			case tt.perm != nil && p == nil:
				t.Error("no permission, want one")
			case tt.perm != nil && !reflect.DeepEqual(p.Expr, tt.perm):
				t.Errorf("permission = %#v, want %#v", p.Expr, tt.perm)
			}
		})
	}

	// A relation nothing reads is what the application asks about, so it is an access.
	unread := compile(t, "model\n  schema 1.1\ntype user\ntype doc\n  relations\n    define label: [user]\n")
	if unread.Model.Type("doc").Permission("label") == nil {
		t.Error("a relation nothing reads has no permission, and only the application can be asking about it")
	}
}

// Whether a direct relation is an access depends on the others: group#member is
// read only to subtract it until document#viewer, itself asked by nothing, gets a
// permission of its own and reads it positively. The promotion has to reach that
// answer whatever order the relations come in.
func TestCompilePromotesUntilNothingChanges(t *testing.T) {
	s := compile(t, `model
  schema 1.1
type user
type group
  relations
    define member: [user]
type document
  relations
    define banned: [group#member]
    define viewer: [group#member]
    define reader: [user] but not banned
`)
	if s.Model.Type("group").Permission("member") == nil {
		t.Error("group#member has no permission, and document#viewer reads it")
	}
	if s.Model.Type("document").Permission("banned") != nil {
		t.Error("document#banned is read only to subtract it, and got a permission")
	}
}

// A userset read only under an exclusion stays an input all the way down.
func TestCompileKeepsASubtractedUsersetAnInput(t *testing.T) {
	s := compile(t, `model
  schema 1.1
type user
type group
  relations
    define member: [user]
type document
  relations
    define banned: [group#member]
    define reader: [user] but not banned
`)
	if s.Model.Type("group").Permission("member") != nil {
		t.Error("group#member is read only to subtract it, and got a permission")
	}
	exact, mixed := zanzibar.CheckE1(s.Model, &zanzibar.WriteModel{Writes: []*zanzibar.WriteRule{
		{Resource: "group", Relation: "member", Operations: []zanzibar.Operation{zanzibar.Delete}, Gate: zanzibar.Gate{Anyone: true}, Subject: zanzibar.SubjectSpec{Self: true}},
	}})
	if !exact {
		t.Errorf("E1 fails over %v: an exclusion must not turn its input into a mixed relation", mixed)
	}
}

// Every form a type restriction can take reaches the relation, the condition on the
// form that carries it and on no other.
// A model says which relations OpenFGA can walk to a fixpoint: one that only reaches
// itself, through a userset or an arrow, for the subjects that can hold it. A relation
// in a loop with another has to meet that loop.
func TestCompileSaysHowOpenFGAWalks(t *testing.T) {
	const model = `model
  schema 1.1
type user
type robot
type group
  relations
    define member: [user, group#member]
    define reader: member
type folder
  relations
    define parent: [folder]
    define viewer: [user] or viewer from parent
type team
  relations
    define member: [user, team#admin]
    define admin: [user, team#member]
type document
  relations
    define viewer: [user, robot]`

	walk := compile(t, model).Model.Walk
	if !walk.StopsAtFailedCaveat {
		t.Error("StopsAtFailedCaveat = false, OpenFGA reads a tuple's condition before following it")
	}
	want := map[zanzibar.FixpointWalk]bool{
		{Type: "group", Name: "member", SubjectType: "user"}:  true,
		{Type: "folder", Name: "viewer", SubjectType: "user"}: true,
	}
	if !reflect.DeepEqual(walk.Fixpoint, want) {
		t.Errorf("Fixpoint = %v, want %v", walk.Fixpoint, want)
	}
}

func TestCompileLowersTypeRestrictions(t *testing.T) {
	s := compile(t, `model
  schema 1.1
type user
type group
  relations
    define member: [user]
type document
  relations
    define viewer: [user, user with fresh, user:*, user:* with fresh, group#member, group#member with fresh]

condition fresh(age: int) {
  age < 10
}
`)
	want := []zanzibar.Allowed{
		{Type: "user"},
		{Type: "user", Caveat: "fresh"},
		{Type: "user", Wildcard: true},
		{Type: "user", Wildcard: true, Caveat: "fresh"},
		{Type: "group", Relation: "member"},
		{Type: "group", Relation: "member", Caveat: "fresh"},
	}
	if got := s.Model.Type("document").Relation("viewer").Allowed; !reflect.DeepEqual(got, want) {
		t.Errorf("Allowed = %+v, want %+v", got, want)
	}
}

func TestCompileLowersConditions(t *testing.T) {
	s := compile(t, `model
  schema 1.1
type user
type document
  relations
    define viewer: [user with fresh, user with $expression]

condition fresh(age: int, tags: list<string>, seen: map<int>, when: timestamp, from: ipaddress) {
  age < 10
}
`)
	fresh := s.Model.Caveat("fresh")
	if fresh == nil {
		t.Fatal("condition fresh was not lowered")
	}
	want := []zanzibar.Parameter{
		{Name: "age", Type: "int"},
		{Name: "from", Type: "ipaddress"},
		{Name: "seen", Type: "map<int>"},
		{Name: "tags", Type: "list<string>"},
		{Name: "when", Type: "timestamp"},
	}
	if !reflect.DeepEqual(fresh.Parameters, want) {
		t.Errorf("Parameters = %+v, want %+v", fresh.Parameters, want)
	}

	// The inline condition is declared by no model, and the writer fills the whole of
	// it, so it is lowered with the expression as the parameter somebody fills.
	inline := s.Model.Caveat("$expression")
	if inline == nil {
		t.Fatal("the inline condition was not lowered")
	}
	if len(inline.Parameters) != 1 || inline.Parameters[0].Name != "expression" {
		t.Errorf("inline condition parameters = %+v, want expression", inline.Parameters)
	}
	if plain := compile(t, "model\n  schema 1.1\ntype user\n"); plain.Model.Caveat("$expression") != nil {
		t.Error("a model no relation of which admits the inline condition declares it")
	}
}

// A model OpenFGA refuses is refused here, by OpenFGA's own validation: what the
// engine reads is held to what the product accepts.
func TestCompileRefusesWhatOpenFGARefuses(t *testing.T) {
	tests := []struct {
		name  string
		model string
	}{
		{name: "not the language", model: "this is not a model"},
		{name: "a schema it does not support", model: "model\n  schema 1.0\ntype user\n"},
		{name: "a relation it does not declare", model: "model\n  schema 1.1\ntype user\ntype doc\n  relations\n    define viewer: editor\n"},
		{name: "a type it does not declare", model: "model\n  schema 1.1\ntype doc\n  relations\n    define viewer: [user]\n"},
		{name: "a walked relation that is not direct", model: "model\n  schema 1.1\ntype user\ntype doc\n  relations\n    define owner: [user]\n    define parent: [doc] or owner\n    define viewer: viewer from parent\n"},
		{name: "a walked relation that admits a wildcard", model: "model\n  schema 1.1\ntype user\ntype doc\n  relations\n    define parent: [doc:*]\n    define viewer: [user] or viewer from parent\n"},
		{name: "a walked relation that admits a userset", model: "model\n  schema 1.1\ntype user\ntype group\n  relations\n    define member: [user]\ntype doc\n  relations\n    define parent: [group#member]\n    define viewer: member from parent\n"},
		{name: "a loop with no way in", model: "model\n  schema 1.1\ntype doc\n  relations\n    define a: b\n    define b: a\n"},
		{name: "a condition it does not declare", model: "model\n  schema 1.1\ntype user\ntype doc\n  relations\n    define viewer: [user with nope]\n"},
		{name: "a condition that is not boolean", model: "model\n  schema 1.1\ntype user\ntype doc\n  relations\n    define viewer: [user with c]\n\ncondition c(x: int) {\n  x + 1\n}\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Compile("model.fga", tt.model); !errors.Is(err, ErrModel) {
				t.Errorf("Compile() error = %v, want ErrModel", err)
			}
		})
	}
}

func TestCompileJSON(t *testing.T) {
	s, err := CompileJSON("model.json", `{
  "schema_version": "1.1",
  "type_definitions": [
    {"type": "user"},
    {
      "type": "document",
      "relations": {"viewer": {"union": {"child": [{"this": {}}, {"computedUserset": {"relation": "owner"}}]}}, "owner": {"this": {}}},
      "metadata": {"relations": {
        "viewer": {"directly_related_user_types": [{"type": "user"}]},
        "owner": {"directly_related_user_types": [{"type": "user"}]}
      }}
    }
  ]
}`)
	if err != nil {
		t.Fatalf("CompileJSON: %v", err)
	}
	doc := s.Model.Type("document")
	if doc.Relation("viewer") == nil || doc.Permission("viewer") == nil {
		t.Error("viewer did not lower to a relation and a permission")
	}
	if doc.Relation("viewer").File != "model.json" {
		t.Errorf("position = %s, want the file", doc.Relation("viewer").Position)
	}
	if _, err := CompileJSON("model.json", "{"); !errors.Is(err, ErrModel) {
		t.Errorf("CompileJSON of broken JSON: error = %v, want ErrModel", err)
	}
}

// A finding names a relation, and has to say where to look. The compiled form holds
// no positions, so these come from the parse tree: comments and blank lines keep
// every line where it is.
func TestCompileReportsWhereThingsAreDeclared(t *testing.T) {
	s := compile(t, `model
  schema 1.1

# a comment on a line of its own
type user

type document
  relations
    define owner: [user] # a comment after a declaration

    # another
    define viewer: [user with fresh] or owner

condition fresh(age: int) {
  age < 10
}
`)
	doc := s.Model.Type("document")
	tests := []struct {
		what string
		got  zanzibar.Position
		line int
	}{
		{"type user", s.Model.Type("user").Position, 5},
		{"type document", doc.Position, 7},
		{"relation owner", doc.Relation("owner").Position, 9},
		{"permission owner", doc.Permission("owner").Position, 9},
		{"relation viewer", doc.Relation("viewer").Position, 12},
		{"condition fresh", s.Model.Caveat("fresh").Position, 14},
	}
	for _, tt := range tests {
		t.Run(tt.what, func(t *testing.T) {
			if tt.got.Line != tt.line || tt.got.File != "model.fga" {
				t.Errorf("position = %s, want model.fga line %d", tt.got, tt.line)
			}
		})
	}

	// The compiled form holds relations in a map; the source order is what a report
	// reads in, on every run.
	if doc.Relations[0].Name != "owner" || doc.Relations[1].Name != "viewer" {
		t.Errorf("relations in order %s, %s, want owner, viewer", doc.Relations[0].Name, doc.Relations[1].Name)
	}
}

// Conditions are evaluated in OpenFGA's own environment, so its ipaddress type
// behaves as it does there, and a missing parameter leaves the answer open whatever
// the rest of the expression decides: OpenFGA refuses to answer in that case, unlike
// SpiceDB, which decides what partial evaluation can.
func TestEvaluate(t *testing.T) {
	s := compile(t, `model
  schema 1.1
type user
type document
  relations
    define viewer: [user with under_ten, user with either, user with from_office, user with $expression]

condition under_ten(age: int) {
  age < 10
}

condition either(a: bool, b: bool) {
  a || b
}

condition from_office(source: ipaddress, office: string) {
  source.in_cidr(office)
}
`)
	tests := []struct {
		name      string
		condition string
		values    map[string]any
		want      zanzibar.Level
		wantErr   bool
	}{
		{name: "holds", condition: "under_ten", values: map[string]any{"age": 3}, want: zanzibar.Yes},
		{name: "does not hold", condition: "under_ten", values: map[string]any{"age": 30}, want: zanzibar.No},
		{name: "a parameter is missing", condition: "under_ten", want: zanzibar.Conditional},
		{name: "a key it does not name is ignored", condition: "under_ten", values: map[string]any{"age": 3, "other": "x"}, want: zanzibar.Yes},
		{name: "the rest decides and one is still missing", condition: "either", values: map[string]any{"a": true}, want: zanzibar.Conditional},
		{name: "every parameter given", condition: "either", values: map[string]any{"a": false, "b": true}, want: zanzibar.Yes},
		{name: "a custom type of its own", condition: "from_office", values: map[string]any{"source": "10.0.0.7", "office": "10.0.0.0/8"}, want: zanzibar.Yes},
		{name: "outside the range", condition: "from_office", values: map[string]any{"source": "192.168.0.7", "office": "10.0.0.0/8"}, want: zanzibar.No},
		{name: "a value of the wrong type", condition: "under_ten", values: map[string]any{"age": "old"}, want: zanzibar.Conditional},
		{name: "a condition nobody declared", condition: "nope", wantErr: true},
		{name: "an inline condition stays open", condition: "$expression", values: map[string]any{"expression": "true"}, want: zanzibar.Conditional},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := s.Evaluate(tt.condition, tt.values)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Evaluate() error = %v, want error %v", err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("Evaluate() = %s, want %s", got, tt.want)
			}
		})
	}
}
