package spicedb

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/saluc28/petard/internal/zanzibar"
)

const lowered = `use expiration

caveat on_weekday(day int, tz string) {
  day < 6
}

definition user {}

definition group {
  relation member: user | group#member
}

definition document {
  relation parent: document
  relation owner: user | user with on_weekday | user with expiration
  relation viewer: user:* | group#member
  permission view = (viewer + owner + parent->view) - owner - viewer
  permission all_view = parent.all(view)
  permission both = owner & viewer
  permission nothing = nil
}
`

// Every node the compiler produces has to come out as the node of the model
// that means the same thing, with the position it was declared at.
func TestCompileLowersEveryNode(t *testing.T) {
	schema, err := Compile("lowered.zed", nil, 1, lowered)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	m := schema.Model

	doc := m.Type("document")
	if doc == nil {
		t.Fatal("document not lowered")
	}
	if doc.Line != 13 || doc.File != "lowered.zed" {
		t.Errorf("document position = %s, want lowered.zed:13", doc.Position)
	}

	owner := doc.Relation("owner")
	wantOwner := []zanzibar.Allowed{
		{Type: "user"},
		{Type: "user", Caveat: "on_weekday"},
		{Type: "user", Expiration: true},
	}
	if !reflect.DeepEqual(owner.Allowed, wantOwner) {
		t.Errorf("owner allows %+v, want %+v", owner.Allowed, wantOwner)
	}
	viewer := doc.Relation("viewer")
	wantViewer := []zanzibar.Allowed{
		{Type: "user", Wildcard: true},
		{Type: "group", Relation: "member"},
	}
	if !reflect.DeepEqual(viewer.Allowed, wantViewer) {
		t.Errorf("viewer allows %+v, want %+v", viewer.Allowed, wantViewer)
	}

	// a - b - c compiles as (a - b) - c.
	outer, ok := doc.Permission("view").Expr.(zanzibar.Exclusion)
	if !ok {
		t.Fatalf("view = %T, want an exclusion", doc.Permission("view").Expr)
	}
	view, ok := outer.Base.(zanzibar.Exclusion)
	if !ok {
		t.Fatalf("view base = %T, want an exclusion", outer.Base)
	}
	if got := outer.Subtracted[0].(zanzibar.Computed).Name; got != "viewer" {
		t.Errorf("view subtracts %s last, want viewer", got)
	}
	base, ok := view.Base.(zanzibar.Union)
	if !ok || len(base.Children) != 3 {
		t.Fatalf("view base = %#v, want a union of three", view.Base)
	}
	if arrow, ok := base.Children[2].(zanzibar.Arrow); !ok || arrow.Through != "parent" || arrow.Target != "view" || arrow.All {
		t.Errorf("third child = %#v, want parent->view", base.Children[2])
	}
	if arrow, ok := doc.Permission("all_view").Expr.(zanzibar.Union).Children[0].(zanzibar.Arrow); !ok || !arrow.All {
		t.Errorf("all_view = %#v, want parent.all(view)", doc.Permission("all_view").Expr)
	}
	if _, ok := doc.Permission("both").Expr.(zanzibar.Intersection); !ok {
		t.Errorf("both = %T, want an intersection", doc.Permission("both").Expr)
	}
	if _, ok := doc.Permission("nothing").Expr.(zanzibar.Union).Children[0].(zanzibar.Nil); !ok {
		t.Errorf("nothing = %#v, want nil", doc.Permission("nothing").Expr)
	}

	caveat := m.Caveat("on_weekday")
	wantParams := []zanzibar.Parameter{{Name: "day", Type: "int"}, {Name: "tz", Type: "string"}}
	if caveat == nil || !reflect.DeepEqual(caveat.Parameters, wantParams) {
		t.Errorf("on_weekday = %+v, want parameters %+v", caveat, wantParams)
	}
}

// A schema inside a validation file starts below its key, and positions have
// to point into the file rather than into the schema text.
func TestCompileCountsFromTheFirstLine(t *testing.T) {
	schema, err := Compile("inside.yaml", nil, 5, "definition user {}\n\ndefinition team {\n  relation member: user\n}")
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	if got := schema.Model.Type("team").Relation("member").Line; got != 8 {
		t.Errorf("team#member line = %d, want 8", got)
	}
}

// What SpiceDB's type system refuses has to be refused here too, since the
// engine relies on every name it meets being declared.
func TestCompileRefuses(t *testing.T) {
	tests := []struct {
		name   string
		schema string
		want   string
	}{
		{
			name:   "syntax",
			schema: "definition user {",
			want:   "",
		},
		{
			name:   "permission using an undeclared name",
			schema: "definition user {}\ndefinition doc {\n  relation owner: user\n  permission view = owner + reader\n}",
			want:   "uses reader, which is not declared",
		},
		{
			name:   "arrow walking a permission",
			schema: "definition user {}\ndefinition doc {\n  relation owner: user\n  permission edit = owner\n  permission view = edit->owner\n}",
			want:   "only a relation can be walked",
		},
		{
			name:   "arrow walking a wildcard",
			schema: "definition user {\n  relation self_ref: user\n}\ndefinition doc {\n  relation reader: user:*\n  permission view = reader->self_ref\n}",
			want:   "a wildcard cannot be walked",
		},
		{
			name:   "relation allowing an undeclared type",
			schema: "definition doc {\n  relation owner: user\n}",
			want:   "allows user, which is not declared",
		},
		{
			name:   "relation allowing an undeclared userset",
			schema: "definition user {}\ndefinition doc {\n  relation owner: user#member\n}",
			want:   "allows user#member, which is not declared",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Compile("bad.zed", nil, 1, tt.schema)
			if !errors.Is(err, ErrSchema) {
				t.Fatalf("Compile() error = %v, want ErrSchema", err)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Compile() error = %q, want it to say %q", err, tt.want)
			}
		})
	}
}

// A caveat is decided when the context fills what it reads, and stays
// conditional when it does not.
func TestEvaluate(t *testing.T) {
	schema, err := Compile("caveat.zed", nil, 1, `caveat ip_allowlist(user_ip ipaddress, cidr string) {
  user_ip.in_cidr(cidr)
}
definition user {}`)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	tests := []struct {
		name    string
		context map[string]any
		want    zanzibar.Level
	}{
		{name: "inside", context: map[string]any{"cidr": "10.0.0.0/8", "user_ip": "10.1.2.3"}, want: zanzibar.Yes},
		{name: "outside", context: map[string]any{"cidr": "10.0.0.0/8", "user_ip": "192.168.1.1"}, want: zanzibar.No},
		{name: "address missing", context: map[string]any{"cidr": "10.0.0.0/8"}, want: zanzibar.Conditional},
		{name: "nothing written", context: nil, want: zanzibar.Conditional},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := schema.Evaluate("ip_allowlist", tt.context)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("Evaluate() = %s, want %s", got, tt.want)
			}
		})
	}

	if _, err := schema.Evaluate("missing", nil); err == nil {
		t.Error("Evaluate() of an undeclared caveat returned no error")
	}
}
