package identity

import (
	"errors"
	"strings"
	"testing"

	"github.com/saluc28/petard/internal/graph"
	"github.com/saluc28/petard/internal/zanzibar"
)

const usersByObjectID = `schema_version: 1
model: identities
types:
  - type: user
    kind: User
    property: objectid
`

func TestParse(t *testing.T) {
	cases := []struct {
		name    string
		content string
		wantErr error
		inErr   string
	}{
		{name: "a map", content: usersByObjectID},
		{
			name:    "a write model beside the schema",
			content: "schema_version: 1\nmodel: relationship-writes\nwrites: []\n",
			wantErr: ErrNotAMap,
		},
		{
			name:    "a validation file beside the schema",
			content: "schema: |-\n  definition user {}\nrelationships: \"\"\n",
			wantErr: ErrNotAMap,
		},
		{
			name:    "another version",
			content: strings.Replace(usersByObjectID, "schema_version: 1", "schema_version: 2", 1),
			wantErr: ErrInvalid,
			inErr:   "version 2",
		},
		{
			name:    "no type",
			content: "schema_version: 1\nmodel: identities\ntypes: []\n",
			wantErr: ErrInvalid,
			inErr:   "names no type",
		},
		{
			name:    "an entry without a property",
			content: "schema_version: 1\nmodel: identities\ntypes:\n  - type: user\n    kind: User\n",
			wantErr: ErrInvalid,
			inErr:   "entry 0",
		},
		{
			// Two entries for one type would make a subject two nodes.
			name:    "a type named twice",
			content: usersByObjectID + "  - type: user\n    kind: AZUser\n    property: objectid\n",
			wantErr: ErrInvalid,
			inErr:   "user is named twice",
		},
		{
			name:    "a field the format does not have",
			content: usersByObjectID + "    match: fuzzy\n",
			inErr:   "match",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := Parse([]byte(tc.content))
			if tc.wantErr == nil && tc.inErr == "" {
				if err != nil {
					t.Fatalf("Parse() = %v, want the map", err)
				}
				if len(m.Types) != 1 || m.Types[0] != (Entry{Type: "user", Kind: "User", Property: "objectid"}) {
					t.Errorf("types = %+v", m.Types)
				}
				return
			}
			if err == nil {
				t.Fatal("Parse() accepted it")
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Errorf("Parse() = %v, want %v", err, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.inErr) {
				t.Errorf("Parse() = %v, want it to say %q", err, tc.inErr)
			}
		})
	}
}

// principals is a graph holding a principal for each id, marked as supposed when
// the id is in supposed.
func principals(t *testing.T, ids []string, supposed ...string) *graph.Graph {
	t.Helper()
	g := graph.New()
	for _, id := range ids {
		props := map[string]any{graph.PropName: id}
		for _, s := range supposed {
			if s == id {
				props[graph.PropHypothetical] = true
			}
		}
		if err := g.AddNode(graph.Node{ID: id, Kind: graph.NodeKindPrincipal, Properties: props}); err != nil {
			t.Fatal(err)
		}
	}
	return g
}

func rel(resource, relation, subject string) zanzibar.Relationship {
	r := zanzibar.Relationship{Relation: relation}
	typ, id, _ := strings.Cut(resource, ":")
	r.Resource = zanzibar.Object{Type: typ, ID: id}
	object, userset, _ := strings.Cut(subject, "#")
	typ, id, _ = strings.Cut(object, ":")
	r.Subject = zanzibar.Subject{Object: zanzibar.Object{Type: typ, ID: id}, Relation: userset}
	return r
}

func mustParse(t *testing.T, content, path string) *Map {
	t.Helper()
	m, err := Parse([]byte(content))
	if err != nil {
		t.Fatal(err)
	}
	m.Path = path
	return m
}

// Only a subject the relationships name directly, of a type the map names, and
// drawn as a principal that is not supposed, is linked, once, in the order the
// principals were drawn.
func TestLinks(t *testing.T) {
	// Every subject left out below has a principal of its own, so that the rule
	// that leaves it out is the only thing that does.
	m := mustParse(t, usersByObjectID+"  - type: team\n    kind: Group\n    property: objectid\n", "authz/identities.yaml")
	g := principals(t,
		[]string{"user:S-1-5-21-1-1106", "user:S-1-5-21-1-1105", "user:attacker", "team:eng", "user:*", "service:S-1-5-21-1-1", "user:nobody"},
		"user:attacker")
	relationships := []zanzibar.Relationship{
		rel("document:a", "viewer", "user:S-1-5-21-1-1105"),
		rel("document:b", "viewer", "user:S-1-5-21-1-1105"), // a second tuple for the same subject
		rel("document:a", "owner", "user:S-1-5-21-1-1106"),
		rel("document:c", "viewer", "user:attacker"),        // supposed by the analysis
		rel("document:c", "viewer", "user:*"),               // a wildcard
		rel("document:c", "viewer", "team:eng#member"),      // a userset
		rel("team:eng", "member", "user:S-1-5-21-1-9999"),   // no principal drawn for it
		rel("document:d", "viewer", "service:S-1-5-21-1-1"), // a type the map does not name
	}

	links, err := Links(g, []Source{{Relationships: relationships, Map: m}})
	if err != nil {
		t.Fatal(err)
	}
	want := []Link{
		{Principal: "user:S-1-5-21-1-1106", Entry: m.Types[0], ID: "S-1-5-21-1-1106", Map: "authz/identities.yaml"},
		{Principal: "user:S-1-5-21-1-1105", Entry: m.Types[0], ID: "S-1-5-21-1-1105", Map: "authz/identities.yaml"},
	}
	if len(links) != len(want) {
		t.Fatalf("links = %+v, want %+v", links, want)
	}
	for i := range want {
		if links[i] != want[i] {
			t.Errorf("link %d = %+v, want %+v", i, links[i], want[i])
		}
	}
}

// A schema with no map beside it links nothing, and a node of another kind under
// the subject's id is not a principal to link.
func TestLinksWithoutAMapOrAPrincipal(t *testing.T) {
	g := graph.New()
	if err := g.AddNode(graph.Node{ID: "user:S-1", Kind: graph.NodeKindResource}); err != nil {
		t.Fatal(err)
	}
	r := []zanzibar.Relationship{rel("document:a", "viewer", "user:S-1")}
	m := mustParse(t, usersByObjectID, "identities.yaml")
	for _, sources := range [][]Source{{{Relationships: r}}, {{Relationships: r, Map: m}}} {
		links, err := Links(g, sources)
		if err != nil || len(links) != 0 {
			t.Errorf("Links() = %+v, %v; want nothing", links, err)
		}
	}
}

// One principal can come from two schemas. Two maps that agree link it once;
// two that make it two different nodes are an error rather than a choice.
func TestLinksFromTwoSchemas(t *testing.T) {
	g := principals(t, []string{"user:S-1"})
	r := []zanzibar.Relationship{rel("document:a", "viewer", "user:S-1")}
	first := mustParse(t, usersByObjectID, "a/identities.yaml")
	same := mustParse(t, usersByObjectID, "b/identities.yaml")
	other := mustParse(t, strings.Replace(usersByObjectID, "kind: User", "kind: AZUser", 1), "c/identities.yaml")

	links, err := Links(g, []Source{{Relationships: r, Map: first}, {Relationships: r, Map: same}})
	if err != nil || len(links) != 1 || links[0].Map != "a/identities.yaml" {
		t.Errorf("two maps that agree: Links() = %+v, %v; want one link from the first", links, err)
	}

	_, err = Links(g, []Source{{Relationships: r, Map: first}, {Relationships: r, Map: other}})
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "c/identities.yaml") {
		t.Errorf("two maps that disagree: Links() = %v, want ErrInvalid naming both maps", err)
	}
}
