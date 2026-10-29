package zanzibar

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

// classifySig renders a classified escalation so two runs can be compared as
// sets: the category, the object and permission it raises, the levels, and the
// decisive write. Scoping may only drop a target no write can reach, so the two
// runs must agree on all of these.
func classifySig(c ClassifiedEscalation) string {
	dw := c.DecisiveWrite
	verb := "add"
	if dw.Delete {
		verb = "del"
	}
	return fmt.Sprintf("%s|%s#%s|%s->%s|%s:%s", c.Category, c.Object, c.Permission, c.Before, c.After, verb, tupleKey(dw.Relationship))
}

func classifySigs(cs []ClassifiedEscalation) []string {
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = classifySig(c)
	}
	slices.Sort(out)
	return out
}

// Scoping the findings path must leave every finding exactly as it was: the
// permissions it skips are ones no write under the model can raise, so they
// classify to nothing either way. Running classify with the reach and with a nil
// scope, which weighs every target, must give identical findings, from every
// starting position the schema generates and from the empty start.
func TestClassifyScopingMatchesUnscoped(t *testing.T) {
	opts := Options{Now: time.Unix(0, 0)}
	cases := []struct {
		name  string
		model *Model
		wm    *WriteModel
	}{
		{
			name:  "documents, viewer self-write",
			model: documents(t),
			wm: &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: []*WriteRule{
				{Resource: "document", Relation: "viewer", Operations: []Operation{Create, Touch}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Any: true}},
			}},
		},
		{
			name:  "many flat permissions, one writable relation",
			model: wideFlatModel(t, 20),
			wm: &WriteModel{SchemaVersion: 1, Kind: "relationship-writes", Writes: []*WriteRule{
				{Resource: "doc", Relation: "t0", Operations: []Operation{Create, Touch}, Gate: Gate{Anyone: true}, Subject: SubjectSpec{Any: true}, Wildcard: true},
			}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scope := newReach(tc.model, tc.wm).scopeOf(tc.model, tc.wm)
			if scope == nil {
				t.Fatal("expected a resolvable scope for this write model")
			}
			starts := [][]Relationship{nil}
			for _, typ := range subjectTypes(tc.model) {
				for _, p := range StartingPositions(tc.model, Object{Type: typ, ID: "attacker"}, opts) {
					starts = append(starts, p.Tuples)
				}
			}
			for _, typ := range subjectTypes(tc.model) {
				attacker := Object{Type: typ, ID: "attacker"}
				for _, start := range starts {
					scoped, err := classifyScoped(tc.model, tc.wm, stubCaveats{}, start, []Object{attacker}, scope, opts)
					if err != nil {
						t.Fatalf("scoped: %v", err)
					}
					unscoped, err := classifyScoped(tc.model, tc.wm, stubCaveats{}, start, []Object{attacker}, nil, opts)
					if err != nil {
						t.Fatalf("unscoped: %v", err)
					}
					if got, want := classifySigs(scoped), classifySigs(unscoped); !slices.Equal(got, want) {
						t.Errorf("scoping changed the findings from %v:\n scoped:   %v\n unscoped: %v",
							start, strings.Join(got, " "), strings.Join(want, " "))
					}
				}
			}
		})
	}
}
