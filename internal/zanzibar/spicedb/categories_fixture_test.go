package spicedb

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/saluc28/petard/internal/zanzibar"
)

func obj(typ, id string) zanzibar.Object { return zanzibar.Object{Type: typ, ID: id} }

func tup(resource zanzibar.Object, relation string, subject zanzibar.Subject) zanzibar.Relationship {
	return zanzibar.Relationship{Resource: resource, Relation: relation, Subject: subject}
}

func sub(o zanzibar.Object) zanzibar.Subject { return zanzibar.Subject{Object: o} }

func userset(o zanzibar.Object, relation string) zanzibar.Subject {
	return zanzibar.Subject{Object: o, Relation: relation}
}

// subjShape is the form a decisive write's subject takes, the axis section 7.1
// turns on: every object of a type at once, the writer itself, another object
// the coalition controls, a typed object such as the folder an arrow walks, or,
// for a delete, whichever controlled subject the deny named.
type subjShape int

const (
	subjSelf subjShape = iota
	subjOther
	subjWildcard
	subjTyped
	subjControlled
)

// categoryCase is a defect the fixture is built to show: from start the
// coalition raises permission on object, and the write that does it is of the
// shape the category names. It is not enough that the category appears
// somewhere over the fixture; it has to come from this write, so a label swap
// between two defects, or a category hung on the wrong raise, fails the case
// rather than passing on the union of what was seen.
type categoryCase struct {
	name       string
	start      []zanzibar.Relationship
	category   zanzibar.Category
	object     zanzibar.Object
	permission string

	// The decisive write that must carry the category.
	resource   string
	relation   string
	del        bool
	shape      subjShape
	subjType   string // the subject's type, for subjTyped
	gateHolds  string // the gate's permission, asserted when set
	gateAnyone bool   // asserted when true
}

func (tc categoryCase) matches(c zanzibar.ClassifiedEscalation, coalition []zanzibar.Object) bool {
	if c.Category != tc.category || c.Object != tc.object || c.Permission != tc.permission {
		return false
	}
	dw, ok := c.Decisive()
	if !ok {
		return false
	}
	rel := dw.Relationship
	if rel.Resource.Type != tc.resource || rel.Relation != tc.relation || dw.Delete != tc.del {
		return false
	}
	if !tc.shapeMatches(rel.Subject, dw.Writer, coalition) {
		return false
	}
	if tc.gateHolds != "" && (dw.Rule == nil || dw.Rule.Gate.Holds != tc.gateHolds) {
		return false
	}
	if tc.gateAnyone && (dw.Rule == nil || !dw.Rule.Gate.Anyone) {
		return false
	}
	return true
}

func (tc categoryCase) shapeMatches(s, writer zanzibar.Subject, coalition []zanzibar.Object) bool {
	switch tc.shape {
	case subjWildcard:
		return s.ID == zanzibar.WildcardID
	case subjSelf:
		return plainSubject(s) && s.Object == writer.Object
	case subjOther:
		return plainSubject(s) && s.Object != writer.Object
	case subjTyped:
		return plainSubject(s) && s.Type == tc.subjType && s.Object != writer.Object
	case subjControlled:
		return plainSubject(s) && controlledObject(s.Object, coalition)
	}
	return false
}

func plainSubject(s zanzibar.Subject) bool {
	return s.Relation == "" && s.ID != zanzibar.WildcardID
}

// controlledObject reports whether an object is one the coalition holds: a
// starting member or something a creation made (identifiers created-N). A
// delete carries no writer, so this is how the ban's own subject is checked.
func controlledObject(o zanzibar.Object, coalition []zanzibar.Object) bool {
	return strings.HasPrefix(o.ID, "created-") || slices.Contains(coalition, o)
}

// The extended fixture, with its write model, exercises every decisive-write
// category: from the deployment each defect needs, the engine labels the write
// that raises a permission with the matching category of section 7.1. Each case
// pins the write and the raise, so the test proves the fixture covers the
// taxonomy and that the engine reads each defect as the category it stands for,
// not merely that every label turns up somewhere. It also holds the invariant
// that a creation step is never a decisive write: a creation is setup, and none
// of the eight kinds is one.
func TestFixtureAllCategories(t *testing.T) {
	sample := findOne(t, fixtureValidation).Sample(time.Now())
	wm, err := zanzibar.LoadWriteModel(fixtureWrites)
	if err != nil {
		t.Fatalf("LoadWriteModel: %v", err)
	}
	mallory := obj("user", "mallory")
	coalition := []zanzibar.Object{mallory}
	d := obj("document", "d")
	opts := zanzibar.Options{Now: time.Unix(0, 0)}

	owned := []zanzibar.Relationship{tup(d, "owner", sub(obj("user", "olivia")))}

	cases := []categoryCase{
		{
			name:       "delete lifts a ban under an exclusion",
			start:      []zanzibar.Relationship{tup(d, "viewer", sub(mallory)), tup(d, "banned", sub(mallory))},
			category:   zanzibar.CategoryFailOpenOnAbsence,
			object:     d,
			permission: "access",
			resource:   "document",
			relation:   "banned",
			del:        true,
			shape:      subjControlled,
		},
		{
			name:       "a wildcard viewer admits every user",
			start:      owned,
			category:   zanzibar.CategoryGlobalSwitch,
			object:     d,
			permission: "view",
			resource:   "document",
			relation:   "viewer",
			shape:      subjWildcard,
		},
		{
			name:       "a parent folder the coalition owns is linked in",
			start:      owned,
			category:   zanzibar.CategoryTransitiveGrant,
			object:     d,
			permission: "view",
			resource:   "document",
			relation:   "parent",
			shape:      subjTyped,
			subjType:   "folder",
		},
		{
			name:       "joining a team the document grants to",
			start:      []zanzibar.Relationship{tup(d, "viewer", userset(obj("team", "design"), "member")), tup(d, "owner", sub(obj("user", "olivia")))},
			category:   zanzibar.CategoryAssumableIdentity,
			object:     d,
			permission: "view",
			resource:   "team",
			relation:   "member",
			shape:      subjSelf,
		},
		{
			name:       "an editor written for a sybil that never held view",
			start:      owned,
			category:   zanzibar.CategoryDelegationNotNarrowed,
			object:     d,
			permission: "edit",
			resource:   "document",
			relation:   "editor",
			shape:      subjOther,
			gateHolds:  "view",
		},
		{
			name:       "view gates writing editor for oneself",
			start:      []zanzibar.Relationship{tup(d, "viewer", sub(mallory))},
			category:   zanzibar.CategorySplitGrant,
			object:     d,
			permission: "edit",
			resource:   "document",
			relation:   "editor",
			shape:      subjSelf,
			gateHolds:  "view",
		},
		{
			name:       "an open gate lets the coalition write itself in",
			start:      owned,
			category:   zanzibar.CategoryAttrSelfWrite,
			object:     d,
			permission: "view",
			resource:   "document",
			relation:   "viewer",
			shape:      subjSelf,
			gateAnyone: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cs, err := zanzibar.Classify(sample.Model, wm, sample.Caveats, tc.start, coalition, opts)
			if err != nil {
				t.Fatalf("Classify: %v", err)
			}
			found := slices.ContainsFunc(cs, func(c zanzibar.ClassifiedEscalation) bool {
				return tc.matches(c, coalition)
			})
			if !found {
				t.Errorf("no %s escalation raising %s on %s by the expected write;\ngot:\n%s", tc.category, tc.permission, tc.object, dumpClassified(cs))
			}
			for _, c := range cs {
				dw, _ := c.Decisive()
				if dw.Creation != nil {
					t.Errorf("classified %s on %s#%s by a creation step (%s): a creation is setup, not a decisive write", c.Category, c.Object, c.Permission, dw.Relationship)
				}
				// edit = owner + editor, so only a write of one of those raises it.
				// A viewer or a parent found edit already up: the raise belongs to
				// the write that caused it, not to a later write of the same path.
				if c.Permission == "edit" && c.Object.Type == "document" && !dw.Delete {
					if r := dw.Relationship.Relation; r != "owner" && r != "editor" {
						t.Errorf("edit on %s classified %s by writing %s, which does not feed edit", c.Object, c.Category, r)
					}
				}
			}
		})
	}

	// The caveat category is not one of the closure's moves: the write model's
	// application-filled parameter produces it, so SelfAssertedExemptions reports
	// it rather than the classifier.
	exemptions := zanzibar.SelfAssertedExemptions(sample.Model, wm, opts)
	for _, want := range []string{
		"document#viewer, user_ip of caveat ip_allowlist",
		"document#editor, now of caveat not_expired",
	} {
		found := slices.ContainsFunc(exemptions, func(m zanzibar.Match) bool { return m.Subject == want })
		if !found {
			t.Errorf("no self-asserted exemption for %q; got %s", want, exemptionSubjects(exemptions))
		}
	}
}

// dumpClassified lists the classified escalations so a failing case shows what
// the engine did find, decisive write and all, next to what it wanted.
func dumpClassified(cs []zanzibar.ClassifiedEscalation) string {
	var b strings.Builder
	for _, c := range cs {
		dw, _ := c.Decisive()
		verb := "write"
		if dw.Delete {
			verb = "delete"
		}
		fmt.Fprintf(&b, "  %s raises %s on %s: %s %s by %s\n", c.Category, c.Permission, c.Object, verb, dw.Relationship, dw.Writer)
	}
	return b.String()
}

func exemptionSubjects(ms []zanzibar.Match) string {
	subjects := make([]string, len(ms))
	for i, m := range ms {
		subjects[i] = m.Subject
	}
	return strings.Join(subjects, "; ")
}
