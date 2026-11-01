// Package zanzibartest holds what the tests of more than one front end share: the
// checks to hold the engine against a real product with.
package zanzibartest

import (
	"slices"

	"github.com/saluc28/petard/internal/zanzibar"
)

// UnlistedID names an object no relationship mentions, so that every type has one
// object only a wildcard or nothing at all can grant to.
const UnlistedID = "petard-unlisted"

// Objects is every object the relationships mention, and one more per type that
// none of them mentions.
func Objects(model *zanzibar.Model, relationships []zanzibar.Relationship) []zanzibar.Object {
	seen := map[zanzibar.Object]bool{}
	var out []zanzibar.Object
	add := func(o zanzibar.Object) {
		if o.ID == zanzibar.WildcardID || seen[o] || model.Type(o.Type) == nil {
			return
		}
		seen[o] = true
		out = append(out, o)
	}
	for _, r := range relationships {
		add(r.Resource)
		add(r.Subject.Object)
	}
	for _, typ := range model.Types {
		add(zanzibar.Object{Type: typ.Name, ID: UnlistedID})
	}
	return out
}

// Subjects is every subject that can be asked about: the objects of a type some
// relation allows as a subject, and of every type when a permission uses self, and
// the usersets a relation allows, on every object of their type.
func Subjects(model *zanzibar.Model, relationships []zanzibar.Relationship) []zanzibar.Subject {
	allowed := map[string]bool{}
	usersets := map[string][]string{}
	for _, typ := range model.Types {
		for _, r := range typ.Relations {
			for _, a := range r.Allowed {
				if a.Relation != "" {
					if !slices.Contains(usersets[a.Type], a.Relation) {
						usersets[a.Type] = append(usersets[a.Type], a.Relation)
					}
					continue
				}
				allowed[a.Type] = true
			}
		}
		for _, p := range typ.Permissions {
			if usesSelf(p.Expr) {
				for _, every := range model.Types {
					allowed[every.Name] = true
				}
			}
		}
	}
	var out []zanzibar.Subject
	for _, o := range Objects(model, relationships) {
		if allowed[o.Type] {
			out = append(out, zanzibar.Subject{Object: o})
		}
		for _, relation := range usersets[o.Type] {
			out = append(out, zanzibar.Subject{Object: o, Relation: relation})
		}
	}
	return out
}

func usesSelf(expr zanzibar.Expr) bool {
	switch e := expr.(type) {
	case zanzibar.Self:
		return true
	case zanzibar.Union:
		return slices.ContainsFunc(e.Children, usesSelf)
	case zanzibar.Intersection:
		return slices.ContainsFunc(e.Children, usesSelf)
	case zanzibar.Exclusion:
		return usesSelf(e.Base) || slices.ContainsFunc(e.Subtracted, usesSelf)
	}
	return false
}

// Names is every name a check can ask on a type, once each: a relation and a
// permission may share one, and it is one question.
func Names(typ *zanzibar.Type) []string {
	var out []string
	for _, r := range typ.Relations {
		out = append(out, r.Name)
	}
	for _, p := range typ.Permissions {
		if !slices.Contains(out, p.Name) {
			out = append(out, p.Name)
		}
	}
	return out
}
