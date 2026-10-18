package zanzibar

import (
	"fmt"
	"maps"
	"slices"
)

// TargetID is the identifier of the object a starting position is about: an
// object the coalition did not create, which it starts out holding a permission
// on.
const TargetID = "target"

// StartingPosition is one way an attacker can start: a pre-existing object, a
// relation or permission the attacker holds on it, and the smallest set of
// tuples that grants it and nothing more. It makes the analysis independent of
// whatever sample tuples a repository has, so that "an attacker who is a viewer
// of a document" is studied whether or not a file writes one.
type StartingPosition struct {
	// Type is the type of the object, Target the relation or permission the
	// attacker holds, and Object the object itself.
	Type   string
	Target string
	Object Object

	// Tuples are the minimal set that grants Target to the attacker on Object.
	// It is the state the closure runs from.
	Tuples []Relationship

	// Attacker is the subject the tuples grant Target to.
	Attacker Object

	// Depth is the unfold bound the generation used, and Truncated is true when
	// a recursive permission reached it, so some starting positions for this
	// target may be missing.
	Depth     int
	Truncated bool
}

// String names the position as the object, the target and the attacker, for the
// report: document:target#view for user:attacker.
func (p StartingPosition) String() string {
	return fmt.Sprintf("%s#%s for %s", p.Object, p.Target, p.Attacker)
}

// StartingPositions generates, for every relation and permission of every type,
// the minimal starting states in which the attacker holds it on a pre-existing
// object. A target reachable in more than one minimal way gives one position per
// way. A recursive permission is unfolded to opts.StartingDepth, and a position
// whose target needed more says so.
//
// The attacker is the subject the positions grant to, a user the analysis
// treats as the coalition's own. A target the attacker cannot hold, one granted
// only to a type it is not, yields no position.
func StartingPositions(model *Model, attacker Object, opts Options) []StartingPosition {
	depth := opts.startingDepth()
	var out []StartingPosition
	for _, t := range model.Types {
		object := Object{Type: t.Name, ID: TargetID}
		for _, name := range targetNames(t) {
			g := &positionGen{model: model, attacker: attacker}
			sets, truncated := g.sets(t.Name, name, object, depth, map[string]bool{})
			for _, tuples := range dedupSets(sets) {
				out = append(out, StartingPosition{
					Type:      t.Name,
					Target:    name,
					Object:    object,
					Tuples:    tuples,
					Attacker:  attacker,
					Depth:     depth,
					Truncated: truncated,
				})
			}
		}
	}
	return out
}

// targetNames is every relation and permission of a type, the targets a starting
// position can be about, in a stable order.
func targetNames(t *Type) []string {
	names := make([]string, 0, len(t.Relations)+len(t.Permissions))
	for _, r := range t.Relations {
		names = append(names, r.Name)
	}
	for _, p := range t.Permissions {
		names = append(names, p.Name)
	}
	return names
}

// positionGen generates the minimal tuple sets for one target. It mints fresh
// auxiliary objects for the usersets and arrows a grant passes through, counted
// from zero so that the sets of one target read the same every run.
type positionGen struct {
	model    *Model
	attacker Object
	counter  int
}

func (g *positionGen) fresh(typ string) Object {
	o := Object{Type: typ, ID: fmt.Sprintf("aux-%d", g.counter)}
	g.counter++
	return o
}

// sets returns the minimal tuple sets that make the attacker hold name on obj,
// and whether the depth bound cut a deeper unfold. seen holds the permissions
// open on the current path, so a permission defined through itself does not
// recurse without end.
func (g *positionGen) sets(typ, name string, obj Object, depth int, seen map[string]bool) ([][]Relationship, bool) {
	t := g.model.Type(typ)
	if t == nil {
		return nil, false
	}
	if r := t.Relation(name); r != nil {
		return g.relationSets(r, obj, depth, seen)
	}
	p := t.Permission(name)
	if p == nil {
		return nil, false
	}
	// The cycle guard is per object: a permission defined through itself on the
	// same object must not recurse, but an arrow reaches a fresh object, a
	// different instance the depth bound governs instead.
	key := obj.String() + "#" + name
	if seen[key] {
		return nil, true
	}
	next := maps.Clone(seen)
	next[key] = true
	return g.exprSets(typ, p.Expr, obj, depth, next)
}

// relationSets is the minimal ways to hold a relation: the attacker written
// directly, a wildcard of the attacker's type, or the attacker reached through
// a userset the relation allows.
func (g *positionGen) relationSets(r *Relation, obj Object, depth int, seen map[string]bool) ([][]Relationship, bool) {
	var sets [][]Relationship
	truncated := false
	for _, a := range r.Allowed {
		switch {
		case a.Wildcard:
			if a.Type == g.attacker.Type {
				sets = append(sets, []Relationship{tuple(obj, r.Name, Subject{Object: Object{Type: a.Type, ID: WildcardID}})})
			}
		case a.Relation == "":
			if a.Type == g.attacker.Type {
				sets = append(sets, []Relationship{tuple(obj, r.Name, Subject{Object: g.attacker})})
			}
		default:
			if depth == 0 {
				truncated = true
				continue
			}
			aux := g.fresh(a.Type)
			inner, cut := g.sets(a.Type, a.Relation, aux, depth-1, seen)
			truncated = truncated || cut
			link := tuple(obj, r.Name, Subject{Object: aux, Relation: a.Relation})
			for _, set := range inner {
				sets = append(sets, append([]Relationship{link}, set...))
			}
		}
	}
	return sets, truncated
}

// exprSets is the minimal ways an expression holds for the attacker on obj.
func (g *positionGen) exprSets(typ string, expr Expr, obj Object, depth int, seen map[string]bool) ([][]Relationship, bool) {
	switch e := expr.(type) {
	case Union:
		var sets [][]Relationship
		truncated := false
		for _, child := range e.Children {
			childSets, cut := g.exprSets(typ, child, obj, depth, seen)
			sets = append(sets, childSets...)
			truncated = truncated || cut
		}
		return sets, truncated

	case Intersection:
		sets := [][]Relationship{{}}
		truncated := false
		for _, child := range e.Children {
			childSets, cut := g.exprSets(typ, child, obj, depth, seen)
			truncated = truncated || cut
			if len(childSets) == 0 {
				// A branch with no way to hold leaves the intersection with none.
				return nil, truncated
			}
			sets = combine(sets, childSets)
		}
		return sets, truncated

	case Exclusion:
		// The attacker holds an exclusion by holding its base and not being in
		// what it subtracts. The minimal set is the base alone: the subtracted
		// tuples are the ones "nothing else" leaves out.
		return g.exprSets(typ, e.Base, obj, depth, seen)

	case Computed:
		return g.sets(typ, e.Name, obj, depth, seen)

	case Arrow:
		return g.arrowSets(typ, e, obj, depth, seen)

	case Self, Nil:
		// Self holds only for the object itself, which the attacker is not on a
		// pre-existing object; nil holds for nobody.
		return nil, false
	}
	return nil, false
}

// arrowSets is the minimal ways an arrow holds: the object linked through the
// walked relation to one object on which the attacker holds the target. For an
// all arrow one such object is still the minimal set, since nothing else is
// present to fail the all.
func (g *positionGen) arrowSets(typ string, a Arrow, obj Object, depth int, seen map[string]bool) ([][]Relationship, bool) {
	if depth == 0 {
		return nil, true
	}
	t := g.model.Type(typ)
	if t == nil {
		return nil, false
	}
	r := t.Relation(a.Through)
	if r == nil {
		return nil, false
	}
	var sets [][]Relationship
	truncated := false
	for _, allowed := range r.Allowed {
		if allowed.Wildcard {
			continue
		}
		aux := g.fresh(allowed.Type)
		inner, cut := g.sets(allowed.Type, a.Target, aux, depth-1, seen)
		truncated = truncated || cut
		link := tuple(obj, a.Through, Subject{Object: aux})
		for _, set := range inner {
			sets = append(sets, append([]Relationship{link}, set...))
		}
	}
	return sets, truncated
}

// tuple builds a relationship with no caveat or expiration, the only kind a
// starting position writes.
func tuple(resource Object, relation string, subject Subject) Relationship {
	return Relationship{Resource: resource, Relation: relation, Subject: subject}
}

// combine is the cartesian product of two lists of tuple sets, each pair joined
// into one set with its tuples deduplicated: the ways to hold an intersection of
// two expressions.
func combine(left, right [][]Relationship) [][]Relationship {
	var out [][]Relationship
	for _, l := range left {
		for _, r := range right {
			merged := slices.Clone(l)
			for _, t := range r {
				if !slices.ContainsFunc(merged, func(x Relationship) bool { return tupleKey(x) == tupleKey(t) }) {
					merged = append(merged, t)
				}
			}
			out = append(out, merged)
		}
	}
	return out
}

// dedupSets drops tuple sets that hold the same tuples as an earlier one, since
// two expansions can land on the same minimal set.
func dedupSets(sets [][]Relationship) [][]Relationship {
	seen := map[string]bool{}
	var out [][]Relationship
	for _, set := range sets {
		keys := make([]string, 0, len(set))
		for _, t := range set {
			keys = append(keys, tupleKey(t))
		}
		slices.Sort(keys)
		sig := fmt.Sprint(keys)
		if seen[sig] {
			continue
		}
		seen[sig] = true
		out = append(out, set)
	}
	return out
}
