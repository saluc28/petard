package zanzibar

// This file works out, from a model alone, which permissions a write to a given
// relation could raise. SafeGates uses it to skip, in each gate check, the
// permissions that cannot change from the write under test: a permission that
// reads nothing the coalition can write can never rise, so checking it finds
// nothing (section 6 of the definitions). The proposals are identical to
// checking every permission, only the dead checks are left out.
//
// The reach is a sound over-approximation. It follows every branch of a
// permission, every arrow into the types it reaches, and every userset a
// relation admits, without asking whether a particular path is ever satisfiable.
// So it may keep a permission whose path is not realizable, which costs a check
// that finds nothing; it never drops one that is, which would lose a finding.

// relRef is a relation of a type, the thing a write changes.
type relRef struct {
	typ  string
	name string
}

// permRef is a permission of a type, the thing a raise is measured on.
type permRef struct {
	typ  string
	name string
}

// raisableIndex maps each relation to the permissions whose value can change
// when that relation's tuples change. It is built once from the model, as the
// inverse of "the relations a permission reads".
func raisableIndex(model *Model) map[relRef][]permRef {
	reverse := map[relRef]map[permRef]bool{}
	for _, t := range model.Types {
		for _, p := range t.Permissions {
			reads := map[relRef]bool{}
			collectReads(model, t.Name, p.Expr, reads, map[string]bool{})
			pr := permRef{typ: t.Name, name: p.Name}
			for rr := range reads {
				perms := reverse[rr]
				if perms == nil {
					perms = map[permRef]bool{}
					reverse[rr] = perms
				}
				perms[pr] = true
			}
		}
	}
	out := make(map[relRef][]permRef, len(reverse))
	for rr, perms := range reverse {
		list := make([]permRef, 0, len(perms))
		for pr := range perms {
			list = append(list, pr)
		}
		out[rr] = list
	}
	return out
}

// collectReads adds to reads every relation the expression of a permission on
// typ can read. seen holds the permissions open on the current walk, so a
// permission reached through itself does not recurse without end.
func collectReads(model *Model, typ string, expr Expr, reads map[relRef]bool, seen map[string]bool) {
	switch e := expr.(type) {
	case Union:
		for _, c := range e.Children {
			collectReads(model, typ, c, reads, seen)
		}
	case Intersection:
		for _, c := range e.Children {
			collectReads(model, typ, c, reads, seen)
		}
	case Exclusion:
		// Deleting a subtracted relation lifts the exclusion, so it is read too.
		collectReads(model, typ, e.Base, reads, seen)
		for _, s := range e.Subtracted {
			collectReads(model, typ, s, reads, seen)
		}
	case Computed:
		collectName(model, typ, e.Name, reads, seen)
	case Arrow:
		// The walked relation, and the target asked on every type the walk reaches.
		collectName(model, typ, e.Through, reads, seen)
		if t := model.Type(typ); t != nil {
			if r := t.Relation(e.Through); r != nil {
				for _, a := range r.Allowed {
					if a.Wildcard {
						continue
					}
					collectName(model, a.Type, e.Target, reads, seen)
				}
			}
		}
	case Self, Nil:
	}
}

// collectName resolves a name on a type as either a relation, which it records
// and whose usersets it follows, or a permission, which it walks.
func collectName(model *Model, typ, name string, reads map[relRef]bool, seen map[string]bool) {
	t := model.Type(typ)
	if t == nil {
		return
	}
	if t.Relation(name) != nil {
		collectRelation(model, typ, name, reads, seen)
		return
	}
	if p := t.Permission(name); p != nil {
		key := typ + "#" + name
		if seen[key] {
			return
		}
		seen[key] = true
		collectReads(model, typ, p.Expr, reads, seen)
	}
}

// collectRelation records a relation as read and follows the usersets it admits:
// holding it through a userset A#x depends on x of A as well.
func collectRelation(model *Model, typ, name string, reads map[relRef]bool, seen map[string]bool) {
	rr := relRef{typ: typ, name: name}
	if reads[rr] {
		return
	}
	reads[rr] = true
	t := model.Type(typ)
	if t == nil {
		return
	}
	r := t.Relation(name)
	if r == nil {
		return
	}
	for _, a := range r.Allowed {
		if a.Wildcard || a.Relation == "" {
			continue
		}
		collectName(model, a.Type, a.Relation, reads, seen)
	}
}

// writableRelations is every relation the coalition can change under a write
// model: the relations the rules write or delete, and the relations the
// creations write. The second value is false when a creation writes a tuple
// whose object type is not fixed by the model, the creator among them: the reach
// cannot be scoped soundly then, so the caller checks every permission instead.
func writableRelations(model *Model, wm *WriteModel) ([]relRef, bool) {
	var refs []relRef
	resolved := true
	for _, w := range wm.Writes {
		refs = append(refs, relRef{typ: w.Resource, name: w.Relation})
	}
	for _, c := range wm.Creates {
		for _, cw := range c.Writes {
			switch {
			case cw.Resource == CreatedPlaceholder:
				refs = append(refs, relRef{typ: c.Creates, name: cw.Relation})
			case model.Type(cw.Resource) != nil:
				// An On object, written on its own declared type.
				refs = append(refs, relRef{typ: cw.Resource, name: cw.Relation})
			default:
				// The creator, or a placeholder with no fixed type.
				resolved = false
			}
		}
	}
	return refs, resolved
}

// raisableScope is the set of permissions a coalition could raise by writing any
// of the given relations, read off the index. It is the permissions SafeGates
// need check for a raise; the rest cannot change from those writes.
func raisableScope(raisers map[relRef][]permRef, writable []relRef) map[permRef]bool {
	scope := map[permRef]bool{}
	for _, rr := range writable {
		for _, pr := range raisers[rr] {
			scope[pr] = true
		}
	}
	return scope
}

// reach is the raisable-permission index together with whether a run may use
// it. A write model whose creation writes a tuple of no fixed type cannot be
// scoped soundly; then resolved is false and every permission is checked, the
// same as before the index existed.
type reach struct {
	index    map[relRef][]permRef
	resolved bool
}

// newReach builds the reach for a model and the base write model a run starts
// from. Whether a run can be scoped is decided by that base model's creations,
// and a run only ever adds write rules to it, which have a fixed type, so the
// decision holds for every derived model too.
func newReach(model *Model, wm *WriteModel) reach {
	_, resolved := writableRelations(model, wm)
	return reach{index: raisableIndex(model), resolved: resolved}
}

// scopeOf is the permissions a run under wm need check for a raise: those a
// write wm allows could reach. It is nil when the model cannot be scoped
// soundly, which leaves every permission to be checked.
func (rc reach) scopeOf(model *Model, wm *WriteModel) map[permRef]bool {
	if !rc.resolved {
		return nil
	}
	writable, _ := writableRelations(model, wm)
	return raisableScope(rc.index, writable)
}
