package zanzibar

import "fmt"

// polarity is how a relation enters a permission: an occurrence is positive when
// adding a tuple of the relation can only raise the permission, negative when
// adding one can only lower it. Exclusion flips it; an all arrow makes the
// walked relation neither, which the analysis records as mixedAll.
type polarity int

const (
	positive polarity = iota
	negative
)

func (p polarity) flip() polarity {
	if p == positive {
		return negative
	}
	return positive
}

// relKey names a relation of a type.
type relKey struct {
	Type     string
	Relation string
}

// occurrence is where a relation stands across the schema: whether it is ever
// positive, ever negative, and whether it is ever the walked relation of an all
// arrow, which is mixed on its own (adding a first tuple can make the arrow
// true, adding another can make it false).
type occurrence struct {
	pos      bool
	neg      bool
	mixedAll bool
}

// mixed reports whether a relation can both raise and lower a permission, so
// that the coalition adding or deleting it is not a one-way move. A relation
// that occurs in both polarities is mixed, and so is one walked by an all arrow.
func (o occurrence) mixed() bool { return o.mixedAll || (o.pos && o.neg) }

// MixedRelation names a relation E1 rules out: one the coalition can write that
// is mixed, so the closure cannot be the single greatest element. Reason says
// which form of mixing it is, for the report.
type MixedRelation struct {
	Type     string
	Relation string
	Reason   string
}

// String writes the relation and why it is mixed, type#relation (reason).
func (m MixedRelation) String() string {
	return fmt.Sprintf("%s#%s (%s)", m.Type, m.Relation, m.Reason)
}

// polarities records, for every relation of the schema, the polarities it
// occurs in. It is read by E1 and by the closure, which adds a relation only
// where it occurs positively and deletes one only where it occurs negatively.
type polarities struct {
	model   *Model
	rel     map[relKey]*occurrence
	visited map[visitKey]bool
}

// visitKey stops the walk from looping on a recursive permission or an arrow
// that comes back to a type it already passed at the same polarity.
type visitKey struct {
	Type string
	Name string
	pol  polarity
}

// analyzePolarities walks every permission of the schema, and every gate of the
// write model, recording the polarity of each relation occurrence. Gates count:
// a gate is a permission that has to hold, so a relation in it occurs the way it
// occurs in any permission the coalition wants to satisfy, positively.
func analyzePolarities(model *Model, wm *WriteModel) *polarities {
	p := &polarities{
		model:   model,
		rel:     map[relKey]*occurrence{},
		visited: map[visitKey]bool{},
	}
	for _, t := range model.Types {
		for _, perm := range t.Permissions {
			p.walk(t.Name, perm.Expr, positive)
		}
	}
	if wm != nil {
		for _, w := range wm.Writes {
			if w.Gate.Holds != "" {
				p.resolve(w.Resource, w.Gate.Holds, positive)
			}
		}
		for _, c := range wm.Creates {
			for _, on := range c.On {
				if on.Gate.Holds != "" {
					p.resolve(on.Type, on.Gate.Holds, positive)
				}
			}
		}
	}
	return p
}

func (p *polarities) at(k relKey) occurrence {
	if o, ok := p.rel[k]; ok {
		return *o
	}
	return occurrence{}
}

func (p *polarities) mark(k relKey, pol polarity, mixedAll bool) {
	o := p.rel[k]
	if o == nil {
		o = &occurrence{}
		p.rel[k] = o
	}
	switch pol {
	case positive:
		o.pos = true
	case negative:
		o.neg = true
	}
	if mixedAll {
		o.mixedAll = true
	}
}

// walk records the relations an expression reaches at a polarity.
func (p *polarities) walk(typ string, expr Expr, pol polarity) {
	switch e := expr.(type) {
	case Union:
		for _, child := range e.Children {
			p.walk(typ, child, pol)
		}
	case Intersection:
		for _, child := range e.Children {
			p.walk(typ, child, pol)
		}
	case Exclusion:
		p.walk(typ, e.Base, pol)
		for _, sub := range e.Subtracted {
			p.walk(typ, sub, pol.flip())
		}
	case Computed:
		p.resolve(typ, e.Name, pol)
	case Arrow:
		p.arrow(typ, e, pol)
	case Self, Nil:
	}
}

// resolve records a relation, or walks into a permission of the same object. A
// permission already walked at this polarity is not walked again, which bounds
// recursion on a permission defined through itself.
func (p *polarities) resolve(typ, name string, pol polarity) {
	t := p.model.Type(typ)
	if t == nil {
		return
	}
	if t.Relation(name) != nil {
		p.mark(relKey{Type: typ, Relation: name}, pol, false)
		return
	}
	perm := t.Permission(name)
	if perm == nil {
		return
	}
	key := visitKey{Type: typ, Name: name, pol: pol}
	if p.visited[key] {
		return
	}
	p.visited[key] = true
	p.walk(typ, perm.Expr, pol)
}

// arrow records the walked relation and walks the target on every type the
// relation can reach. The walked relation keeps the enclosing polarity under
// any, and is mixed under all; the target keeps the polarity either way.
func (p *polarities) arrow(typ string, a Arrow, pol polarity) {
	p.mark(relKey{Type: typ, Relation: a.Through}, pol, a.All)

	t := p.model.Type(typ)
	if t == nil {
		return
	}
	r := t.Relation(a.Through)
	if r == nil {
		return
	}
	for _, allowed := range r.Allowed {
		if allowed.Wildcard {
			continue
		}
		p.resolve(allowed.Type, a.Target, pol)
	}
}

// CheckE1 reports whether exactness condition E1 holds for a schema under a
// write model: no relation the coalition can add or delete is mixed. When it
// fails, the returned relations are the ones that break it, named in the result
// so the bound is never silent. Under E1 every move the closure makes only
// raises a permission, the reachable states have one greatest element, and the
// closure computes it (section 5.2 of the definitions).
func CheckE1(model *Model, wm *WriteModel) (bool, []MixedRelation) {
	p := analyzePolarities(model, wm)
	var mixed []MixedRelation
	seen := map[relKey]bool{}
	for _, w := range wm.Writes {
		if !writes(w.Operations) && !deletes(w.Operations) {
			continue
		}
		k := relKey{Type: w.Resource, Relation: w.Relation}
		if seen[k] {
			continue
		}
		occ := p.at(k)
		if !occ.mixed() {
			continue
		}
		seen[k] = true
		mixed = append(mixed, MixedRelation{Type: w.Resource, Relation: w.Relation, Reason: occ.reason()})
	}
	return len(mixed) == 0, mixed
}

// reason says in a few words why a relation is mixed.
func (o occurrence) reason() string {
	if o.mixedAll {
		return "walked by an all arrow"
	}
	return "occurs in both polarities"
}

// positivePermissions is every permission of a type whose expansion reads a
// relation positively, so that adding to the relation, or lifting a caveat on
// it, raises the permission. It is how a write on a relation is tied to the
// access it opens.
func positivePermissions(model *Model, typ, relation string) []string {
	t := model.Type(typ)
	if t == nil {
		return nil
	}
	var out []string
	for _, p := range t.Permissions {
		pol := &polarities{model: model, rel: map[relKey]*occurrence{}, visited: map[visitKey]bool{}}
		pol.walk(typ, p.Expr, positive)
		if pol.at(relKey{Type: typ, Relation: relation}).pos {
			out = append(out, p.Name)
		}
	}
	return out
}

// deletes reports whether a set of operations removes a tuple.
func deletes(ops []Operation) bool {
	for _, op := range ops {
		if op == Delete {
			return true
		}
	}
	return false
}
