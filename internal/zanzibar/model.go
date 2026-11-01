// Package zanzibar is the engine for Zanzibar models: the schemas of SpiceDB
// and of OpenFGA, which both compile their language into the userset rewrite
// tree of the Zanzibar paper, and the relationships stored against them.
//
// A front end lowers the compiled form of one product into a Model, and the
// engine works on the Model alone. Nothing in this package knows which product
// a model came from: where the products differ, the front end says so in what
// it builds, and the engine reads it from there.
package zanzibar

import (
	"fmt"
	"slices"
	"time"
)

// Model is a schema: its types, the relations and permissions on each, and the
// caveats the relations may carry.
type Model struct {
	Types   []*Type
	Caveats []*Caveat

	// Walk is how the product follows relationships to answer a check.
	Walk Walk

	// Terms are the words the product has for what a report names.
	Terms Terms

	types   map[string]*Type
	caveats map[string]*Caveat
}

// Terms are the words a product has for a caveat and a relationship, so that a report
// reads in the words of the model it is about. The zero value is the engine's own.
type Terms struct {
	Caveat, Relationship string
}

func (t Terms) caveat() string {
	if t.Caveat == "" {
		return "caveat"
	}
	return t.Caveat
}

func (t Terms) relationship() string {
	if t.Relationship == "" {
		return "relationship"
	}
	return t.Relationship
}

// Walk is how a product follows relationships to answer a check, where products
// differ on what a loop of relationships does to the answer. A loop the product meets
// on the side an exclusion subtracts grants nothing, and one it never meets is no
// reason to refuse. The zero value follows every relationship and meets every loop.
type Walk struct {
	// StopsAtFailedCaveat is true when the product does not follow a relationship
	// whose caveat does not hold, so a loop behind it is never met.
	StopsAtFailedCaveat bool

	// Fixpoint is what the product walks to a fixpoint, with a set of what it has
	// seen, so a loop there is never met.
	Fixpoint map[FixpointWalk]bool
}

// FixpointWalk is a relation or permission of a type, asked by objects of a type. A
// userset asking meets every loop.
type FixpointWalk struct {
	Type, Name, SubjectType string
}

// meetsLoopAt says whether the product meets a loop that comes back to name on an
// object of typ, with subject asking.
func (w Walk) meetsLoopAt(typ, name string, subject Subject) bool {
	return subject.Relation != "" || !w.Fixpoint[FixpointWalk{Type: typ, Name: name, SubjectType: subject.Type}]
}

// NewModel builds a model and indexes it by name. A name declared twice is an
// error, because every lookup after this one would silently pick one of them.
func NewModel(types []*Type, caveats []*Caveat) (*Model, error) {
	m := &Model{
		Types:   types,
		Caveats: caveats,
		types:   make(map[string]*Type, len(types)),
		caveats: make(map[string]*Caveat, len(caveats)),
	}
	for _, t := range types {
		if _, ok := m.types[t.Name]; ok {
			return nil, fmt.Errorf("zanzibar: type %s declared twice", t.Name)
		}
		m.types[t.Name] = t
		if err := t.index(); err != nil {
			return nil, err
		}
	}
	for _, c := range caveats {
		if _, ok := m.caveats[c.Name]; ok {
			return nil, fmt.Errorf("zanzibar: caveat %s declared twice", c.Name)
		}
		m.caveats[c.Name] = c
	}
	return m, nil
}

// Type returns the type of that name, or nil.
func (m *Model) Type(name string) *Type { return m.types[name] }

// Caveat returns the caveat of that name, or nil.
func (m *Model) Caveat(name string) *Caveat { return m.caveats[name] }

// Type is a definition: a kind of object, such as document or user.
type Type struct {
	Name        string
	Relations   []*Relation
	Permissions []*Permission
	Position

	relations   map[string]*Relation
	permissions map[string]*Permission
}

// index builds the lookups by name. A relation and a permission may share a name
// only when the permission reads that relation with Stored: the relation is what
// is written under the name, and the permission what the name answers.
func (t *Type) index() error {
	t.relations = make(map[string]*Relation, len(t.Relations))
	t.permissions = make(map[string]*Permission, len(t.Permissions))
	for _, r := range t.Relations {
		if t.relations[r.Name] != nil {
			return fmt.Errorf("zanzibar: %s#%s declared twice", t.Name, r.Name)
		}
		t.relations[r.Name] = r
	}
	for _, p := range t.Permissions {
		stored := storedNames(p.Expr)
		for _, name := range stored {
			if t.relations[name] == nil {
				return fmt.Errorf("zanzibar: %s#%s reads %s#%s as stored, and no relation of that name is declared", t.Name, p.Name, t.Name, name)
			}
		}
		if t.permissions[p.Name] != nil || (t.relations[p.Name] != nil && !slices.Contains(stored, p.Name)) {
			return fmt.Errorf("zanzibar: %s#%s declared twice", t.Name, p.Name)
		}
		t.permissions[p.Name] = p
	}
	return nil
}

// storedNames is every relation an expression reads with Stored.
func storedNames(expr Expr) []string {
	var out []string
	switch e := expr.(type) {
	case Stored:
		out = append(out, e.Name)
	case Union:
		for _, child := range e.Children {
			out = append(out, storedNames(child)...)
		}
	case Intersection:
		for _, child := range e.Children {
			out = append(out, storedNames(child)...)
		}
	case Exclusion:
		out = append(out, storedNames(e.Base)...)
		for _, child := range e.Subtracted {
			out = append(out, storedNames(child)...)
		}
	}
	return out
}

// Declares says whether the type has a relation or a permission of that name.
func (t *Type) Declares(name string) bool {
	return t.relations[name] != nil || t.permissions[name] != nil
}

// Relation returns the relation of that name, or nil: what a write changes. A
// permission of that name is not a relation.
func (t *Type) Relation(name string) *Relation { return t.relations[name] }

// Permission returns the permission of that name, or nil: what a check of that
// name answers from, when there is one.
func (t *Type) Permission(name string) *Permission { return t.permissions[name] }

// Relation is what relationships are stored against, such as the viewer of a
// document. It is the only thing a write can change.
type Relation struct {
	Name string

	// Allowed is every kind of subject the relation may hold. A relationship
	// whose subject matches none of them cannot be written.
	Allowed []Allowed
	Position
}

// Allowed is one kind of subject a relation may hold.
type Allowed struct {
	// Type is the type of the subject object.
	Type string

	// Relation is empty when the subject is the object itself, as user:alice,
	// and names a relation of it when the subject is a userset, the members of
	// group:eng#member.
	Relation string

	// Wildcard is a subject that stands for every object of Type, present or
	// future: user:*.
	Wildcard bool

	// Caveat names the caveat a relationship of this kind carries, empty when
	// it carries none.
	Caveat string

	// Expiration is true when a relationship of this kind carries an
	// expiration time.
	Expiration bool
}

// Permission is computed from relations and other permissions, and never
// stored.
type Permission struct {
	Name string
	Expr Expr
	Position
}

// Expr is the expression of a permission: a Union, an Intersection, an
// Exclusion, a Computed, an Arrow, Stored, Self or Nil.
type Expr interface{ isExpr() }

// Union holds when any child holds.
type Union struct{ Children []Expr }

// Intersection holds when every child holds.
type Intersection struct{ Children []Expr }

// Exclusion holds when Base holds and none of Subtracted does.
type Exclusion struct {
	Base       Expr
	Subtracted []Expr
}

// Computed is a relation or permission of the same object.
type Computed struct {
	Name string
	Position
}

// Arrow walks the relation Through and asks Target on each object it reaches.
// With All false it holds when Target holds on any of them; with All true, on
// every one, and not at all when Through reaches nothing. The subject relation
// of the relationships it walks is ignored: the arrow goes to their object.
type Arrow struct {
	Through string
	Target  string
	All     bool
	Position
}

// Stored is what is written under a relation of the same object, the _this of
// the Zanzibar paper. A product that keeps one name for what is written and what
// is asked, as OpenFGA does with define viewer: [user] or editor, lowers it to a
// relation and a permission of that name, and the permission reads the relation
// with Stored: a Computed of that name would ask the permission again. A product
// that keeps the two apart has no use for it.
type Stored struct {
	Name string
}

// Self holds for the object itself, asked as a subject.
type Self struct{}

// Nil holds for nobody.
type Nil struct{}

func (Union) isExpr()        {}
func (Intersection) isExpr() {}
func (Exclusion) isExpr()    {}
func (Computed) isExpr()     {}
func (Arrow) isExpr()        {}
func (Stored) isExpr()       {}
func (Self) isExpr()         {}
func (Nil) isExpr()          {}

// Caveat is a condition a relationship can carry: a CEL expression over typed
// parameters. The engine never reads the expression; a CaveatEvaluator from
// the front end that lowered the model does.
type Caveat struct {
	Name       string
	Parameters []Parameter
	Position
}

// Parameter is one input of a caveat.
type Parameter struct {
	Name string
	Type string
}

// Position is where something was declared. Line and Column count from 1, and
// both are zero when the source did not say.
type Position struct {
	File   string
	Line   int
	Column int
}

// String writes the position as file:line:column, or the file alone when the
// source gave no line.
func (p Position) String() string {
	if p.Line == 0 {
		return p.File
	}
	return fmt.Sprintf("%s:%d:%d", p.File, p.Line, p.Column)
}

// Object is one object of a type, such as document:readme.
type Object struct {
	Type string
	ID   string
}

// String writes the object as SpiceDB does, document:readme.
func (o Object) String() string { return o.Type + ":" + o.ID }

// WildcardID is the identifier of a subject that stands for every object of
// its type.
const WildcardID = "*"

// Subject is what a relationship grants to: an object, a userset when Relation
// is set, or every object of a type when the ID is WildcardID.
type Subject struct {
	Object
	Relation string
}

// String writes the subject as SpiceDB does, user:alice or group:eng#member.
func (s Subject) String() string {
	if s.Relation == "" {
		return s.Object.String()
	}
	return s.Object.String() + "#" + s.Relation
}

// Relationship is one stored fact: Resource has Subject in Relation.
type Relationship struct {
	Resource Object
	Relation string
	Subject  Subject

	// Caveat is the caveat the relationship carries and the context written
	// with it, nil when it carries none.
	Caveat *CaveatUse

	// Expires is when the relationship stops counting, nil when it does not.
	Expires *time.Time
	Position
}

// String writes the relationship without its caveat and expiration, as
// document:readme#viewer@user:alice.
func (r Relationship) String() string {
	return r.Resource.String() + "#" + r.Relation + "@" + r.Subject.String()
}

// CaveatUse is a caveat as one relationship carries it.
type CaveatUse struct {
	Name    string
	Context map[string]any
}
