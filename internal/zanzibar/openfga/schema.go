// Package openfga is the OpenFGA front end of the Zanzibar engine. It compiles a
// model with OpenFGA's own language package, holds it to OpenFGA's own validation,
// lowers the compiled form into a zanzibar.Model, and evaluates conditions in
// OpenFGA's own CEL environment.
//
// It is the one package of petard that imports OpenFGA, so that what the engine
// knows about a model is what this package chose to tell it. Every OpenFGA line
// cited in this package was read at fb8e7df8 (v1.22.0+2).
package openfga

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"github.com/openfga/language/pkg/go/transformer"
	"github.com/openfga/openfga/pkg/typesystem"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/saluc28/petard/internal/zanzibar"
)

// ErrModel is returned for a model that does not compile, or that compiles into
// something OpenFGA's type system refuses.
var ErrModel = errors.New("openfga: invalid model")

// inlineExpression is the reserved condition whose CEL expression a tuple carries
// in its own context, rather than the model declaring it
// (internal/condition/inline.go:19). A relation that admits it hands the writer
// the whole condition, not only its parameters.
const inlineExpression = "$expression"

// inlineExpressionParameter is the key of a tuple's context that holds the
// expression of an inline condition (internal/condition/inline.go:24). It is the
// parameter a model has to say who fills, since it is the condition itself.
const inlineExpressionParameter = "expression"

// Schema is a compiled model: the model lowered from it, and its conditions as
// OpenFGA compiled them. It is the CaveatEvaluator to check its model with.
type Schema struct {
	Model *zanzibar.Model

	types *typesystem.TypeSystem
}

// Compile compiles a model written in the DSL. file is the name positions are
// reported against.
func Compile(file, text string) (*Schema, error) {
	model, err := transformer.TransformDSLToProto(text)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrModel, file, err)
	}
	return lower(file, model, dslPositions(file, text))
}

// CompileJSON compiles a model in the JSON form the OpenFGA API takes. That form
// holds no positions, so everything in it is reported against the file alone.
func CompileJSON(file, text string) (*Schema, error) {
	model, err := transformer.LoadJSONStringToProto(text)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrModel, file, err)
	}
	return lower(file, model, nil)
}

// lower validates a compiled model and lowers it into the engine's model.
//
// The two products draw one line differently. SpiceDB declares a relation, what
// is written, apart from a permission, what is asked. OpenFGA keeps both under one
// name: define viewer: [user] or editor stores tuples under viewer, and a check of
// viewer also reads editor. So a relation holding the _this of the rewrite becomes
// a relation and a permission of that name, the permission reading the relation
// with zanzibar.Stored. Writes, tuples, gates and reports keep the name the model
// wrote, and nothing is translated on the way in or out.
//
// A relation that is nothing but _this answers a check too, so it gets a
// permission reading itself, which is what a raise is measured on. Two kinds are
// left as relations alone, which is what a schema that separates the two would
// declare: one an arrow walks, whose tuples link objects and which OpenFGA holds to
// be direct (pkg/typesystem/typesystem.go:1347-1352), and one read only to subtract
// it, a ban, where holding it opens nothing and adding a permission would read every
// exclusion as a relation that both raises and lowers.
func lower(file string, model *openfgav1.AuthorizationModel, at map[string]zanzibar.Position) (*Schema, error) {
	types, err := typesystem.NewAndValidate(context.Background(), model)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrModel, file, err)
	}

	position := func(key string) zanzibar.Position {
		if p, ok := at[key]; ok {
			return p
		}
		return zanzibar.Position{File: file}
	}

	var (
		lowered []*zanzibar.Type
		direct  []directRelation
		inline  bool
	)
	for _, def := range model.GetTypeDefinitions() {
		t := &zanzibar.Type{Name: def.GetType(), Position: position(def.GetType())}
		relations := def.GetRelations()
		for _, name := range relationNames(def.GetType(), relations, at) {
			rewrite := relations[name]
			pos := position(def.GetType() + "#" + name)
			if typesystem.RewriteContainsSelf(rewrite) {
				r := &zanzibar.Relation{Name: name, Position: pos}
				for _, ref := range def.GetMetadata().GetRelations()[name].GetDirectlyRelatedUserTypes() {
					r.Allowed = append(r.Allowed, lowerAllowed(ref))
					inline = inline || ref.GetCondition() == inlineExpression
				}
				t.Relations = append(t.Relations, r)
			}
			if _, stored := rewrite.GetUserset().(*openfgav1.Userset_This); stored {
				walked, err := types.IsTuplesetRelation(def.GetType(), name)
				if err != nil {
					return nil, fmt.Errorf("%w: %s: %s#%s: %w", ErrModel, file, def.GetType(), name, err)
				}
				if !walked {
					direct = append(direct, directRelation{t: t, name: name, pos: pos})
				}
				continue
			}
			expr, err := lowerRewrite(name, rewrite)
			if err != nil {
				return nil, fmt.Errorf("%w: %s: %s#%s: %w", ErrModel, file, def.GetType(), name, err)
			}
			t.Permissions = append(t.Permissions, &zanzibar.Permission{Name: name, Expr: expr, Position: pos})
		}
		lowered = append(lowered, t)
	}

	m, err := withAccessPermissions(lowered, lowerConditions(model, inline, position), direct)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrModel, file, err)
	}
	return &Schema{Model: m, types: types}, nil
}

// directRelation is a relation that is nothing but _this and no arrow walks,
// which is an access unless the model reads it only to subtract it.
type directRelation struct {
	t    *zanzibar.Type
	name string
	pos  zanzibar.Position
}

// withAccessPermissions gives each direct relation that is an access a permission
// reading itself, and returns the model. Whether one is an access depends on the
// others: a relation that admits group#member reads group#member at its own
// polarity, and only once it has a permission does anything read it. So the
// relations are promoted until a round promotes none. A promotion only ever adds a
// positive occurrence, so the set of relations left only subtracted only shrinks
// and the loop ends.
func withAccessPermissions(types []*zanzibar.Type, caveats []*zanzibar.Caveat, direct []directRelation) (*zanzibar.Model, error) {
	for {
		m, err := zanzibar.NewModel(types, caveats)
		if err != nil {
			return nil, err
		}
		subtracted := zanzibar.SubtractedOnly(m)
		promoted := false
		for _, d := range direct {
			if d.t.Permission(d.name) != nil || subtracted[zanzibar.RelationRef{Type: d.t.Name, Relation: d.name}] {
				continue
			}
			d.t.Permissions = append(d.t.Permissions, &zanzibar.Permission{
				Name:     d.name,
				Expr:     zanzibar.Stored{Name: d.name},
				Position: d.pos,
			})
			promoted = true
		}
		if !promoted {
			return m, nil
		}
	}
}

// relationNames is the relations of a type in the order the source declares them,
// by name where the source says nothing, since the compiled form holds them in a
// map and a report has to read the same on every run.
func relationNames(typ string, relations map[string]*openfgav1.Userset, at map[string]zanzibar.Position) []string {
	names := make([]string, 0, len(relations))
	for name := range relations {
		names = append(names, name)
	}
	slices.SortFunc(names, func(a, b string) int {
		if c := at[typ+"#"+a].Line - at[typ+"#"+b].Line; c != 0 {
			return c
		}
		return strings.Compare(a, b)
	})
	return names
}

func lowerAllowed(ref *openfgav1.RelationReference) zanzibar.Allowed {
	return zanzibar.Allowed{
		Type:     ref.GetType(),
		Relation: ref.GetRelation(),
		Wildcard: ref.GetWildcard() != nil,
		Caveat:   ref.GetCondition(),
	}
}

// lowerRewrite lowers the rewrite of the relation named name. Its _this is what is
// stored under that name.
func lowerRewrite(name string, rewrite *openfgav1.Userset) (zanzibar.Expr, error) {
	switch r := rewrite.GetUserset().(type) {
	case *openfgav1.Userset_This:
		return zanzibar.Stored{Name: name}, nil
	case *openfgav1.Userset_ComputedUserset:
		return zanzibar.Computed{Name: r.ComputedUserset.GetRelation()}, nil
	case *openfgav1.Userset_TupleToUserset:
		return zanzibar.Arrow{
			Through: r.TupleToUserset.GetTupleset().GetRelation(),
			Target:  r.TupleToUserset.GetComputedUserset().GetRelation(),
		}, nil
	case *openfgav1.Userset_Union:
		children, err := lowerChildren(name, r.Union.GetChild())
		return zanzibar.Union{Children: children}, err
	case *openfgav1.Userset_Intersection:
		children, err := lowerChildren(name, r.Intersection.GetChild())
		return zanzibar.Intersection{Children: children}, err
	case *openfgav1.Userset_Difference:
		base, err := lowerRewrite(name, r.Difference.GetBase())
		if err != nil {
			return nil, err
		}
		subtract, err := lowerRewrite(name, r.Difference.GetSubtract())
		if err != nil {
			return nil, err
		}
		return zanzibar.Exclusion{Base: base, Subtracted: []zanzibar.Expr{subtract}}, nil
	}
	return nil, fmt.Errorf("rewrite %T", rewrite.GetUserset())
}

func lowerChildren(name string, children []*openfgav1.Userset) ([]zanzibar.Expr, error) {
	out := make([]zanzibar.Expr, 0, len(children))
	for _, child := range children {
		expr, err := lowerRewrite(name, child)
		if err != nil {
			return nil, err
		}
		out = append(out, expr)
	}
	return out, nil
}

// lowerConditions lowers the conditions a model declares, by name, and the inline
// one when a relation admits it, which no model declares.
func lowerConditions(model *openfgav1.AuthorizationModel, inline bool, position func(string) zanzibar.Position) []*zanzibar.Caveat {
	names := make([]string, 0, len(model.GetConditions()))
	for name := range model.GetConditions() {
		names = append(names, name)
	}
	slices.Sort(names)

	out := make([]*zanzibar.Caveat, 0, len(names)+1)
	for _, name := range names {
		c := &zanzibar.Caveat{Name: name, Position: position("condition " + name)}
		parameters := model.GetConditions()[name].GetParameters()
		for parameter, ref := range parameters {
			c.Parameters = append(c.Parameters, zanzibar.Parameter{Name: parameter, Type: parameterType(ref)})
		}
		slices.SortFunc(c.Parameters, func(a, b zanzibar.Parameter) int { return strings.Compare(a.Name, b.Name) })
		out = append(out, c)
	}
	if inline {
		out = append(out, &zanzibar.Caveat{
			Name:       inlineExpression,
			Parameters: []zanzibar.Parameter{{Name: inlineExpressionParameter, Type: "string"}},
		})
	}
	return out
}

// parameterType writes a parameter type the way the DSL does: string, or
// list<string> for a generic one.
func parameterType(ref *openfgav1.ConditionParamTypeRef) string {
	name := strings.ToLower(strings.TrimPrefix(ref.GetTypeName().String(), "TYPE_NAME_"))
	if generics := ref.GetGenericTypes(); len(generics) > 0 {
		parts := make([]string, 0, len(generics))
		for _, generic := range generics {
			parts = append(parts, parameterType(generic))
		}
		return name + "<" + strings.Join(parts, ", ") + ">"
	}
	return name
}

// Evaluate evaluates a condition of the model the way a check of OpenFGA does.
//
// Keys that name no parameter of the condition are ignored
// (internal/condition/condition.go:169-173). When the condition cannot be decided,
// a parameter missing or a value of the wrong type, OpenFGA refuses to answer that
// branch, even where the parameters given already settle the expression
// (internal/condition/eval/eval.go:125-138), and the refusal only stands if no other
// branch grants (internal/graph/check.go:197-200). Conditional is what stands in for
// that refusal here: the engine's three valued logic gives the same answer. SpiceDB,
// by contrast, decides on what partial evaluation can settle.
//
// An inline condition, which OpenFGA takes only behind the inline_expressions
// experimental flag (pkg/server/write.go:58-66), is read as Conditional: its
// expression travels on the tuple and is compiled by code OpenFGA keeps internal,
// so it stays one that may hold, as section 5.4 of the definitions reads a caveat
// it cannot decide.
func (s *Schema) Evaluate(name string, values map[string]any) (zanzibar.Level, error) {
	if name == inlineExpression {
		return zanzibar.Conditional, nil
	}
	condition, ok := s.types.GetConditions()[name]
	if !ok {
		return zanzibar.No, fmt.Errorf("condition %s is not declared", name)
	}
	fields, err := structpb.NewStruct(values)
	if err != nil {
		return zanzibar.No, fmt.Errorf("context of condition %s: %w", name, err)
	}
	result, err := condition.Evaluate(context.Background(), fields.GetFields())
	switch {
	case err != nil, len(result.MissingParameters) > 0:
		return zanzibar.Conditional, nil //nolint:nilerr // a condition OpenFGA cannot decide is an answer here, not a failure of the check
	case result.ConditionMet:
		return zanzibar.Yes, nil
	}
	return zanzibar.No, nil
}
