// Package spicedb is the SpiceDB front end of the Zanzibar engine. It compiles
// a schema with SpiceDB's own compiler, lowers the compiled definitions into a
// zanzibar.Model, and evaluates caveats in SpiceDB's own CEL environment.
//
// It is the one package of petard that imports SpiceDB, so that what the
// engine knows about a model is what this package chose to tell it.
package spicedb

import (
	"errors"
	"fmt"
	"io/fs"
	"sort"

	"github.com/authzed/spicedb/pkg/caveats"
	caveattypes "github.com/authzed/spicedb/pkg/caveats/types"
	core "github.com/authzed/spicedb/pkg/proto/core/v1"
	"github.com/authzed/spicedb/pkg/schemadsl/compiler"
	"github.com/authzed/spicedb/pkg/schemadsl/input"

	"github.com/saluc28/petard/internal/zanzibar"
)

// ellipsis is how SpiceDB names the object itself as a subject relation.
const ellipsis = "..."

// ErrSchema is returned for a schema that does not compile, or that compiles
// into something SpiceDB's type system would refuse.
var ErrSchema = errors.New("spicedb: invalid schema")

// Schema is a compiled schema: the model lowered from it, and its caveats
// compiled in SpiceDB's CEL environment. It is the CaveatEvaluator to check its
// model with.
type Schema struct {
	Model *zanzibar.Model

	compiled map[string]*caveats.CompiledCaveat
	refs     map[string]map[string]*core.CaveatTypeReference
}

// Compile compiles a schema. file is the name positions are reported against
// and firstLine the line of it the text starts on, which is not 1 for a schema
// written inside a validation file; imports is where the schema's imports are
// read from, nil when it has none. SpiceDB keeps an import inside it, refusing
// a path with .. or one that is not local (pkg/schemadsl/compiler/importer.go
// at v1.56.2).
func Compile(file string, imports fs.FS, firstLine int, text string) (*Schema, error) {
	var opts []compiler.Option
	if imports != nil {
		opts = append(opts, compiler.SourceFS(imports))
	}
	compiled, err := compiler.Compile(compiler.InputSchema{
		Source:       input.Source(file),
		SchemaString: text,
	}, compiler.AllowUnprefixedObjectType(), opts...)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrSchema, file, err)
	}

	at := origin{file: file, line: firstLine}
	s := &Schema{
		compiled: make(map[string]*caveats.CompiledCaveat, len(compiled.CaveatDefinitions)),
		refs:     make(map[string]map[string]*core.CaveatTypeReference, len(compiled.CaveatDefinitions)),
	}
	caveatList := make([]*zanzibar.Caveat, 0, len(compiled.CaveatDefinitions))
	for _, def := range compiled.CaveatDefinitions {
		c, err := s.lowerCaveat(at, def)
		if err != nil {
			return nil, err
		}
		caveatList = append(caveatList, c)
	}

	types := make([]*zanzibar.Type, 0, len(compiled.ObjectDefinitions))
	for _, def := range compiled.ObjectDefinitions {
		t, err := lowerType(at, def)
		if err != nil {
			return nil, err
		}
		types = append(types, t)
	}

	model, err := zanzibar.NewModel(types, caveatList)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrSchema, file, err)
	}
	if err := validate(model); err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrSchema, file, err)
	}
	s.Model = model
	return s, nil
}

func (s *Schema) lowerCaveat(at origin, def *core.CaveatDefinition) (*zanzibar.Caveat, error) {
	params, err := caveattypes.DecodeParameterTypes(caveattypes.Default.TypeSet, def.GetParameterTypes())
	if err != nil {
		return nil, fmt.Errorf("%w: %s: caveat %s: %w", ErrSchema, at.file, def.GetName(), err)
	}
	compiled, err := caveats.DeserializeCaveatWithTypeSet(caveattypes.Default.TypeSet, def.GetSerializedExpression(), params)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: caveat %s: %w", ErrSchema, at.file, def.GetName(), err)
	}
	s.compiled[def.GetName()] = compiled
	s.refs[def.GetName()] = def.GetParameterTypes()

	c := &zanzibar.Caveat{Name: def.GetName(), Position: at.position(def.GetSourcePosition())}
	for name, ref := range def.GetParameterTypes() {
		c.Parameters = append(c.Parameters, zanzibar.Parameter{Name: name, Type: caveats.ParameterTypeString(ref)})
	}
	sort.Slice(c.Parameters, func(i, j int) bool { return c.Parameters[i].Name < c.Parameters[j].Name })
	return c, nil
}

func lowerType(at origin, def *core.NamespaceDefinition) (*zanzibar.Type, error) {
	t := &zanzibar.Type{Name: def.GetName(), Position: at.position(def.GetSourcePosition())}
	for _, rel := range def.GetRelation() {
		pos := at.position(rel.GetSourcePosition())
		if rel.GetUsersetRewrite() == nil {
			r := &zanzibar.Relation{Name: rel.GetName(), Position: pos}
			for _, allowed := range rel.GetTypeInformation().GetAllowedDirectRelations() {
				r.Allowed = append(r.Allowed, lowerAllowed(allowed))
			}
			t.Relations = append(t.Relations, r)
			continue
		}
		expr, err := lowerRewrite(at, rel.GetUsersetRewrite())
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %s#%s: %w", ErrSchema, at.file, def.GetName(), rel.GetName(), err)
		}
		t.Permissions = append(t.Permissions, &zanzibar.Permission{Name: rel.GetName(), Expr: expr, Position: pos})
	}
	return t, nil
}

func lowerAllowed(allowed *core.AllowedRelation) zanzibar.Allowed {
	a := zanzibar.Allowed{
		Type:       allowed.GetNamespace(),
		Caveat:     allowed.GetRequiredCaveat().GetCaveatName(),
		Expiration: allowed.GetRequiredExpiration() != nil,
	}
	switch {
	case allowed.GetPublicWildcard() != nil:
		a.Wildcard = true
	case allowed.GetRelation() != ellipsis:
		a.Relation = allowed.GetRelation()
	}
	return a
}

func lowerRewrite(at origin, rewrite *core.UsersetRewrite) (zanzibar.Expr, error) {
	switch op := rewrite.GetRewriteOperation().(type) {
	case *core.UsersetRewrite_Union:
		children, err := lowerChildren(at, op.Union.GetChild())
		return zanzibar.Union{Children: children}, err
	case *core.UsersetRewrite_Intersection:
		children, err := lowerChildren(at, op.Intersection.GetChild())
		return zanzibar.Intersection{Children: children}, err
	case *core.UsersetRewrite_Exclusion:
		children, err := lowerChildren(at, op.Exclusion.GetChild())
		if err != nil {
			return nil, err
		}
		if len(children) < 2 {
			return nil, errors.New("an exclusion with nothing to exclude")
		}
		return zanzibar.Exclusion{Base: children[0], Subtracted: children[1:]}, nil
	}
	return nil, fmt.Errorf("rewrite %T", rewrite.GetRewriteOperation())
}

func lowerChildren(at origin, children []*core.SetOperation_Child) ([]zanzibar.Expr, error) {
	out := make([]zanzibar.Expr, 0, len(children))
	for _, child := range children {
		expr, err := lowerChild(at, child)
		if err != nil {
			return nil, err
		}
		out = append(out, expr)
	}
	return out, nil
}

func lowerChild(at origin, child *core.SetOperation_Child) (zanzibar.Expr, error) {
	pos := at.position(child.GetSourcePosition())
	switch c := child.GetChildType().(type) {
	case *core.SetOperation_Child_ComputedUserset:
		if c.ComputedUserset.GetObject() != core.ComputedUserset_TUPLE_OBJECT {
			return nil, errors.New("a computed userset on the subject of a relationship, outside an arrow")
		}
		return zanzibar.Computed{Name: c.ComputedUserset.GetRelation(), Position: pos}, nil
	case *core.SetOperation_Child_TupleToUserset:
		return zanzibar.Arrow{
			Through:  c.TupleToUserset.GetTupleset().GetRelation(),
			Target:   c.TupleToUserset.GetComputedUserset().GetRelation(),
			Position: pos,
		}, nil
	case *core.SetOperation_Child_FunctionedTupleToUserset:
		ttu := c.FunctionedTupleToUserset
		var all bool
		switch ttu.GetFunction() {
		case core.FunctionedTupleToUserset_FUNCTION_ANY:
		case core.FunctionedTupleToUserset_FUNCTION_ALL:
			all = true
		default:
			return nil, fmt.Errorf("arrow function %s", ttu.GetFunction())
		}
		return zanzibar.Arrow{
			Through:  ttu.GetTupleset().GetRelation(),
			Target:   ttu.GetComputedUserset().GetRelation(),
			All:      all,
			Position: pos,
		}, nil
	case *core.SetOperation_Child_UsersetRewrite:
		return lowerRewrite(at, c.UsersetRewrite)
	case *core.SetOperation_Child_XNil:
		return zanzibar.Nil{}, nil
	case *core.SetOperation_Child_XSelf:
		return zanzibar.Self{}, nil
	case *core.SetOperation_Child_XThis:
		// The schema language cannot write it; it belongs to namespace
		// configurations older than the language.
		return nil, errors.New("_this, which the schema language does not produce")
	}
	return nil, fmt.Errorf("set operation child %T", child.GetChildType())
}

// origin is where the text of a schema starts in the file it was read from.
type origin struct {
	file string
	line int
}

// position turns a position SpiceDB reports in the text of the schema into one
// in the file.
func (at origin) position(pos *core.SourcePosition) zanzibar.Position {
	if pos == nil {
		return zanzibar.Position{File: at.file}
	}
	return zanzibar.Position{
		File:   at.file,
		Line:   at.line + int(pos.GetZeroIndexedLineNumber()), //nolint:gosec // a line of a schema file fits in an int
		Column: int(pos.GetZeroIndexedColumnPosition()) + 1,   //nolint:gosec // a column of a schema file fits in an int
	}
}

// validate refuses what SpiceDB's type system refuses and the compiler lets
// through, the references a definition makes to names it does not declare.
// petard does not import the type system, which brings SpiceDB's datastore
// with it; the checks here are the ones of
// pkg/schema/typesystem_validation.go at v1.56.2 that the engine relies on.
func validate(m *zanzibar.Model) error {
	for _, t := range m.Types {
		for _, r := range t.Relations {
			if len(r.Allowed) == 0 {
				return fmt.Errorf("%s#%s allows no subject", t.Name, r.Name)
			}
			for _, a := range r.Allowed {
				target := m.Type(a.Type)
				if target == nil {
					return fmt.Errorf("%s#%s allows %s, which is not declared", t.Name, r.Name, a.Type)
				}
				if a.Relation != "" && !target.Declares(a.Relation) {
					return fmt.Errorf("%s#%s allows %s#%s, which is not declared", t.Name, r.Name, a.Type, a.Relation)
				}
				if a.Caveat != "" && m.Caveat(a.Caveat) == nil {
					return fmt.Errorf("%s#%s uses caveat %s, which is not declared", t.Name, r.Name, a.Caveat)
				}
			}
		}
		for _, p := range t.Permissions {
			if err := validateExpr(t, p, p.Expr); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateExpr(t *zanzibar.Type, p *zanzibar.Permission, expr zanzibar.Expr) error {
	switch e := expr.(type) {
	case zanzibar.Union:
		return validateAll(t, p, e.Children)
	case zanzibar.Intersection:
		return validateAll(t, p, e.Children)
	case zanzibar.Exclusion:
		if err := validateExpr(t, p, e.Base); err != nil {
			return err
		}
		return validateAll(t, p, e.Subtracted)
	case zanzibar.Computed:
		if !t.Declares(e.Name) {
			return fmt.Errorf("%s#%s uses %s, which is not declared", t.Name, p.Name, e.Name)
		}
	case zanzibar.Arrow:
		through := t.Relation(e.Through)
		if through == nil {
			if t.Permission(e.Through) != nil {
				return fmt.Errorf("%s#%s walks %s, a permission: only a relation can be walked", t.Name, p.Name, e.Through)
			}
			return fmt.Errorf("%s#%s walks %s, which is not declared", t.Name, p.Name, e.Through)
		}
		for _, a := range through.Allowed {
			if a.Wildcard {
				return fmt.Errorf("%s#%s walks %s, which allows %s:*: a wildcard cannot be walked", t.Name, p.Name, e.Through, a.Type)
			}
		}
	}
	return nil
}

func validateAll(t *zanzibar.Type, p *zanzibar.Permission, exprs []zanzibar.Expr) error {
	for _, e := range exprs {
		if err := validateExpr(t, p, e); err != nil {
			return err
		}
	}
	return nil
}

// Evaluate evaluates a caveat of the schema the way SpiceDB does: parameters
// the context does not fill stay unknown, and a result that depends on them is
// Conditional. Keys that name no parameter of the caveat are ignored.
func (s *Schema) Evaluate(name string, context map[string]any) (zanzibar.Level, error) {
	compiled, ok := s.compiled[name]
	if !ok {
		return zanzibar.No, fmt.Errorf("caveat %s is not declared", name)
	}
	typed, err := caveats.ConvertContextToParameters(caveattypes.Default.TypeSet, context, s.refs[name], caveats.SkipUnknownParameters)
	if err != nil {
		return zanzibar.No, err
	}
	result, err := caveats.EvaluateCaveat(compiled, typed)
	if err != nil {
		return zanzibar.No, err
	}
	switch {
	case result.IsPartial():
		return zanzibar.Conditional, nil
	case result.Value():
		return zanzibar.Yes, nil
	}
	return zanzibar.No, nil
}
