package openfga

import (
	"errors"
	"fmt"
	"slices"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"github.com/openfga/openfga/pkg/tuple"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/saluc28/petard/internal/zanzibar"
)

// ErrTuple is returned for a tuple the model does not admit.
var ErrTuple = errors.New("openfga: invalid tuple")

// inlineExpressionKeys are the keys of a tuple's context an inline condition reads
// (internal/condition/inline.go:24-25). OpenFGA evaluates the expression against
// the context of the check alone (internal/condition/eval/eval.go:61), so anything
// else written beside them counts for nothing.
var inlineExpressionKeys = []string{inlineExpressionParameter, "parameters"}

// LowerTuple lowers a tuple of OpenFGA into a relationship. pos is where it was
// read.
func LowerTuple(pos zanzibar.Position, key *openfgav1.TupleKey) zanzibar.Relationship {
	objectType, objectID := tuple.SplitObject(key.GetObject())
	userObject, userRelation := tuple.SplitObjectRelation(key.GetUser())
	userType, userID := tuple.SplitObject(userObject)

	r := zanzibar.Relationship{
		Resource: zanzibar.Object{Type: objectType, ID: objectID},
		Relation: key.GetRelation(),
		Subject:  zanzibar.Subject{Object: zanzibar.Object{Type: userType, ID: userID}, Relation: userRelation},
		Position: pos,
	}
	if c := key.GetCondition(); c.GetName() != "" {
		r.Caveat = &zanzibar.CaveatUse{Name: c.GetName(), Context: c.GetContext().AsMap()}
		if c.GetName() == inlineExpression {
			for name := range r.Caveat.Context {
				if !slices.Contains(inlineExpressionKeys, name) {
					delete(r.Caveat.Context, name)
				}
			}
		}
	}
	return r
}

// Admit says whether the model admits a relationship, as a write of OpenFGA asks
// (internal/validation/validation.go:60-85, :142-188, :213-312). A check also
// reads only the tuples that pass (FilterInvalidTuples, :379-384), so a tuple left
// over from an older model counts for nothing rather than for what it used to
// mean.
//
// The form of the subject and the condition are one question: a relation that
// admits user with a condition does not admit user without one, nor user:* with
// it.
func (s *Schema) Admit(r zanzibar.Relationship) error {
	t := s.Model.Type(r.Resource.Type)
	if t == nil {
		return fmt.Errorf("%w: %s: type %s is not declared", ErrTuple, r, r.Resource.Type)
	}
	relation := t.Relation(r.Relation)
	if relation == nil {
		if t.Declares(r.Relation) {
			return fmt.Errorf("%w: %s: %s#%s takes no tuples", ErrTuple, r, r.Resource.Type, r.Relation)
		}
		return fmt.Errorf("%w: %s: %s#%s is not declared", ErrTuple, r, r.Resource.Type, r.Relation)
	}
	if r.Resource.ID == zanzibar.WildcardID {
		return fmt.Errorf("%w: %s: an object cannot be a wildcard", ErrTuple, r)
	}

	name := ""
	if r.Caveat != nil {
		name = r.Caveat.Name
	}
	if !slices.ContainsFunc(relation.Allowed, func(a zanzibar.Allowed) bool {
		return a.Caveat == name && admitsSubject(a, r.Subject)
	}) {
		if name == "" {
			return fmt.Errorf("%w: %s: %s#%s does not admit this subject without a condition", ErrTuple, r, r.Resource.Type, r.Relation)
		}
		return fmt.Errorf("%w: %s: %s#%s does not admit this subject with condition %s", ErrTuple, r, r.Resource.Type, r.Relation, name)
	}

	if name == "" || name == inlineExpression {
		return nil
	}
	fields, err := structpb.NewStruct(r.Caveat.Context)
	if err != nil {
		return fmt.Errorf("%w: %s: context of condition %s: %w", ErrTuple, r, name, err)
	}
	typed, err := s.types.GetConditions()[name].CastContextToTypedParameters(fields.GetFields())
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrTuple, r, err)
	}
	for key := range fields.GetFields() {
		if _, ok := typed[key]; !ok {
			return fmt.Errorf("%w: %s: condition %s has no parameter %s", ErrTuple, r, name, key)
		}
	}
	return nil
}

// admitCheck says whether a check names what the model declares, which OpenFGA asks of
// a request before it answers (internal/validation/validation.go:19-33, :389-482). The
// engine has no reason to: nothing it asks names what the model does not declare.
func (s *Schema) admitCheck(asked zanzibar.Relationship) error {
	t := s.Model.Type(asked.Resource.Type)
	switch {
	case t == nil:
		return fmt.Errorf("type %s is not declared", asked.Resource.Type)
	case !t.Declares(asked.Relation):
		return fmt.Errorf("%s#%s is not declared", asked.Resource.Type, asked.Relation)
	}
	subject := s.Model.Type(asked.Subject.Type)
	switch {
	case subject == nil:
		return fmt.Errorf("type %s is not declared", asked.Subject.Type)
	case asked.Subject.Relation != "" && !subject.Declares(asked.Subject.Relation):
		return fmt.Errorf("%s#%s is not declared", asked.Subject.Type, asked.Subject.Relation)
	}
	return nil
}

func admitsSubject(a zanzibar.Allowed, s zanzibar.Subject) bool {
	switch {
	case a.Type != s.Type:
		return false
	case a.Wildcard:
		return s.ID == zanzibar.WildcardID && s.Relation == ""
	case s.ID == zanzibar.WildcardID:
		return false
	}
	return a.Relation == s.Relation
}
