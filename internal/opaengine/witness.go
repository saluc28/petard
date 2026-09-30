package opaengine

import (
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
)

// maxWitnesses bounds the requests Witnesses writes for one comparison. Each one
// costs an evaluation of the decision on each side.
const maxWitnesses = 16

// witnessFiller is written into a field a condition reads without pinning it,
// and into the elements of a list nothing pins: any value satisfies the
// condition there, but the field has to be defined.
const witnessFiller = "petard"

// Witnesses returns requests that can prove this grant reaches beyond the other
// where Beyond cannot tell: for each condition whose readable fields escape
// every condition of the other, the requests that satisfy those fields, written
// over a copy of the part of the request the question fixed.
//
// Beyond leaves such a gain uncertain when a condition also negates a rule
// partial evaluation generated, reads a field it cannot turn into values, or
// comes from a residual a bound cut short: any of them can rule out the very
// requests the readable fields let through, the way a deny that switches off
// every delete rules out a delete a new role seems to grant. Evaluating one of
// these requests on both sides settles it. A request granted on this side and
// refused on the other is a gain, whatever the unread part of the condition
// was. A request that is not proves nothing either way.
func (g GrantContent) Witnesses(other GrantContent, fixed map[string]any) []map[string]any {
	if g.always || other.always {
		return nil
	}
	var requests []map[string]any
	for _, condition := range g.conditions {
		if condition.opaqueOther || !escapesAll(condition, other.conditions) {
			continue
		}
		for _, request := range condition.requests(fixed) {
			requests = append(requests, request)
			if len(requests) == maxWitnesses {
				return requests
			}
		}
	}
	return requests
}

// escapesAll reports whether a condition escapes every one of the others on the
// fields they read.
func escapesAll(condition grantCondition, others []grantCondition) bool {
	for _, other := range others {
		if readableCoverage(other, condition) != escapes {
			return false
		}
	}
	return true
}

// requests writes the requests that satisfy the fields a condition reads, one
// for each choice among the values a field may take. A field the condition only
// reads opaquely is left out, since nothing here says what satisfies it, and the
// fixed part of the request is kept wherever the condition names it too.
func (c grantCondition) requests(fixed map[string]any) []map[string]any {
	type assignment struct {
		field string
		value any
	}

	choices := [][]assignment{{}}
	lengths := map[string]int{}
	for _, field := range slices.Sorted(maps.Keys(c.fields)) {
		constraint := c.fields[field]
		if list, isLength := strings.CutSuffix(field, "[#]"); isLength {
			for value := range constraint.values {
				if n, err := strconv.Atoi(value); err == nil {
					lengths[list] = n
				}
			}
			continue
		}

		var next [][]assignment
		for _, chosen := range choices {
			for _, option := range constraint.options() {
				next = append(next, append(slices.Clone(chosen), assignment{field: field, value: option}))
			}
		}
		if len(next) > maxWitnesses {
			next = next[:maxWitnesses]
		}
		choices = next
	}

	var requests []map[string]any
choosing:
	for _, chosen := range choices {
		request := copyRequest(fixed)
		for _, set := range chosen {
			if !writeField(request, set.field, set.value) {
				continue choosing
			}
		}
		for list, n := range lengths {
			for i := range n {
				if !writeField(request, indexField(list, i), witnessFiller) {
					continue choosing
				}
			}
		}
		fillGaps(request)
		requests = append(requests, request)
	}
	return requests
}

// options returns the values a field can take to satisfy the constraint: the
// collection holding every value a membership asks for, each value an equality
// pins, each prefix a wildcard match allows, or, for a field read and pinned to
// nothing, a filler.
func (f fieldConstraint) options() []any {
	values := slices.Sorted(maps.Keys(f.values))
	switch {
	case f.member:
		collection := []any{}
		for _, value := range values {
			collection = append(collection, f.valueOf(value))
		}
		if len(collection) == 0 {
			collection = append(collection, witnessFiller)
		}
		return []any{collection}
	case len(values) > 0:
		var options []any
		for _, value := range values {
			options = append(options, f.valueOf(value))
		}
		return options
	case len(f.prefixes) > 0:
		var options []any
		for _, prefix := range slices.Sorted(maps.Keys(f.prefixes)) {
			options = append(options, prefix)
		}
		return options
	default:
		return []any{witnessFiller}
	}
}

// valueOf writes a pinned value as a request carries it, with the type it was
// written with.
func (f fieldConstraint) valueOf(value string) any {
	if term := f.terms[value]; term != nil {
		if written, err := ast.JSON(term.Value); err == nil {
			return written
		}
	}
	return value
}

// writeField sets one field of a request, written as grant conditions name
// fields: input.token.user.id, input.path[0], input.items[_].name. A range over
// a list becomes its first element. A field the fixed part of the request
// already sets keeps its value, and a field that cannot be written reports
// false.
func writeField(request map[string]any, field string, value any) bool {
	ref, err := ast.ParseRef(field)
	if err != nil || !isInputRooted(ref) || len(ref) < 2 {
		return false
	}
	_, ok := setAt(request, ref[1:], value)
	return ok
}

// setAt writes a value at a path under a container, creating the objects and
// lists on the way, and returns the container as it is afterwards.
func setAt(container any, path ast.Ref, value any) (any, bool) {
	if len(path) == 0 {
		if container != nil {
			return container, true
		}
		return value, true
	}

	switch key := path[0].Value.(type) {
	case ast.String:
		object, isObject := container.(map[string]any)
		if container == nil {
			object, isObject = map[string]any{}, true
		}
		if !isObject {
			return container, false
		}
		child, ok := setAt(object[string(key)], path[1:], value)
		if !ok {
			return container, false
		}
		object[string(key)] = child
		return object, true

	case ast.Number, ast.Var:
		index := 0
		if number, isNumber := key.(ast.Number); isNumber {
			i, isInt := number.Int()
			if !isInt || i < 0 {
				return container, false
			}
			index = i
		}
		list, isList := container.([]any)
		if container == nil {
			isList = true
		}
		if !isList {
			return container, false
		}
		for len(list) <= index {
			list = append(list, nil)
		}
		child, ok := setAt(list[index], path[1:], value)
		if !ok {
			return container, false
		}
		list[index] = child
		return list, true
	}
	return container, false
}

// fillGaps puts the filler in the elements of a list nothing wrote, so that a
// list pinned at its third element has two defined elements before it. It
// changes the objects and lists it is given in place.
func fillGaps(value any) {
	switch value := value.(type) {
	case map[string]any:
		for _, child := range value {
			fillGaps(child)
		}
	case []any:
		for i, child := range value {
			if child == nil {
				value[i] = witnessFiller
				continue
			}
			fillGaps(child)
		}
	}
}

// copyRequest copies the fixed part of a request, so that writing a witness
// into the copy leaves it alone.
func copyRequest(fixed map[string]any) map[string]any {
	request := make(map[string]any, len(fixed))
	for key, value := range fixed {
		request[key] = copyValue(value)
	}
	return request
}

// copyValue copies a value of a request as JSON would.
func copyValue(value any) any {
	switch value := value.(type) {
	case map[string]any:
		copied := make(map[string]any, len(value))
		for key, child := range value {
			copied[key] = copyValue(child)
		}
		return copied
	case []any:
		copied := make([]any, len(value))
		for i, child := range value {
			copied[i] = copyValue(child)
		}
		return copied
	}
	return value
}
