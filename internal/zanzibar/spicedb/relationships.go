package spicedb

import (
	"errors"
	"fmt"
	"strings"

	"github.com/authzed/spicedb/pkg/tuple"

	"github.com/saluc28/petard/internal/zanzibar"
)

// ErrRelationship is returned for a relationship that does not parse.
var ErrRelationship = errors.New("spicedb: invalid relationship")

// ParseRelationships reads relationships one per line, in the notation of
// SpiceDB, document:readme#viewer@user:alice, with a caveat and an expiration
// written after it in brackets. Blank lines and lines starting with // are
// skipped, as in the relationships block of a validation file
// (pkg/validationfile/blocks/relationships.go at v1.56.2). firstLine is the
// line of the file the text starts on, so that positions point into the file.
func ParseRelationships(file string, firstLine int, text string) ([]zanzibar.Relationship, error) {
	var out []zanzibar.Relationship
	for i, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") {
			continue
		}
		pos := zanzibar.Position{File: file, Line: firstLine + i, Column: strings.Index(line, trimmed) + 1}
		rel, err := tuple.Parse(trimmed)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %q: %w", ErrRelationship, pos, trimmed, err)
		}
		out = append(out, lowerRelationship(rel, pos))
	}
	return out, nil
}

func lowerRelationship(rel tuple.Relationship, pos zanzibar.Position) zanzibar.Relationship {
	r := zanzibar.Relationship{
		Resource: zanzibar.Object{Type: rel.Resource.ObjectType, ID: rel.Resource.ObjectID},
		Relation: rel.Resource.Relation,
		Subject:  lowerSubject(rel.Subject),
		Expires:  rel.OptionalExpiration,
		Position: pos,
	}
	if c := rel.OptionalCaveat; c != nil && c.GetCaveatName() != "" {
		r.Caveat = &zanzibar.CaveatUse{Name: c.GetCaveatName(), Context: c.GetContext().AsMap()}
	}
	return r
}

func lowerSubject(onr tuple.ObjectAndRelation) zanzibar.Subject {
	s := zanzibar.Subject{Object: zanzibar.Object{Type: onr.ObjectType, ID: onr.ObjectID}}
	if onr.Relation != ellipsis {
		s.Relation = onr.Relation
	}
	return s
}
