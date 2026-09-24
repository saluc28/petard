package taxonomy

import (
	"errors"
	"fmt"

	"github.com/saluc28/petard/internal/opaengine"
	"github.com/saluc28/petard/internal/pep"
)

// This file is where a declared enforcement point meets the analysis: the
// decisions it asks for, the part of the request that names who asks, and how
// much of what the decisions read of the request it speaks about.

// DeclareEnforcementPoint adds to a bundle the decisions an enforcement point
// asks for, on the side each of them lands on.
//
// The product asks for rules by name, and which rules of the bundle carry the
// name is a fact the bundle states: the same move measure makes with the
// violation of Gatekeeper, made here from a declaration that says where it was
// read. A bundle holding none of them is not a policy for that product, and
// saying so beats reporting a policy nobody asked anything of.
func DeclareEnforcementPoint(bundle *opaengine.Bundle, point *pep.EnforcementPoint) error {
	if point == nil {
		return nil
	}
	grants, denies := point.Entrypoints(bundle.RulesNamed)
	if len(grants)+len(denies) == 0 {
		var names []string
		for _, decision := range point.Decisions {
			names = append(names, decision.Rule)
		}
		return fmt.Errorf("taxonomy: %s asks for %v, and the bundle has no rule by any of those names", point.ID, names)
	}
	bundle.Entrypoints = append(bundle.Entrypoints, grants...)
	bundle.DenyEntrypoints = append(bundle.DenyEntrypoints, denies...)
	return nil
}

// ShapeOf recognizes the shape of the request, taking the subject from where it
// is declared: the command line first, then the enforcement point, and when
// neither says, from what the decisions read.
//
// The subject an enforcement point declares is where the product puts the
// requester, and a policy may never look at it: the login policy of the
// Spacelift starter repository reads the teams and nothing else. That is not an
// error in the declaration, so the shape is then recognized as if nothing had
// been declared.
func ShapeOf(reads *opaengine.ReadSet, subject string, point *pep.EnforcementPoint) (opaengine.Shape, error) {
	if subject != "" || point == nil || point.Subject == "" {
		return opaengine.ShapeOf(reads, subject)
	}
	shape, err := opaengine.ShapeOf(reads, point.Subject)
	if errors.Is(err, opaengine.ErrSubjectNotRead) {
		return opaengine.RecognizeShape(reads), nil
	}
	return shape, err
}

// RequestCoverage is how much of what the decisions read of the request an
// enforcement point speaks about.
type RequestCoverage struct {
	// Read are the parts of the request the decisions read, and Declared the
	// ones the enforcement point says who sets.
	Read     []string
	Declared []string

	// ByCaller are the declared ones whoever sends the request sets.
	ByCaller []string
}

// RequestCoverageOf measures an enforcement point against the parts of the
// request the decisions read.
func RequestCoverageOf(reads *opaengine.ReadSet, point *pep.EnforcementPoint) RequestCoverage {
	coverage := RequestCoverage{Read: reads.InputPaths}
	for _, path := range reads.InputPaths {
		field, declared := point.FieldFor(path)
		if !declared {
			continue
		}
		coverage.Declared = append(coverage.Declared, path)
		if field.SetBy == pep.SetByCaller {
			coverage.ByCaller = append(coverage.ByCaller, path)
		}
	}
	return coverage
}
