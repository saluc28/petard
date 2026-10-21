package zanzibar

import (
	"fmt"
	"slices"
	"strings"
)

// SelfAssertedExemptionID is PTD-ZAN-001: a caveat holds a relationship to a
// condition on a value the check was meant to supply, and whoever writes the
// relationship can fix that value instead, so the condition reads the writer's
// value on every check that follows.
const SelfAssertedExemptionID = "PTD-ZAN-001"

// SelfAssertedExemptions finds, under a write model, the relations a coalition
// can write with a caveat whose check-supplied parameter it can set itself.
// SpiceDB lets a write carry any declared parameter of the caveat
// (internal/relationships/validation.go:248-262 at v1.56.2), and the written
// context wins over the check's (internal/caveats/run.go:222-230), so a
// parameter the write model marks as the application's is the writer's to fix.
// Fixing it raises the permissions the relation feeds from conditional to
// unconditional.
//
// It is the write-model form of the pattern: who writes the relation, and that
// the parameter is the check's, are declared, so the match is a finding. Where
// no write model says so, WriterSetParameters reads the same pattern off the
// sample as a candidate.
//
// The coalition is studied as every type the schema admits as a subject, not a
// user alone, so a schema whose actors are accounts or services is covered too:
// a gate is reachable when any such subject can hold it.
func SelfAssertedExemptions(model *Model, wm *WriteModel, opts Options) []Match {
	positions := startingPositionsForSubjects(model, opts)
	var out []Match
	for _, w := range wm.Writes {
		if !writes(w.Operations) {
			// The exemption rides on writing the tuple; a delete rule does not
			// set a caveat context.
			continue
		}
		t := model.Type(w.Resource)
		if t == nil {
			continue
		}
		r := t.Relation(w.Relation)
		if r == nil {
			continue
		}
		for _, cw := range w.Caveats {
			if !relationAllowsCaveat(r, cw.Name) {
				// The write model attaches a caveat the relation does not carry;
				// SpiceDB would refuse the write, so it opens nothing.
				continue
			}
			cav := model.Caveat(cw.Name)
			if cav == nil {
				continue
			}
			for _, param := range cav.Parameters {
				if cw.Filler(param.Name) != FillerApplication {
					continue
				}
				perms := positivePermissions(model, w.Resource, w.Relation)
				if len(perms) == 0 {
					// The relation feeds no permission, so fixing the caveat
					// raises nothing to report.
					continue
				}
				if !gateReachable(w.Gate, w.Resource, positions) {
					continue
				}
				out = append(out, exemptionMatch(w, r.Position, cw.Name, param.Name, perms))
			}
		}
	}
	return out
}

// startingPositionsForSubjects generates starting positions for an attacker of
// every type the schema admits as a direct subject, so reachability is judged
// over all of them rather than over a user alone.
func startingPositionsForSubjects(model *Model, opts Options) []StartingPosition {
	var positions []StartingPosition
	for _, typ := range subjectTypes(model) {
		positions = append(positions, StartingPositions(model, Object{Type: typ, ID: "attacker"}, opts)...)
	}
	return positions
}

// subjectTypes is every type that appears as a direct subject of some relation:
// the objects the schema lets hold a relation on their own, which is what a
// coalition member is. A userset or a wildcard is not one, since neither is an
// object a coalition controls by being it.
func subjectTypes(model *Model) []string {
	var types []string
	for _, t := range model.Types {
		for _, r := range t.Relations {
			for _, a := range r.Allowed {
				if a.Relation == "" && !a.Wildcard && !slices.Contains(types, a.Type) {
					types = append(types, a.Type)
				}
			}
		}
	}
	return types
}

// relationAllowsCaveat reports whether a relation has an allowed subject form
// that carries the caveat.
func relationAllowsCaveat(r *Relation, caveat string) bool {
	for _, a := range r.Allowed {
		if a.Caveat == caveat {
			return true
		}
	}
	return false
}

// gateReachable reports whether a coalition can hold the gate of a write rule on
// a resource of the schema. A service gate no end user drives is out of reach;
// anyone is always in reach; a gate that holds a permission is in reach when a
// starting position puts the attacker there, which is the closure's own account
// of what the coalition can hold before it writes.
func gateReachable(gate Gate, resource string, positions []StartingPosition) bool {
	switch {
	case gate.Service != "":
		return false
	case gate.Anyone:
		return true
	case gate.Holds != "":
		return slices.ContainsFunc(positions, func(p StartingPosition) bool {
			return p.Type == resource && p.Target == gate.Holds
		})
	}
	return false
}

// exemptionMatch builds the finding for a self-asserted exemption.
func exemptionMatch(w *WriteRule, at Position, caveat, parameter string, perms []string) Match {
	m := Match{
		PatternID: SelfAssertedExemptionID,
		Verdict:   Finding,
		Subject:   fmt.Sprintf("%s#%s, %s of caveat %s", w.Resource, w.Relation, parameter, caveat),
	}
	via := w.Via
	if via == "" {
		via = "a write the model allows"
	}
	m.Details = append(m.Details,
		Detail{
			Label:    "written by",
			Text:     fmt.Sprintf("%s may write %s#%s, at %s, with %s, through %s", gatePhrase(w.Gate), w.Resource, w.Relation, at, caveat, via),
			Position: at,
		},
		Detail{
			Label: "the check brings",
			Text:  fmt.Sprintf("%s, which the writer may set on the relationship instead, fixing it for every check that goes through", parameter),
		},
		Detail{
			Label: "raises",
			Text:  fmt.Sprintf("%s on %s, from conditional to unconditional", permissionList(perms), w.Resource),
		},
	)
	return m
}

// gatePhrase names who a gate lets write, as the subject of a report sentence.
func gatePhrase(g Gate) string {
	switch {
	case g.Anyone:
		return "anyone"
	case g.Holds != "":
		return "whoever holds " + g.Holds
	case g.Service != "":
		return "the " + g.Service + " service"
	}
	return "whoever is allowed"
}

// permissionList writes a list of permissions as prose, one or several.
func permissionList(perms []string) string {
	switch len(perms) {
	case 1:
		return perms[0]
	case 2:
		return perms[0] + " and " + perms[1]
	default:
		return fmt.Sprintf("%s and %s", strings.Join(perms[:len(perms)-1], ", "), perms[len(perms)-1])
	}
}
