package zanzibar

import "slices"

// GateProposal is, for a relation the write model leaves without a rule, which
// permissions on the resource are safe gates to write it and which would let a
// coalition escalate. It is how a write model enters without being written by
// hand: petard proposes a gate per such relation, the author confirms which one
// the application uses, and commits.
type GateProposal struct {
	Type     string
	Relation string

	// Safe are the permissions that, used as the gate, let no coalition raise
	// anything by writing the relation.
	Safe []string

	// Unsafe are the permissions that would, each with a witness of what writing
	// the relation under it opens.
	Unsafe []UnsafeGate
}

// UnsafeGate is a permission that is not a safe gate for a relation, with an
// escalation it would allow.
type UnsafeGate struct {
	Permission string
	Escalation Escalation
}

// SafeGates computes, for every relation the write model leaves without a rule,
// which permissions on its type are safe gates to write it. A permission W is a
// safe gate for relation r of type T when letting every holder of W write r, as
// the schema allows its subjects, raises nothing for any coalition, read with
// the closure over the starting positions (section 6 of the definitions).
//
// Each gate is tried on top of the write model as it stands, so a proposal is
// weighed together with the rules already declared. A relation whose every
// permission is unsafe has no safe gate, and the run says so rather than
// proposing one.
func SafeGates(model *Model, wm *WriteModel, caveats CaveatEvaluator, opts Options) ([]GateProposal, error) {
	var proposals []GateProposal
	for _, t := range model.Types {
		for _, r := range t.Relations {
			if hasWriteRule(wm, t.Name, r.Name) {
				continue
			}
			proposal := GateProposal{Type: t.Name, Relation: r.Name}
			for _, p := range t.Permissions {
				esc, unsafe, err := gateEscalates(model, wm, caveats, t.Name, r, p.Name, opts)
				if err != nil {
					return nil, err
				}
				if unsafe {
					proposal.Unsafe = append(proposal.Unsafe, UnsafeGate{Permission: p.Name, Escalation: esc})
				} else {
					proposal.Safe = append(proposal.Safe, p.Name)
				}
			}
			proposals = append(proposals, proposal)
		}
	}
	return proposals, nil
}

// hasWriteRule reports whether the write model already has a rule for a relation.
func hasWriteRule(wm *WriteModel, resource, relation string) bool {
	for _, w := range wm.Writes {
		if w.Resource == resource && w.Relation == relation {
			return true
		}
	}
	return false
}

// gateEscalates reports whether letting holders of permission gate write
// relation r of type typ lets a coalition escalate, with a witness when it does.
// It adds the proposed rule to the write model and runs the escalation search
// from every starting position in which the attacker holds the gate.
func gateEscalates(model *Model, wm *WriteModel, caveats CaveatEvaluator, typ string, r *Relation, gate string, opts Options) (Escalation, bool, error) {
	proposed := &WriteModel{
		SchemaVersion: wm.SchemaVersion,
		Kind:          wm.Kind,
		Writes: append(slices.Clone(wm.Writes), &WriteRule{
			Resource:   typ,
			Relation:   r.Name,
			Operations: []Operation{Create, Touch},
			Gate:       Gate{Holds: gate},
			Subject:    SubjectSpec{Any: true},
			Wildcard:   allowsWildcard(r),
		}),
		Creates: wm.Creates,
	}

	for _, p := range startingPositionsForSubjects(model, opts) {
		if p.Type != typ || p.Target != gate {
			continue
		}
		escs, err := Escalations(model, proposed, caveats, p.Tuples, []Object{p.Attacker}, opts)
		if err != nil {
			return Escalation{}, false, err
		}
		if len(escs) > 0 {
			return escs[0], true, nil
		}
	}
	return Escalation{}, false, nil
}

// allowsWildcard reports whether a relation admits a wildcard subject.
func allowsWildcard(r *Relation) bool {
	return slices.ContainsFunc(r.Allowed, func(a Allowed) bool { return a.Wildcard })
}
