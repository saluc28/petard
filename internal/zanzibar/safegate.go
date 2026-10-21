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
	if err := checkTogether(model, wm, caveats, proposals, opts); err != nil {
		return nil, err
	}
	return proposals, nil
}

// checkTogether holds the proposals against one another, since two writes a
// coalition can make together can raise what neither raises alone (section 6 of
// the definitions). It adds every gate still proposed as safe to the write model
// at once and runs the closure from the starting positions. A gate whose own
// write is then the decisive write of a raise is demoted from safe to unsafe: it
// was safe only while the other relations stayed unwritable. An escalation whose
// decisive write is a rule the author declared is a finding the run already
// reports, not a fault of a proposal, so it demotes nothing.
func checkTogether(model *Model, wm *WriteModel, caveats CaveatEvaluator, proposals []GateProposal, opts Options) error {
	positions := startingPositionsForSubjects(model, opts)
	for {
		combined := withProposals(model, wm, proposals)
		demoted := false
		for i := range proposals {
			for _, gate := range slices.Clone(proposals[i].Safe) {
				esc, ok, err := combinedEscalates(model, combined, caveats, positions, proposals[i].Type, proposals[i].Relation, gate, opts)
				if err != nil {
					return err
				}
				if ok {
					demoteGate(proposals, proposals[i].Type, proposals[i].Relation, gate, esc)
					demoted = true
					break
				}
			}
			if demoted {
				break
			}
		}
		// A demotion removes one rule from the combination, which can make a gate
		// unsafe only in its company safe again, so each is rebuilt and rechecked
		// from the start until the set holds together. Demoting the gate under
		// test, in proposal order, keeps which one is dropped the same on every run.
		if !demoted {
			return nil
		}
	}
}

// combinedEscalates runs the closure over the model that holds every proposal at
// once, from the positions in which the attacker holds gate on typ, and reports
// whether writing relation under gate is then the decisive write of a raise. That
// is the sign the gate is safe only while the other relations stay unwritable:
// the relation has no rule of its own, so the only rule for it in the combined
// model is the proposed one, and an escalation some declared rule is decisive for
// is a finding the run already reports, not counted here.
func combinedEscalates(model *Model, combined *WriteModel, caveats CaveatEvaluator, positions []StartingPosition, typ, relation, gate string, opts Options) (Escalation, bool, error) {
	for _, pos := range positions {
		if pos.Type != typ || pos.Target != gate {
			continue
		}
		escs, err := Escalations(model, combined, caveats, pos.Tuples, []Object{pos.Attacker}, opts)
		if err != nil {
			return Escalation{}, false, err
		}
		for _, esc := range escs {
			dw, ok := esc.Decisive()
			if !ok || dw.Rule == nil || dw.Rule.Gate.Holds != gate {
				continue
			}
			if dw.Relationship.Resource.Type == typ && dw.Relationship.Relation == relation {
				return esc, true, nil
			}
		}
	}
	return Escalation{}, false, nil
}

// withProposals is the write model with a rule added for every gate the
// proposals still call safe, each a holder of that permission writing the
// relation, so the closure weighs them together.
func withProposals(model *Model, wm *WriteModel, proposals []GateProposal) *WriteModel {
	writes := slices.Clone(wm.Writes)
	for _, p := range proposals {
		t := model.Type(p.Type)
		if t == nil {
			continue
		}
		r := t.Relation(p.Relation)
		for _, gate := range p.Safe {
			writes = append(writes, &WriteRule{
				Resource:   p.Type,
				Relation:   p.Relation,
				Operations: []Operation{Create, Touch},
				Gate:       Gate{Holds: gate},
				Subject:    SubjectSpec{Any: true},
				Wildcard:   allowsWildcard(r),
			})
		}
	}
	return &WriteModel{SchemaVersion: wm.SchemaVersion, Kind: wm.Kind, Writes: writes, Creates: wm.Creates}
}

// demoteGate moves a gate from the safe set of its proposal to the unsafe one,
// with the witness of what it opened in combination.
func demoteGate(proposals []GateProposal, resource, relation, gate string, esc Escalation) {
	for i := range proposals {
		if proposals[i].Type != resource || proposals[i].Relation != relation {
			continue
		}
		at := slices.Index(proposals[i].Safe, gate)
		if at < 0 {
			return
		}
		proposals[i].Safe = slices.Delete(proposals[i].Safe, at, at+1)
		proposals[i].Unsafe = append(proposals[i].Unsafe, UnsafeGate{Permission: gate, Escalation: esc})
		return
	}
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
