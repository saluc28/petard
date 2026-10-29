package zanzibar

import (
	"runtime"
	"slices"

	"golang.org/x/sync/errgroup"
)

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

	// Raises are the permissions writing the relation could raise, as type#name,
	// read off the schema's reachability. It tells apart a relation on a type
	// with no permission to gate on, where Safe and Unsafe are both empty: one
	// that raises nothing is safe to write, one that raises something escalates
	// with no local permission to gate it.
	Raises []string
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
	// Each gate check need only weigh the permissions a write to the relation
	// under it could reach; the rest cannot change and would read the same every
	// time. The reach that says which those are is read off the schema once here.
	return safeGates(model, wm, caveats, newReach(model, wm), opts)
}

// safeGates is SafeGates with the reach given rather than read from the model,
// so a test can run it both with the reach and with an empty one and confirm
// the scoping leaves every proposal unchanged.
func safeGates(model *Model, wm *WriteModel, caveats CaveatEvaluator, rc reach, opts Options) ([]GateProposal, error) {
	// The starting positions depend on the schema alone, not on the relation or
	// the gate under test, so they are generated once and indexed by the gate
	// they put the attacker on. Regenerating them inside the per-relation,
	// per-permission loop walked the whole schema again for every pair, which is
	// quadratic in the permissions of a type and dominates on a large one.
	positions := startingPositionsForSubjects(model, opts)
	byGate := positionsByGate(positions)

	// The relations with no rule are weighed one per worker: each reads only the
	// shared model, write model, caveats and positions, none of which it changes,
	// so the work splits across the processors without a lock. The result of each
	// is placed back by its index, so the proposals come out in the same order,
	// the same bytes, however the workers interleave.
	type unruled struct {
		t *Type
		r *Relation
	}
	var jobs []unruled
	for _, t := range model.Types {
		for _, r := range t.Relations {
			if !hasWriteRule(wm, t.Name, r.Name) {
				jobs = append(jobs, unruled{t: t, r: r})
			}
		}
	}

	proposals := make([]GateProposal, len(jobs))
	g := new(errgroup.Group)
	g.SetLimit(runtime.GOMAXPROCS(0))
	for i, jb := range jobs {
		g.Go(func() error {
			proposal, err := relationGates(model, wm, caveats, jb.t, jb.r, byGate, rc, opts)
			if err != nil {
				return err
			}
			proposals[i] = proposal
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}

	if err := checkTogether(model, wm, caveats, proposals, byGate, rc, opts); err != nil {
		return nil, err
	}
	return proposals, nil
}

// relationGates weighs each permission of a type as a gate for writing one of
// its relations, and returns which are safe and which a coalition could
// escalate through. It reads only shared inputs it does not change, so one call
// is independent of the next and they can run on separate workers.
func relationGates(model *Model, wm *WriteModel, caveats CaveatEvaluator, t *Type, r *Relation, byGate map[gateKey][]StartingPosition, rc reach, opts Options) (GateProposal, error) {
	proposal := GateProposal{Type: t.Name, Relation: r.Name, Raises: raisesList(rc.index, t.Name, r.Name)}
	for _, p := range t.Permissions {
		esc, unsafe, err := gateEscalates(model, wm, caveats, t.Name, r, p.Name, byGate, rc, opts)
		if err != nil {
			return GateProposal{}, err
		}
		if unsafe {
			proposal.Unsafe = append(proposal.Unsafe, UnsafeGate{Permission: p.Name, Escalation: esc})
		} else {
			proposal.Safe = append(proposal.Safe, p.Name)
		}
	}
	return proposal, nil
}

// raisesList is the permissions writing a relation could raise, as sorted
// type#name strings, read off the reachability index. It is empty for a relation
// no permission reads, which is how a report tells a harmless relation on a
// permission-less type from one that escalates across types.
func raisesList(index map[relRef][]permRef, typ, relation string) []string {
	refs := index[relRef{typ: typ, name: relation}]
	out := make([]string, 0, len(refs))
	for _, pr := range refs {
		out = append(out, pr.typ+"#"+pr.name)
	}
	slices.Sort(out)
	return out
}

// gateKey is a starting position's type and the relation or permission the
// attacker holds, the two fields a gate check looks a position up by.
type gateKey struct{ typ, target string }

// positionsByGate indexes the starting positions by the gate they put the
// attacker on, so a gate check reads its positions in one lookup rather than
// filtering the whole set.
func positionsByGate(positions []StartingPosition) map[gateKey][]StartingPosition {
	byGate := map[gateKey][]StartingPosition{}
	for _, p := range positions {
		k := gateKey{typ: p.Type, target: p.Target}
		byGate[k] = append(byGate[k], p)
	}
	return byGate
}

// checkTogether holds the proposals against one another, since two writes a
// coalition can make together can raise what neither raises alone (section 6 of
// the definitions). It adds every gate still proposed as safe to the write model
// at once and runs the closure from the starting positions. A gate whose own
// write is then the decisive write of a raise is demoted from safe to unsafe: it
// was safe only while the other relations stayed unwritable. An escalation whose
// decisive write is a rule the author declared is a finding the run already
// reports, not a fault of a proposal, so it demotes nothing.
func checkTogether(model *Model, wm *WriteModel, caveats CaveatEvaluator, proposals []GateProposal, byGate map[gateKey][]StartingPosition, rc reach, opts Options) error {
	for {
		combined := withProposals(model, wm, proposals)
		scope := rc.scopeOf(model, combined)
		// The combined run from a starting position depends on the type and gate
		// the position puts the attacker on, not on which relation is weighed, so
		// it is run once per gate and reused across the relations of that type that
		// share it. On a type with many unruled relations this is the difference
		// between one run per relation and one per gate.
		gates := map[gateKey]map[string]Escalation{}
		demoted := false
		for i := range proposals {
			for _, gate := range proposals[i].Safe {
				k := gateKey{typ: proposals[i].Type, target: gate}
				byRel, ok := gates[k]
				if !ok {
					var err error
					byRel, err = combinedGate(model, combined, caveats, byGate[k], scope, k, opts)
					if err != nil {
						return err
					}
					gates[k] = byRel
				}
				if esc, found := byRel[proposals[i].Relation]; found {
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

// combinedGate runs the closure over the model that holds every proposal at once,
// from each position the gate puts the attacker on, and returns, keyed by the
// relation the decisive write of a raise under the gate targets, the witness of
// that raise. A proposal for such a relation is unsafe in company: the gate is
// safe only while the other relations stay unwritable, since the relation has no
// rule of its own and the only rule for it in the combined model is the proposed
// one. An escalation some declared rule is decisive for is a finding the run
// already reports, not counted here. The decisive write is read past a trailing
// creation (decisiveWrite), so a gate that links a created object into a
// pre-existing one is not called safe because a setup write of the creation
// happened to end the witness. The run does not depend on which relation is
// asked, only on the gate's type and name, so one run serves every relation of
// that type that proposes the gate.
func combinedGate(model *Model, combined *WriteModel, caveats CaveatEvaluator, positions []StartingPosition, scope map[permRef]bool, k gateKey, opts Options) (map[string]Escalation, error) {
	byRel := map[string]Escalation{}
	for _, pos := range positions {
		escs, err := escalationsScoped(model, combined, caveats, pos.Tuples, []Object{pos.Attacker}, scope, opts)
		if err != nil {
			return nil, err
		}
		for _, esc := range escs {
			dw, ok := esc.decisiveWrite()
			if !ok || dw.Rule == nil || dw.Rule.Gate.Holds != k.target {
				continue
			}
			if dw.Relationship.Resource.Type != k.typ {
				continue
			}
			if _, seen := byRel[dw.Relationship.Relation]; !seen {
				byRel[dw.Relationship.Relation] = esc
			}
		}
	}
	return byRel, nil
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
func gateEscalates(model *Model, wm *WriteModel, caveats CaveatEvaluator, typ string, r *Relation, gate string, byGate map[gateKey][]StartingPosition, rc reach, opts Options) (Escalation, bool, error) {
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
	scope := rc.scopeOf(model, proposed)

	for _, p := range byGate[gateKey{typ: typ, target: gate}] {
		escs, err := escalationsScoped(model, proposed, caveats, p.Tuples, []Object{p.Attacker}, scope, opts)
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
