package zanzibar

import (
	"cmp"
	"fmt"
	"slices"
)

// patternID is the registry id of the pattern a decisive-write category belongs
// to. The self-asserted exemption is PTD-ZAN-001 and comes from
// SelfAssertedExemptions rather than the closure, so it has no entry here; a
// category with no id, should one be added without one, emits nothing.
func (c Category) patternID() string {
	switch c {
	case CategoryFailOpenOnAbsence:
		return "PTD-ZAN-002"
	case CategoryGlobalSwitch:
		return "PTD-ZAN-003"
	case CategoryTransitiveGrant:
		return "PTD-ZAN-004"
	case CategoryAssumableIdentity:
		return "PTD-ZAN-005"
	case CategoryDelegationNotNarrowed:
		return "PTD-ZAN-006"
	case CategorySplitGrant:
		return "PTD-ZAN-007"
	case CategoryAttrSelfWrite:
		return "PTD-ZAN-008"
	}
	return ""
}

// escalationFindings are the escalations a coalition can raise over a sample,
// each labelled with the registry id of its decisive-write category. It is
// classifiedEscalations turned into the matches a report prints, sorted so the
// same sample prints the same bytes on every run. Run is the one caller.
func escalationFindings(s Sample, wm *WriteModel) []Match {
	found := classifiedEscalations(s, wm)
	out := make([]Match, 0, len(found))
	for _, f := range found {
		out = append(out, escalationMatch(f.patternID, f.esc))
	}

	// The closure visits states in an order a map decides, so the escalations
	// come out shuffled. A report prints the same bytes on every run, so the
	// matches are sorted by id and then by heading before they leave here.
	slices.SortFunc(out, func(a, b Match) int {
		if c := cmp.Compare(a.PatternID, b.PatternID); c != 0 {
			return c
		}
		return cmp.Compare(a.Subject, b.Subject)
	})
	return out
}

// attackerEscalation is one escalation the coalition can raise, paired with the
// attacker whose witness was kept. The findings leave the attacker implicit, a
// heading naming only the object type and the permission; the graph needs it as
// the principal a PTD_CanEscalateTo starts from, so it is carried here and both
// are built from the one list.
type attackerEscalation struct {
	attacker  Object
	esc       ClassifiedEscalation
	patternID string
}

// key is the identity a finding and the graph both deduplicate on: the
// category, the object type and the permission. The object it was shown on is
// not part of it, the fact being that the schema lets the raise happen at all
// rather than the particular object it turned up on.
func (a attackerEscalation) key() string {
	return a.patternID + "|" + a.esc.Object.Type + "|" + a.esc.Permission
}

// classifiedEscalations are the escalations a coalition can raise over a
// sample, deduplicated by category, object type and permission. The coalition
// is an attacker of every type the schema admits as a subject, run from both
// starting states the definitions name (section 3): the relationships of the
// validation file, and the starting positions generated from the schema. A
// raise reachable from more than one of those is kept once, with the first
// witness and attacker that reached it, so two runs keep the same one.
//
// It needs a write model, since every category rests on a write the model
// allows; with none it returns nothing. The findings and the graph are both
// built from this, so a report and a graph of one sample cannot disagree about
// what the engine found.
func classifiedEscalations(s Sample, wm *WriteModel) []attackerEscalation {
	if s.Model == nil || wm == nil {
		return nil
	}
	opts := Options{Now: s.Now}

	// The reach says which permissions a write under the model could raise; it is
	// read off the model once here and scopes every classification, so a target
	// no write can reach is not weighed, the same saving SafeGates takes. A nil
	// scope, when the model cannot be scoped soundly, weighs every target.
	scope := newReach(s.Model, wm).scopeOf(s.Model, wm)

	seen := map[string]bool{}
	var out []attackerEscalation
	add := func(start []Relationship, attacker Object) {
		classified, err := classifyScoped(s.Model, wm, s.Caveats, start, []Object{attacker}, scope, opts)
		if err != nil {
			// A starting state the caveat environment cannot evaluate yields no
			// finding from that state; another state reaches the same raise.
			return
		}
		for _, c := range classified {
			id := c.Category.patternID()
			if id == "" {
				continue
			}
			ae := attackerEscalation{attacker: attacker, esc: c, patternID: id}
			key := ae.key()
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, ae)
		}
	}

	for _, typ := range subjectTypes(s.Model) {
		attacker := Object{Type: typ, ID: "attacker"}
		add(s.Relationships, attacker)
		for _, p := range StartingPositions(s.Model, attacker, opts) {
			add(p.Tuples, attacker)
		}
	}
	return out
}

// escalationMatch builds the finding for one classified escalation: the kind of
// the decisive write, who the write model lets make it, and the permission it
// raises.
func escalationMatch(id string, c ClassifiedEscalation) Match {
	m := Match{
		PatternID: id,
		Verdict:   Finding,
		Subject:   fmt.Sprintf("%s#%s, %s", c.Object.Type, c.Permission, categoryPhrase(c.Category)),
	}
	m.Details = append(m.Details, Detail{Label: "written by", Text: decisiveText(c.DecisiveWrite)})
	m.Details = append(m.Details, Detail{
		Label: "raises",
		Text:  fmt.Sprintf("%s on %s, from %s to %s", c.Permission, c.Object.Type, c.Before, c.After),
	})
	if c.DefeatsExpiry {
		m.Details = append(m.Details, Detail{
			Label: "also",
			Text:  "defeats a time bound: the relation carries an expiration the coalition sets or omits, so a grant meant to lapse does not (stale authority, unbounded delegation)",
		})
	}
	m.Details = append(m.Details, witnessDetails(c.Writes)...)
	return m
}

// witnessDetails are the evidence lines of a finding: the writes of the witness
// in order, each the tuple the coalition adds, removes or the object it creates,
// and who the write model lets make it. The summary names the decisive write
// alone; these show the whole path it ends, the setup a multi-write escalation
// needs, so -v answers "how" and the first screen does not carry it. They are
// marked verbose, since a path is read after the claim, not before it.
func witnessDetails(writes []WriteStep) []Detail {
	details := make([]Detail, 0, len(writes))
	for i, w := range writes {
		label := ""
		if i == 0 {
			label = "path"
		}
		details = append(details, Detail{Label: label, Text: stepText(w), Verbose: true})
	}
	return details
}

// stepText describes one write of a witness: the tuple it adds or removes, or
// the object it creates, and who the write model lets make it. A tuple a
// creation writes on its own new object rides on the creation's gate, named at
// the create step above it, so it carries no gate of its own.
func stepText(w WriteStep) string {
	var verb, what string
	var gate Gate
	var via string
	switch {
	case w.Delete:
		verb, what = "delete", w.Relationship.String()
		if w.Rule != nil {
			gate, via = w.Rule.Gate, w.Rule.Via
		}
	case w.Creation != nil:
		// Whoever may create the object makes both its birth and the tuples the
		// creation writes on it, so each carries the creation's gate. A birth
		// writes no tuple of its own, so it is named by the object it brings in.
		gate, via = w.Creation.Gate, w.Creation.Via
		if w.Relationship.Relation == "" {
			verb, what = "create", w.Created.String()
		} else {
			verb, what = "write", w.Relationship.String()
		}
	default:
		verb, what = "write", w.Relationship.String()
		if w.Rule != nil {
			gate, via = w.Rule.Gate, w.Rule.Via
		}
	}

	line := verb + " " + what
	if gate == (Gate{}) {
		return line
	}
	who := gatePhrase(gate)
	if via != "" {
		who += ", through " + via
	}
	return line + " (" + who + ")"
}

// categoryPhrase names the kind of a decisive write in a few words, for the
// heading a report prints the finding under.
func categoryPhrase(c Category) string {
	switch c {
	case CategoryFailOpenOnAbsence:
		return "a deny lifted by a delete"
	case CategoryGlobalSwitch:
		return "a grant to every subject at once"
	case CategoryTransitiveGrant:
		return "linked to an object the coalition controls"
	case CategoryAssumableIdentity:
		return "a userset the coalition can join"
	case CategoryDelegationNotNarrowed:
		return "a grant written for another the writer lacks"
	case CategorySplitGrant:
		return "written in behind a permission the coalition held"
	case CategoryAttrSelfWrite:
		return "written in behind a gate that needs no permission"
	}
	return string(c)
}

// decisiveText describes the decisive write: who the write model lets make it,
// what it writes or deletes, and where.
func decisiveText(dw WriteStep) string {
	verb := "write"
	if dw.Delete {
		verb = "delete"
	}
	who := "a coalition subject"
	via := ""
	if dw.Rule != nil {
		who = gatePhrase(dw.Rule.Gate)
		if dw.Rule.Via != "" {
			via = ", through " + dw.Rule.Via
		}
	}
	return fmt.Sprintf("%s may %s %s#%s%s", who, verb, dw.Relationship.Resource.Type, dw.Relationship.Relation, via)
}
