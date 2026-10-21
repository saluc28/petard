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
// each labelled with the registry id of its decisive-write category. The
// coalition is an attacker of every type the schema admits as a subject, run
// from both starting states the definitions name (section 3): the relationships
// of the validation file, and the starting positions generated from the schema.
// A raise reachable from more than one of those is reported once per category,
// object type and permission, the fact being that the schema lets it happen at
// all rather than the particular object it was shown on.
//
// It needs a write model, since every category rests on a write the model
// allows; with none it returns nothing, and SelfAssertedExemptions still reads
// its candidate off the sample. Run is the one caller.
func escalationFindings(s Sample, wm *WriteModel) []Match {
	if s.Model == nil || wm == nil {
		return nil
	}
	opts := Options{Now: s.Now}

	seen := map[string]bool{}
	var out []Match
	add := func(start []Relationship, attacker Object) {
		classified, err := Classify(s.Model, wm, s.Caveats, start, []Object{attacker}, opts)
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
			key := id + "|" + c.Object.Type + "|" + c.Permission
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, escalationMatch(id, c))
		}
	}

	for _, typ := range subjectTypes(s.Model) {
		attacker := Object{Type: typ, ID: "attacker"}
		add(s.Relationships, attacker)
		for _, p := range StartingPositions(s.Model, attacker, opts) {
			add(p.Tuples, attacker)
		}
	}

	// The closure visits states in an order a map decides, so the findings come
	// out shuffled. A report prints the same bytes on every run, so they are
	// sorted by id and then by heading before they leave here.
	slices.SortFunc(out, func(a, b Match) int {
		if c := cmp.Compare(a.PatternID, b.PatternID); c != 0 {
			return c
		}
		return cmp.Compare(a.Subject, b.Subject)
	})
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
	if dw, ok := c.Decisive(); ok {
		m.Details = append(m.Details, Detail{Label: "written by", Text: decisiveText(dw)})
	}
	m.Details = append(m.Details, Detail{
		Label: "raises",
		Text:  fmt.Sprintf("%s on %s, from %s to %s", c.Permission, c.Object.Type, c.Before, c.After),
	})
	return m
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
