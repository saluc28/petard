package zanzibar

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
)

// WriterSetParameterID is the pattern of a caveat parameter meant to come with
// the check, which whoever writes the relationship can set instead.
const WriterSetParameterID = "PTD-ZAN-001"

// maxWitnessRewrites bounds how many rewritten relationships are tried while
// looking for a check that shows a parameter's effect. A match is reported
// either way; the bound only decides how hard it looks for the proof.
const maxWitnessRewrites = 200

// WriterSetParameters finds the parameters of caveats that checks are meant to
// supply and that whoever writes the relationship can set instead.
//
// A relationship carries its caveat with a context, and that context is
// written over the one a check supplies: SpiceDB merges them that way
// (internal/caveats/run.go:222-230 at v1.56.2), and so does OpenFGA. A write may
// set any parameter of the caveat (internal/relationships/validation.go:248-262
// at v1.56.2). So a parameter meant to come with the check, the address of the
// caller or the time of the request, is the writer's to fix: written once, the
// value the check brings stops counting, for that relationship and every check
// that goes through it.
//
// Which parameters are meant for the check is in no schema. The sample says it:
// a check that supplies the parameter, or relationships of the relation that
// leave it out while none writes it. A parameter the sample says nothing about
// is left alone.
//
// Who writes the relationship is in no schema either, so every match is a
// candidate. It becomes a finding once a write model can say who writes the
// relation and whether they choose its context.
func WriterSetParameters(s Sample) []Match {
	var out []Match
	for _, t := range s.Model.Types {
		for _, r := range t.Relations {
			for _, name := range caveatsOf(r) {
				c := s.Model.Caveat(name)
				if c == nil {
					continue
				}
				for _, p := range c.Parameters {
					if m, ok := writerSetParameter(s, t, r, c, p.Name); ok {
						out = append(out, m)
					}
				}
			}
		}
	}
	return out
}

// caveatsOf is every caveat a relation lets its relationships carry, in the
// order the relation names them.
func caveatsOf(r *Relation) []string {
	var out []string
	for _, a := range r.Allowed {
		if a.Caveat != "" && !slices.Contains(out, a.Caveat) {
			out = append(out, a.Caveat)
		}
	}
	return out
}

func writerSetParameter(s Sample, t *Type, r *Relation, c *Caveat, p string) (Match, bool) {
	var supplied []Assertion
	for _, a := range s.Assertions {
		if _, ok := a.Context[p]; ok {
			supplied = append(supplied, a)
		}
	}
	var left []int
	written := 0
	for i, rel := range s.Relationships {
		if rel.Resource.Type != t.Name || rel.Relation != r.Name || rel.Caveat == nil || rel.Caveat.Name != c.Name {
			continue
		}
		if _, ok := rel.Caveat.Context[p]; ok {
			written++
			continue
		}
		left = append(left, i)
	}
	if len(supplied) == 0 && (len(left) == 0 || written > 0) {
		return Match{}, false
	}

	m := Match{
		PatternID: WriterSetParameterID,
		Verdict:   Candidate,
		Subject:   fmt.Sprintf("%s#%s, %s of caveat %s", t.Name, r.Name, p, c.Name),
	}
	m.Details = append(m.Details, Detail{
		Label:    "written on",
		Text:     fmt.Sprintf("%s#%s at %s, and whoever writes it chooses the context of %s", t.Name, r.Name, r.Position, c.Name),
		Position: r.Position,
	})
	if len(supplied) > 0 {
		m.Details = append(m.Details, Detail{
			Label:    "supplied by",
			Text:     fmt.Sprintf("%s of the file, the first at %s", count(len(supplied), "check"), supplied[0].Position),
			Position: supplied[0].Position,
		})
	} else {
		m.Details = append(m.Details, Detail{
			Label:    "left by",
			Text:     fmt.Sprintf("%s of the relation, which leave it to the check, the first at %s", count(len(left), "relationship"), s.Relationships[left[0]].Position),
			Position: s.Relationships[left[0]].Position,
		})
	}
	if written > 0 {
		m.Details = append(m.Details, Detail{
			Label: "written by",
			Text:  count(written, "relationship") + " of the relation already",
		})
	}

	if w := findParameterWitness(s, left, p, supplied); w != nil {
		m.Details = append(m.Details, Detail{
			Label: "shown by",
			Text: fmt.Sprintf("%s, at %s, goes from %s to %s once %s carries %s",
				w.check, w.check.Position, w.before, w.after, w.relationship, encode(w.written)),
			Position: w.check.Position,
		})
	} else {
		m.Details = append(m.Details, Detail{
			Label: "shown by",
			Text:  "no check of the file, with the values its checks supply written on a relationship that leaves the parameter out",
		})
	}
	return m, true
}

// parameterWitness is a check whose answer rises once a relationship carries
// the parameter.
type parameterWitness struct {
	relationship  Relationship
	written       map[string]any
	check         Assertion
	before, after Level
}

// findParameterWitness writes the parameter, with each value the checks of
// the file supply for it, on each relationship that leaves it out, and looks
// for a check of the file whose answer rises. The checks that supply the
// parameter are asked first, since they are the ones it was meant for.
func findParameterWitness(s Sample, left []int, p string, supplied []Assertion) *parameterWitness {
	values := valuesOf(supplied, p)
	if len(values) == 0 || len(left) == 0 {
		return nil
	}
	checks := slices.Concat(supplied, slices.DeleteFunc(slices.Clone(s.Assertions), func(a Assertion) bool {
		_, ok := a.Context[p]
		return ok
	}))

	before := NewChecker(s.Model, s.Relationships, s.Caveats, s.Now)
	rewrites := 0
	for _, i := range left {
		for _, v := range values {
			if rewrites == maxWitnessRewrites {
				return nil
			}
			rewrites++

			rewritten := slices.Clone(s.Relationships)
			rel := rewritten[i]
			context := maps.Clone(rel.Caveat.Context)
			if context == nil {
				context = map[string]any{}
			}
			context[p] = v
			rel.Caveat = &CaveatUse{Name: rel.Caveat.Name, Context: context}
			rewritten[i] = rel
			after := NewChecker(s.Model, rewritten, s.Caveats, s.Now)

			for _, q := range checks {
				// A check the model cannot answer, one naming what the schema
				// does not declare, shows nothing either way.
				b, err := before.Check(q.Resource, q.Name, q.Subject, q.Context)
				if err != nil {
					continue
				}
				a, err := after.Check(q.Resource, q.Name, q.Subject, q.Context)
				if err != nil {
					continue
				}
				if a.Level > b.Level {
					return &parameterWitness{
						relationship: s.Relationships[i],
						written:      context,
						check:        q,
						before:       b.Level,
						after:        a.Level,
					}
				}
			}
		}
	}
	return nil
}

// valuesOf is every distinct value the checks supply for a parameter, in the
// order they first appear.
func valuesOf(checks []Assertion, p string) []any {
	var out []any
	seen := map[string]bool{}
	for _, a := range checks {
		v := a.Context[p]
		key := encode(v)
		if !seen[key] {
			seen[key] = true
			out = append(out, v)
		}
	}
	return out
}

// encode writes a value as JSON, which every value read from a context is.
func encode(v any) string {
	encoded, _ := json.Marshal(v)
	return string(encoded)
}

// count writes a number and what it counts, plural when it has to be.
func count(n int, thing string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", thing)
	}
	return fmt.Sprintf("%d %ss", n, thing)
}
