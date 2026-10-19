package zanzibar

import (
	"encoding/json"
	"slices"
	"time"
)

// Sample is a model with what a file of the product holds about it: the
// relationships written against it and the checks somebody asserts. The
// patterns read the model for what can happen, and the sample for evidence of
// what was meant: a value a check supplies, a value a relationship leaves out.
type Sample struct {
	Model         *Model
	Relationships []Relationship
	Assertions    []Assertion

	// Caveats evaluates the caveats of the model, and Now is the time
	// expirations are read at.
	Caveats CaveatEvaluator
	Now     time.Time
}

// Run applies every pattern of the engine to a sample, under a write model when
// one is given. With a write model, a pattern that rests on who writes a
// relation is a finding; without one, it reads the same shape off the sample as
// a candidate, so a match a write model would confirm is still surfaced.
//
// A finding and the candidate of the same relation and parameter are the same
// fact, so the candidate is dropped once the write model has made it a finding.
func Run(s Sample, wm *WriteModel) []Match {
	candidates := WriterSetParameters(s)
	if wm == nil {
		return candidates
	}
	findings := SelfAssertedExemptions(s.Model, wm, Options{})
	confirmed := make(map[string]bool, len(findings))
	for _, f := range findings {
		confirmed[f.Subject] = true
	}
	out := slices.Clone(findings)
	for _, c := range candidates {
		if !confirmed[c.Subject] {
			out = append(out, c)
		}
	}
	return out
}

// Assertion is a check somebody wrote down with the answer they expect, as a
// validation file asserts it.
type Assertion struct {
	Resource Object
	Name     string
	Subject  Subject

	// Context is what the check supplies for caveats, nil when it supplies
	// nothing. It is the evidence that a parameter is meant to come with the
	// check rather than with the relationship.
	Context map[string]any

	Level Level
	Position
}

// String writes the check the way SpiceDB writes an assertion,
// document:readme#view@user:alice, followed by with and the context when it
// supplies one.
func (a Assertion) String() string {
	s := a.Resource.String() + "#" + a.Name + "@" + a.Subject.String()
	if a.Context == nil {
		return s
	}
	// A context read from JSON encodes back to JSON.
	encoded, _ := json.Marshal(a.Context)
	return s + " with " + string(encoded)
}

// Verdict is how sure a result is.
type Verdict string

const (
	// Finding means every signal of the pattern held, including who can
	// make the write it rests on.
	Finding Verdict = "finding"

	// Candidate means the model and the sample hold and who can make the
	// write is neither declared nor proven: "this would be one if that holds".
	Candidate Verdict = "candidate"
)

// Match is one fact a pattern found, with the verdict on it.
type Match struct {
	PatternID string
	Verdict   Verdict

	// Subject names what the fact is about in a few words, the heading a
	// report prints it under.
	Subject string

	// Details are the lines a report prints under the heading, in order: what
	// the pattern read, where, and what shows it.
	Details []Detail
}

// Detail is one labelled line of a match. The text says where to look in the
// words of the pattern; Position is the same place for a reader that is not a
// person.
type Detail struct {
	Label string
	Text  string
	Position
}
