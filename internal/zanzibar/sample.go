package zanzibar

import (
	"encoding/json"
	"fmt"
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
	matches, _ := RunWithLimits(s, wm)
	return matches
}

// RunWithLimits is Run, and says where the run stopped short of weighing everything.
func RunWithLimits(s Sample, wm *WriteModel) ([]Match, Limits) {
	candidates := WriterSetParameters(s)
	if wm == nil {
		return candidates, Limits{}
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
	escalations, limits := escalationFindings(s, wm)
	return append(out, escalations...), limits
}

// Limits says where an analysis of a sample stopped short of weighing everything, so
// that a store too large to weigh whole does not read as one with nothing more in it.
// What was found holds either way.
type Limits struct {
	// SearchesStopped counts the searches for witnesses that reached maxSearchStates.
	SearchesStopped int

	// SubjectsLeftOut counts the subjects, one for each object, that were not weighed
	// for what they can raise once maxSubjectWork was spent.
	SubjectsLeftOut int

	// HoldingsLeftOut counts the objects not asked who holds what on them once
	// maxHoldingChecks were spent.
	HoldingsLeftOut int

	// SupposedLeftOut counts the states not weighed for an attacker the analysis
	// supposes once maxSupposedWork was spent.
	SupposedLeftOut int

	// StartsLeftOut counts the objects a witness can link to or start from that were
	// weighed through another of their shape.
	StartsLeftOut int

	// ProposalsLeftOut counts the safe gates whose company check did not finish once
	// the proposal pass spent its work budget. A gate still shown safe among them
	// was not held against the others, so it may be unsafe in their company.
	ProposalsLeftOut int
}

// Add sums two limits, for an analysis of several samples.
func (l *Limits) Add(other Limits) {
	l.SearchesStopped += other.SearchesStopped
	l.SubjectsLeftOut += other.SubjectsLeftOut
	l.HoldingsLeftOut += other.HoldingsLeftOut
	l.SupposedLeftOut += other.SupposedLeftOut
	l.StartsLeftOut += other.StartsLeftOut
	l.ProposalsLeftOut += other.ProposalsLeftOut
}

// Lines say the limits in words, none when nothing stopped short.
func (l Limits) Lines() []string {
	var lines []string
	if l.SearchesStopped > 0 {
		lines = append(lines, fmt.Sprintf("%d %s for a witness stopped at the limit of the states weighed: what was found holds, and there can be more",
			l.SearchesStopped, plural(l.SearchesStopped, "search", "searches")))
	}
	if l.SubjectsLeftOut > 0 {
		lines = append(lines, fmt.Sprintf("%d %s of what a subject can raise on an object went unasked, past the limit of the work",
			l.SubjectsLeftOut, plural(l.SubjectsLeftOut, "question", "questions")))
	}
	if l.HoldingsLeftOut > 0 {
		lines = append(lines, fmt.Sprintf("%d %s not asked who holds what, past the limit of the work",
			l.HoldingsLeftOut, plural(l.HoldingsLeftOut, "object", "objects")))
	}
	if l.SupposedLeftOut > 0 {
		lines = append(lines, fmt.Sprintf("%d %s of what an account with nothing can raise went unasked, past the limit of the work",
			l.SupposedLeftOut, plural(l.SupposedLeftOut, "question", "questions")))
	}
	if l.StartsLeftOut > 0 {
		lines = append(lines, fmt.Sprintf("%d %s a witness can link to or start from weighed through another of the same shape: a witness that needs that very object is not found",
			l.StartsLeftOut, plural(l.StartsLeftOut, "object", "objects")))
	}
	if l.ProposalsLeftOut > 0 {
		lines = append(lines, fmt.Sprintf("%d safe %s not held against the others, past the limit of the work the proposals may take: run with -quiet for the findings alone, or supply a write model",
			l.ProposalsLeftOut, plural(l.ProposalsLeftOut, "gate", "gates")))
	}
	return lines
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
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

	// Raise is set on an escalation, a finding the closure reaches through a write
	// rule, and nil on any other match.
	Raise *Raise
}

// Raise is what an escalation lifts and the rule behind it, which a report reads to say
// what one rule opens, a rule being what somebody changes.
type Raise struct {
	// Cause says who the write model lets make the decisive write, and through
	// what.
	Cause string

	// Kind names the decisive write in a few words.
	Kind string

	// Type and Permission are what rises, and Before and After how far.
	Type, Permission string
	Before, After    Level

	// Proof is the raise as the product itself can be asked to show it, on the
	// object and from the state the witness was found on. It is nil when petard
	// cannot write one, and NoProof then says why.
	Proof   *Proof
	NoProof string

	// Witness is the shortest attack path, the writes in order, resolved for a
	// report: what each writes, who the write model lets make it and through
	// what, and where the relation it writes is declared. The one marked
	// Decisive is the write the raise is classified by. petard why renders it,
	// and -v prints the same writes as its path lines. It is empty on a match
	// the closure reached without a witness.
	Witness []WitnessStep
}

// WitnessStep is one write of an escalation's witness, resolved for a report.
// The writes in order are the attack path, and the one marked Decisive is the
// write after which the permission rose, the one the finding is classified by.
type WitnessStep struct {
	// Verb is write, delete or create.
	Verb string

	// Tuple is the relationship written or deleted, or the object a creation
	// brings into being.
	Tuple string

	// Who is who the write model lets make the write, empty when no rule gates
	// it; Via is the endpoint it goes through, empty when the write model names
	// none.
	Who string
	Via string

	// At is where the relation the write targets is declared in the schema, the
	// zero Position for a creation, which writes no relation of its own.
	At Position

	// Decisive marks the write the permission rose after.
	Decisive bool
}

// Detail is one labelled line of a match. The text says where to look in the
// words of the pattern; Position is the same place for a reader that is not a
// person.
type Detail struct {
	Label string
	Text  string
	Position

	// Verbose marks a line as evidence, the detail behind the finding that a
	// report prints only when asked for it, so the first screen stays the claim
	// and the proof sits behind -v.
	Verbose bool
}
