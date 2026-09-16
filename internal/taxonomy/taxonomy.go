// Package taxonomy applies the curated patterns of abuse to what the engine
// found.
//
// The patterns are data, in taxonomy-registry, and this package reads them
// rather than restating them: an id, a title, what a match emits. What stays in
// Go is the computation of the signals, because a signal is a walk over the
// model and no data format is going to express that better than code. The line
// is worth keeping in mind while reading: if a rule about the world ends up
// here as a literal, it belongs in the registry instead.
//
// It reads opaengine for now, which makes it engine specific in a way the
// design does not want. When a second engine arrives the shared shape of a read
// moves into a neutral package and this import goes away; nothing here depends
// on Rego itself, only on the shape of what came out of it.
package taxonomy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	yaml "go.yaml.in/yaml/v3"
)

// SchemaVersion is the registry format this package reads.
const SchemaVersion = 1

// StatusVerified is the status a pattern reaches when its declared false
// positives have been settled as well as found, which is what MeasurementCase
// and MeasurementOutOfBand are for.
const StatusVerified = "verified"

// How a declared false positive is settled.
const (
	// MeasurementCase means a policy can be written that realizes the
	// condition, so the registry carries one and the engine is run over it.
	MeasurementCase = "case"

	// MeasurementOutOfBand means the discriminator is not in the policy and not
	// in the data. Intent lives there, and so does a guarantee something
	// upstream of the engine makes and nothing in the bundle enforces. There is
	// no case to write, and saying so is the measurement: it tells whoever
	// reads a finding that this one needs a person.
	MeasurementOutOfBand = "out-of-band"
)

// Pattern is what the engine needs of a registry entry.
//
// The file holds much more, and deliberately so: preconditions, mechanism,
// references. Those are for the person reading the pattern, and loading them
// here would only invite the code to start believing it understands them.
//
// The false positives are the exception, and only for what a pattern has to do
// to call itself verified. The condition stays prose, for whoever reads it, and
// the case that realizes it is a policy this package runs. A declared false
// positive nobody executes drifts away from the engine one commit at a time,
// and drifts in silence, because the engine that moved is also the only thing
// that could have noticed.
type Pattern struct {
	SchemaVersion int    `yaml:"schema_version"`
	ID            string `yaml:"id"`
	Name          string `yaml:"name"`
	Title         string `yaml:"title"`
	Engine        string `yaml:"engine"`
	Status        string `yaml:"status"`

	Category struct {
		ID    string `yaml:"id"`
		Title string `yaml:"title"`
	} `yaml:"category"`

	Detection struct {
		RequiresWriteModel bool `yaml:"requires_write_model"`
	} `yaml:"detection"`

	Graph struct {
		Emits string `yaml:"emits"`
		Edge  string `yaml:"edge"`
	} `yaml:"graph"`

	FalsePositives []FalsePositive `yaml:"false_positives"`
}

// FalsePositive is one condition under which the pattern fires with no abuse
// behind it, and how that condition is settled.
type FalsePositive struct {
	// Condition is when the signal fires for nothing, and Discriminator what it
	// would take to tell the two apart. Both are for the reader.
	Condition     string `yaml:"condition"`
	Discriminator string `yaml:"discriminator"`

	// Measurement is MeasurementCase or MeasurementOutOfBand, and is empty on a
	// pattern that has not been through this yet.
	Measurement string `yaml:"measurement"`

	// Case is the condition made executable, and is present exactly when
	// Measurement is MeasurementCase.
	Case *FalsePositiveCase `yaml:"case"`
}

// FalsePositiveCase is one condition written as a policy, with what the engine
// makes of it.
type FalsePositiveCase struct {
	// Policy is a bundle of its own, holding the condition and nothing else,
	// marking its decision as an entrypoint the way the fixture marks its own.
	//
	// It is small on purpose. The fixture is a world, with a write model and a
	// story that has to stay coherent; this is one question asked in isolation,
	// and the two would spoil each other.
	Policy string `yaml:"policy"`

	// Reports is what the engine does with that policy: true when the pattern
	// still fires on it, which for a declared false positive is the admission
	// written down and checked, false when the condition turned out to be told
	// apart after all.
	Reports bool `yaml:"reports"`

	// Note says what the run showed, in the words of whoever wrote the case.
	Note string `yaml:"note"`
}

// LoadRegistry reads every pattern of one engine from the registry directory.
func LoadRegistry(dir string) ([]Pattern, error) {
	entries, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, fmt.Errorf("taxonomy: listing %s: %w", dir, err)
	}

	patterns := make([]Pattern, 0, len(entries))
	for _, file := range entries {
		content, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("taxonomy: reading %s: %w", file, err)
		}

		var pattern Pattern
		if err := yaml.Unmarshal(content, &pattern); err != nil {
			return nil, fmt.Errorf("taxonomy: parsing %s: %w", file, err)
		}
		if pattern.SchemaVersion != SchemaVersion {
			return nil, fmt.Errorf("taxonomy: %s is schema version %d, this reads %d", file, pattern.SchemaVersion, SchemaVersion)
		}
		if pattern.ID == "" {
			return nil, fmt.Errorf("taxonomy: %s has no id, and the id is what the findings are filed under", file)
		}
		if err := checkFalsePositives(pattern); err != nil {
			return nil, fmt.Errorf("taxonomy: %s: %w", file, err)
		}
		patterns = append(patterns, pattern)
	}
	return patterns, nil
}

// checkFalsePositives holds the registry to what a status claims about it.
//
// It is here rather than in a test because the registry is data the tool ships
// and reads at run time: a file that says verified while leaving a condition
// unsettled is a wrong answer to give a reader, not a broken build.
func checkFalsePositives(pattern Pattern) error {
	for _, fp := range pattern.FalsePositives {
		condition := strings.TrimSpace(fp.Condition)
		switch fp.Measurement {
		case MeasurementCase:
			if fp.Case == nil || fp.Case.Policy == "" {
				return fmt.Errorf("%q is measured by a case and carries none", condition)
			}
		case MeasurementOutOfBand:
			if fp.Case != nil {
				return fmt.Errorf("%q is out of band and carries a case anyway", condition)
			}
		case "":
			if fp.Case != nil {
				return fmt.Errorf("%q carries a case and does not say it is measured by one", condition)
			}
			if pattern.Status == StatusVerified {
				return fmt.Errorf("status is %s and %q says nothing about how it is settled", StatusVerified, condition)
			}
		default:
			return fmt.Errorf("%q is measured %q, which is neither %q nor %q", condition, fp.Measurement, MeasurementCase, MeasurementOutOfBand)
		}
	}
	return nil
}

// Find returns the pattern with the given id.
func Find(patterns []Pattern, id string) (Pattern, bool) {
	for _, pattern := range patterns {
		if strings.EqualFold(pattern.ID, id) {
			return pattern, true
		}
	}
	return Pattern{}, false
}

// Verdict is how sure a match is.
type Verdict string

const (
	// VerdictFinding means every signal of the pattern held, the write model
	// included.
	VerdictFinding Verdict = "finding"

	// VerdictCandidate means the policy side held but nothing said who can
	// write the data. It is not a weaker finding, it is a different claim:
	// "this would be one if somebody can write here".
	VerdictCandidate Verdict = "candidate"
)

// ReadSite is one place a path is read.
type ReadSite struct {
	// Ref is the read as it stands in that rule, which differs from one site
	// to the next: written out in the decision, indexed by a parameter inside
	// a function.
	Ref  string
	Rule string
	File string
	Line int
}

// Finding is one match of a pattern.
//
// One finding per fact, not per line. The fact of the self write pattern is
// that a field the subject can write decides about the subject; that the
// policy reads it in three places makes it no more true, and counting three
// findings would inflate every number a report is judged by. The places are
// kept, because that is where somebody has to go and look.
type Finding struct {
	PatternID string
	Verdict   Verdict

	// Summary is the fact in one line, written by the pattern that found it.
	//
	// It lives here rather than being composed from the fields below because
	// the fields do not say what the fact is: a decision and a host mean "this
	// decision trusts that party" to one pattern and "this decision goes quiet
	// when that party stops answering" to another. A single function guessing
	// between them from the shape of the data would be guessing at exactly the
	// thing each pattern exists to state.
	Summary string

	// Path is the normalized path the finding is about, for the patterns whose
	// fact is about a path.
	Path string

	// Decision, Source and Origin are the other shape a fact can have: this
	// decision depends on that party, which reached it through that builtin.
	// Source is empty when the policy computes the destination instead of
	// writing it, which is the worse case of the two and has to stay
	// distinguishable from a destination nobody could read.
	Decision string
	Source   string
	Origin   string

	// Reads are the places to go and look, in the order they were found:
	// usually where the path is read, and for a fact that is not about a path,
	// where the construct that produces it sits.
	Reads []ReadSite

	// UncoveredKeys are the documents of the collection where the path is
	// absent, and KeysChecked how many were tried. Together they are the third
	// shape of a fact: a check that applies to some of the data and not to the
	// rest.
	UncoveredKeys []string
	KeysChecked   int

	// Principal is the one the fact is about, when the fact is about somebody
	// rather than about a path: not the part of input that names them, which is
	// Subject, but the document in the data that is them. Target is who they
	// can become, for the one fact that is about two people.
	Principal string
	Target    string

	// SubjectPosition is the segment of Path where the subject's own document
	// sits, counted from the data root.
	//
	// It is what lets a later pattern turn a path everybody shares into one
	// person's document: data.users[_].profile.department at position 2 is
	// data.users.mallory.profile.department for mallory. The write model is
	// where the position comes from, since it is the model that says which
	// segment the writer is.
	SubjectPosition int

	// ReachTransitive and ReachDirect are how much a decision grants that
	// principal with the relation in place and with it cut, and Relation is
	// what was cut. It is the fourth shape of a fact, and the only one that is
	// a measurement rather than a structure.
	ReachTransitive int
	ReachDirect     int
	Relation        []string

	// EnforcingSide says how the side that applies the check was established.
	// The claim rests on it, and when it becomes a guess instead of a
	// declaration the confidence has to follow.
	EnforcingSide string

	// Subject is the part of input the shape recognizers took for the subject,
	// and Confidence the level they reached. It travels with the finding
	// because the whole claim rests on it: if input.user is not the subject,
	// this is not a self write.
	Subject    string
	Confidence string

	// ViaWritePath is the write model entry that turned a candidate into a
	// finding, and Via is how the write happens. A finding without the how is
	// not actionable.
	ViaWritePath string
	Via          string
	Note         string

	// AuthorizedBy is the decision that lets the principal make the write, and
	// Value is what the write puts in the field, for the split grant that rests
	// on one decision governing what another decision reads.
	AuthorizedBy string
	Value        string
}

// String renders a finding as one line, for a report.
func (f Finding) String() string {
	line := fmt.Sprintf("%s %s: %s", f.PatternID, f.Verdict, f.Summary)
	switch len(f.Reads) {
	case 0:
		// A fact with nowhere to look says so by not mentioning a place, rather
		// than by reporting none of them.
	case 1:
		line += ", 1 place to look"
	default:
		line += fmt.Sprintf(", %d places to look", len(f.Reads))
	}

	line += fmt.Sprintf(" (confidence %s)", f.Confidence)
	if f.Via != "" {
		line += ", written via " + f.Via
	}
	return line
}

// named is how a report calls the other end of a call the policy makes.
//
// A destination the request can steer is a worse case than a fixed one, since
// then whoever asks also chooses who the policy asks, so it reads as its own
// thing rather than as a host nobody managed to parse.
func named(source string) string {
	if source == "" {
		return "a destination the policy computes"
	}
	return source
}
