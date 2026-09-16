package taxonomy

import (
	"github.com/saluc28/petard/internal/opaengine"
	"github.com/saluc28/petard/internal/writemodel"
)

// AttrSelfWrite is the id of the OPA instance of the self write category.
const AttrSelfWrite = "PTD-OPA-001"

// SelfWrite finds the reads where the subject of a decision picks the document
// that decides about it, and can write that document.
//
// The three signals of the pattern, in order:
//
//  1. the read happens in a rule that contributes to a decision, which holds by
//     construction because the walk starts at the declared entrypoints;
//  2. the index of the read derives from input, and is the subject;
//  3. the field, the whole path and not just the collection, is declared
//     writable by that same subject.
//
// The side of the decision the read sits on is not among them. The subject
// picks the value they write, so a field that denies them is a field they can
// clear: a suspension the subject writes is a suspension the subject lifts.
// Where a value sits decides what its absence does, not what the one who
// controls it can do.
//
// The third is the one no policy can answer, and it is what separates a
// finding from a candidate. It is also what separates the two reads of the
// fixture that look identical to the first two signals: the department of a
// profile and the roles of the same record are both picked by the subject, and
// only the write model says that one is written by the user and the other by an
// administrator.
func SelfWrite(reads *opaengine.ReadSet, shape opaengine.Shape, model *writemodel.Model) ([]Finding, error) {
	var findings []Finding
	byPath := make(map[string]int, len(reads.Reads))

	for _, read := range reads.Reads {
		if !signalsHold(read, shape) {
			continue
		}

		path, err := writemodel.ParsePath(read.Path)
		if err != nil {
			return nil, err
		}

		writer, entry, at, writes := subjectWrites(read, path, model)
		if model != nil && !writes {
			// The model had its say: either it does not cover this path, and a
			// closed world means nobody writes it, or it covers it and names
			// somebody else. Both are silence, and the counter case of the
			// fixture is the second one.
			continue
		}

		// Every read is checked on its own before being grouped. Two reads of
		// the same path can index it differently, one by the subject and one
		// by something else, and only the first is a self write.
		site := ReadSite{Ref: read.Ref, Rule: read.Rule, File: read.File, Line: read.Line}
		if at, grouped := byPath[read.Path]; grouped {
			findings[at].Reads = append(findings[at].Reads, site)
			continue
		}

		finding := Finding{
			PatternID:  AttrSelfWrite,
			Verdict:    VerdictCandidate,
			Summary:    read.Path,
			Path:       read.Path,
			Reads:      []ReadSite{site},
			Subject:    shape.Subject,
			Confidence: shape.Confidence.String(),
		}
		if writes {
			finding.Verdict = VerdictFinding
			finding.ViaWritePath = entry.RawPath
			finding.Via = writer.Via
			finding.Note = writer.Note
			finding.SubjectPosition = at
		}

		byPath[read.Path] = len(findings)
		findings = append(findings, finding)
	}
	return findings, nil
}

// signalsHold checks the signals that the policy alone can answer.
func signalsHold(read opaengine.Read, shape opaengine.Shape) bool {
	if read.Provenance != opaengine.ProvenanceInput {
		return false
	}
	return shape.IndexedBySubject(read)
}

// subjectWrites reports whether the model says the subject of the decision can
// write this path.
//
// The link is the capture. A model entry writes data.users.{owner}.profile.
// department and names {owner} among the writers, which says "whoever this
// segment identifies writes this field". If the read has the subject standing
// at that same segment, then the one who writes is the one being decided about.
// It also reports where in the path the subject stands, because that is what
// turns the path into one person's document later on.
func subjectWrites(read opaengine.Read, path writemodel.Path, model *writemodel.Model) (writemodel.Writer, writemodel.Entry, int, bool) {
	if model == nil {
		return writemodel.Writer{}, writemodel.Entry{}, 0, false
	}

	for _, entry := range model.Covering(path) {
		for _, writer := range entry.WritableBy {
			name, isCapture := writer.IsCapture()
			if !isCapture {
				// A role, a system, a concrete principal: somebody who is not
				// the subject. An administrator who can elevate anybody is the
				// expected behaviour, not a defect.
				continue
			}
			position, found := entry.Path.CapturePosition(name)
			if !found {
				continue
			}
			if subjectStandsAt(read, position) {
				return writer, entry, position, true
			}
		}
	}
	return writemodel.Writer{}, writemodel.Entry{}, 0, false
}

// subjectStandsAt reports whether the subject of the request is the index at a
// given position of the read.
func subjectStandsAt(read opaengine.Read, position int) bool {
	for _, index := range read.Indexes {
		if index.Position == position {
			return index.Term != ""
		}
	}
	return false
}

// Coverage is how much of what the decisions read the write model speaks about.
//
// The design asks for this number on every run, and the reason is worth
// repeating: in a closed world an undeclared path is an assumed safe path, so
// without the number a clean run and an empty model look exactly the same.
type Coverage struct {
	Read      []string
	Covered   []string
	Uncovered []string
}

// Percent is the share of read paths the model covers, rounded down.
func (c Coverage) Percent() int {
	if len(c.Read) == 0 {
		return 0
	}
	return len(c.Covered) * 100 / len(c.Read)
}

// CoverageOf measures the write model against what the decisions read.
func CoverageOf(reads *opaengine.ReadSet, model *writemodel.Model) (Coverage, error) {
	coverage := Coverage{Read: reads.Paths()}
	for _, read := range coverage.Read {
		path, err := writemodel.ParsePath(read)
		if err != nil {
			return Coverage{}, err
		}
		if model != nil && model.Covers(path) {
			coverage.Covered = append(coverage.Covered, read)
			continue
		}
		coverage.Uncovered = append(coverage.Uncovered, read)
	}
	return coverage, nil
}
