package taxonomy

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/saluc28/petard/internal/opaengine"
	"github.com/saluc28/petard/internal/writemodel"
)

// GlobalDocumentDecides is the id of the OPA instance of the global switch
// category.
const GlobalDocumentDecides = "PTD-OPA-008"

// stranger is the principal the pattern asks about: a name no document holds,
// in a namespace of the tool's own, so that whatever a decision gives them it
// gives to anybody who can send a request.
//
// It is the question Kubernetes builds an identity for. A caller nobody
// authenticated becomes system:anonymous in the group system:unauthenticated
// (staging/src/k8s.io/apiserver/pkg/authentication/request/anonymous/
// anonymous.go:44 at v1.37.0), and the authorizer answers for that identity
// like for anybody else.
const stranger = "petard:nobody"

// GlobalSwitch finds the documents every request shares that decide what
// somebody nobody named gets.
//
// The three signals of the pattern, in order:
//
//  1. a decision reads a document through a path with no dynamic segment: the
//     same document whatever the request, which is what the engine reports as
//     static provenance;
//  2. with that document left unknown, the decision still depends on it for a
//     principal no document names, the rest of the request left open;
//  3. the write model says who writes the document.
//
// The second is what makes it a switch rather than configuration. A setting
// read next to the requester's own record, the console an administrator may
// open, decides only for whoever has a record, and a principal nobody named
// gets nothing from it whatever it says; a setting that decides for them
// decides for anybody, since anybody who can send a request is somebody no
// document names. BloodHound draws the same shape for a group policy object,
// which applies its settings to everything in the container it is linked to
// (GPLink, packages/cue/bh/ad/ad.cue:1352 at v9.7.0).
//
// Without a recognized subject nobody can be named in a request, and the
// question falls back to any request at all, with the confidence of a shape
// that recognized nothing.
func GlobalSwitch(ctx context.Context, a Analysis) ([]Finding, error) {
	if a.Data == nil {
		return nil, fmt.Errorf("%w: %s", ErrNeedsData, GlobalDocumentDecides)
	}

	var request map[string]any
	fields, named := subjectFieldsOf(a.Shape)
	if named {
		request = requestNaming(fields, stranger)
	}
	unknowns := unknownsBesides(a.Shape, a.Reads.InputPaths)

	var findings []Finding
	for _, start := range sharedDocuments(a.Reads) {
		depends, err := opaengine.DependsOn(ctx, a.Bundle, a.Data, opaengine.Request{
			Decision: start.decision,
			Unknowns: unknowns,
			Input:    request,
		}, start.path)
		if err != nil {
			return nil, err
		}
		if !depends {
			continue
		}

		entry, writers := writersOf(a.Model, start.path)
		if a.Model != nil && len(writers) == 0 {
			// The world is closed: a document the model does not cover is one
			// nobody writes, and a switch nobody can reach is not one.
			continue
		}

		today := ""
		if len(unknowns) > 0 {
			// With nothing left open the request would be the whole of input,
			// and the answer would stop being about the stranger.
			granted, err := reachOf(ctx, a.Bundle, a.Data, start.decision, request, unknowns, a.Limits)
			if err != nil {
				return nil, err
			}
			today = describeToday(granted)
		}
		findings = append(findings, globalFinding(a, start, named, today, entry, writers))
	}
	return sortedFindings(findings), nil
}

// sharedDocument is one place the pattern can start: a decision and a document
// every request shares, with every line that reads it for that decision.
type sharedDocument struct {
	decision string
	path     string
	sites    []ReadSite
}

// sharedDocuments collects the static reads, one per decision and path.
//
// Both sides of a decision count. A document read to deny is one its writer can
// clear for everybody at once, which is the reason the registry gives for not
// letting the side of a controlled value decide anything.
func sharedDocuments(reads *opaengine.ReadSet) []sharedDocument {
	byKey := map[string]int{}
	var starts []sharedDocument
	for _, read := range reads.Reads {
		if read.Provenance != opaengine.ProvenanceStatic {
			continue
		}
		site := ReadSite{Ref: read.Ref, Rule: read.Rule, File: read.File, Line: read.Line}
		for _, decision := range read.Decisions {
			key := decision.Name + "\x00" + read.Path
			if at, seen := byKey[key]; seen {
				starts[at].sites = append(starts[at].sites, site)
				continue
			}
			byKey[key] = len(starts)
			starts = append(starts, sharedDocument{decision: decision.Name, path: read.Path, sites: []ReadSite{site}})
		}
	}
	return starts
}

// writersOf returns who the model says writes a path, and the first entry that
// says so, which is the one a finding quotes.
func writersOf(model *writemodel.Model, path string) (writemodel.Entry, []writemodel.Writer) {
	if model == nil {
		return writemodel.Entry{}, nil
	}
	parsed, err := writemodel.ParsePath(path)
	if err != nil {
		return writemodel.Entry{}, nil
	}

	covering := model.Covering(parsed)
	if len(covering) == 0 {
		return writemodel.Entry{}, nil
	}
	var writers []writemodel.Writer
	for _, entry := range covering {
		writers = append(writers, entry.WritableBy...)
	}
	return covering[0], writers
}

// describeToday says what the decision gives the stranger as the data stands.
func describeToday(granted reach) string {
	switch {
	case granted.always:
		return "today it grants them whatever they ask"
	case granted.nothing():
		return "today it grants them nothing"
	default:
		return fmt.Sprintf("today it grants them %d ways", granted.ways)
	}
}

// globalFinding says what was measured: the document, the decision it switches,
// for whom, what that decision gives them today, and who holds the switch.
func globalFinding(a Analysis, start sharedDocument, named bool, today string, entry writemodel.Entry, writers []writemodel.Writer) Finding {
	whom := "for a principal no document names"
	if !named {
		whom = "for any request, since nothing in it was recognized as who sends it"
	}
	parts := []string{fmt.Sprintf("%s decides %s %s", start.path, start.decision, whom)}
	if today != "" {
		parts = append(parts, today)
	}

	finding := Finding{
		PatternID:  GlobalDocumentDecides,
		Verdict:    VerdictCandidate,
		Decision:   start.decision,
		Path:       start.path,
		Reads:      slices.Clone(start.sites),
		Subject:    a.Shape.Subject,
		Confidence: a.Shape.Confidence.String(),
	}
	if len(writers) > 0 {
		var names []string
		for _, writer := range writers {
			if !slices.Contains(names, writer.Principal) {
				names = append(names, writer.Principal)
			}
		}
		parts = append(parts, "and "+strings.Join(names, " and ")+" writes it")
		finding.Verdict = VerdictFinding
		finding.ViaWritePath = entry.RawPath
		finding.Via = writers[0].Via
		finding.Note = writers[0].Note
	}
	finding.Summary = strings.Join(parts, ", ")
	return finding
}
