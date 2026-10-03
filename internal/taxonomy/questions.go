package taxonomy

import (
	"slices"
	"strconv"
	"strings"

	"github.com/saluc28/petard/internal/opaengine"
	"github.com/saluc28/petard/internal/writemodel"
)

// A Question is a path the policy reads to decide, that nobody has declared who
// can write. Answer it in a write model, naming who writes the path, and the
// candidate that rested on it becomes a finding or goes away.
//
// Only the patterns whose signal names exactly the path that settles it ask a
// question: the self write (PTD-OPA-001), where the subject stands in the read,
// and the global document (PTD-OPA-008), a document every request shares. A
// position in a hierarchy (PTD-OPA-003) is settled by the self write that reaches
// it, not by writing the relation, and the write allowed by another decision
// (PTD-OPA-006) needs a decision named behind the write, which is more than a
// path; neither asks a question of its own.
type Question struct {
	// Path is the data path to declare writable, as the decisions read it:
	// data.users[_].roles.
	Path string

	// Patterns are the ids that rest on the path, sorted.
	Patterns []string

	// Shared is set when the path is a document that decides for anybody rather
	// than the record of one principal, so the question is who writes it at all.
	Shared bool

	// LookedUp is set when the subject is found in the path by value, a member of
	// a list, so the write that settles it is the subject joining the list.
	LookedUp bool

	// Writable is the path in the write model's own notation, with the subject's
	// segment named, ready to drop into a model: data.users.{owner}.roles.
	Writable string

	// Writer is the principal to suggest for Writable: the subject's own capture
	// for a self write, or a role placeholder for a shared document.
	Writer string
}

// OpenQuestions derives the questions a run leaves open: the paths a write-path
// pattern reads that the write model does not cover.
//
// The self write questions come from the reads where the subject stands, not
// from the candidates, so a partial write model still shows what it leaves open:
// the world is closed, so a path a partial model does not cover produces no
// candidate, but it is still a question nobody has answered. The global document
// questions come from the candidates, since a document decides for anybody only
// once the data shows it does.
func OpenQuestions(a Analysis, found Findings) []Question {
	byPath := map[string]*Question{}
	var paths []string
	ensure := func(path string) (*Question, bool) {
		question, seen := byPath[path]
		if !seen {
			question = &Question{Path: path}
			byPath[path] = question
			paths = append(paths, path)
		}
		return question, seen
	}

	for _, read := range opaengine.SubjectIndexedReads(a.Shape, a.Reads) {
		a.askSelfWrite(read, false, ensure)
	}
	for _, read := range opaengine.SubjectMatchedReads(a.Shape, a.Reads) {
		a.askSelfWrite(read, true, ensure)
	}
	for _, finding := range found.GlobalSwitch {
		if finding.Verdict != VerdictCandidate || finding.Path == "" || a.covers(finding.Path) {
			continue
		}
		question, seen := ensure(finding.Path)
		if !seen {
			question.Shared = true
			question.Writable, question.Writer = sharedEntry(finding.Path)
		}
		addPattern(question, GlobalDocumentDecides)
	}

	slices.Sort(paths)
	questions := make([]Question, 0, len(paths))
	for _, path := range paths {
		question := byPath[path]
		slices.Sort(question.Patterns)
		questions = append(questions, *question)
	}
	return questions
}

// askSelfWrite records a self write question for a read where the subject stands,
// unless the model already covers where the subject writes.
//
// A question is settled once the model says who writes where the subject would.
// For a search by value that is either the collection the read names, whose
// declared writer is who adds members, or the element itself, declared when a
// member may add themselves; either answers the join. For an index the two are
// the same path.
func (a Analysis) askSelfWrite(read opaengine.Read, byValue bool, ensure func(string) (*Question, bool)) {
	places, err := subjectPlaces(read, a.Shape)
	if err != nil {
		return
	}
	for _, place := range places {
		if place.byValue != byValue || a.covers(read.Path) || a.coversPath(place.path) {
			continue
		}
		question, seen := ensure(read.Path)
		if !seen {
			question.LookedUp = byValue
			question.Writable, question.Writer = writableEntry(place)
		}
		addPattern(question, AttrSelfWrite)
		return
	}
}

func addPattern(question *Question, pattern string) {
	if !slices.Contains(question.Patterns, pattern) {
		question.Patterns = append(question.Patterns, pattern)
	}
}

// covers reports whether the write model names a writer for a path. Without a
// model nothing is covered, so every pattern-relevant read is an open question.
func (a Analysis) covers(path string) bool {
	parsed, err := writemodel.ParsePath(path)
	if err != nil {
		return false
	}
	return a.coversPath(parsed)
}

// coversPath is covers for a path already parsed, the form the self write places
// come in.
func (a Analysis) coversPath(path writemodel.Path) bool {
	return a.Model != nil && a.Model.Covers(path)
}

// writableEntry renders the path a self write question declares, with the
// subject's segment named, and the principal to suggest for it. For a search by
// value the subject is the element written, so the element capture is named and
// the writer is that element; otherwise the subject is the segment it indexes.
func writableEntry(place subjectPlace) (string, string) {
	segments := slices.Clone(place.path.Segments)
	writer := ""
	switch {
	case place.byValue:
		if i := lastCapture(segments); i >= 0 {
			segments[i].Name = "member"
			writer = "{member}"
		}
	case place.position >= 0 && place.position < len(segments) && segments[place.position].Kind == writemodel.SegmentCapture:
		segments[place.position].Name = "owner"
		writer = "{owner}"
	}
	nameRemaining(segments)
	return writemodel.Path{Segments: segments}.String(), writer
}

// sharedEntry renders a global document question. Nobody is named by the policy,
// so the writer is a placeholder for whoever writes the shared document.
func sharedEntry(path string) (string, string) {
	parsed, err := writemodel.ParsePath(path)
	if err != nil {
		return path, "role:CHANGEME"
	}
	segments := slices.Clone(parsed.Segments)
	nameRemaining(segments)
	return writemodel.Path{Segments: segments}.String(), "role:CHANGEME"
}

// lastCapture returns the index of the last unnamed capture, or -1.
func lastCapture(segments []writemodel.Segment) int {
	for i := len(segments) - 1; i >= 0; i-- {
		if segments[i].Kind == writemodel.SegmentCapture {
			return i
		}
	}
	return -1
}

// nameRemaining gives every still-unnamed capture a name, after the document it
// indexes, so the skeleton has no bare braces for a reader to decode.
func nameRemaining(segments []writemodel.Segment) {
	used := map[string]bool{}
	for _, segment := range segments {
		if segment.Kind == writemodel.SegmentCapture && segment.Name != "" {
			used[segment.Name] = true
		}
	}
	for i := range segments {
		if segments[i].Kind != writemodel.SegmentCapture || segments[i].Name != "" {
			continue
		}
		name := "key"
		if i > 0 && segments[i-1].Kind == writemodel.SegmentLiteral {
			name = singular(segments[i-1].Name)
		}
		for base, n := name, 2; used[name]; n++ {
			name = base + strconv.Itoa(n)
		}
		used[name] = true
		segments[i].Name = name
	}
}

// singular drops a trailing s, so the capture of users reads {user}.
func singular(name string) string {
	if len(name) > 1 && strings.HasSuffix(name, "s") {
		return strings.TrimSuffix(name, "s")
	}
	if name == "" {
		return "key"
	}
	return name
}

// Asks is the one line a report prints for a question: what to find out about
// the path.
func (q Question) Asks() string {
	switch {
	case q.Shared:
		return "who can write it?"
	case q.LookedUp:
		return "can the subject add themselves to it?"
	default:
		return "can the subject write their own?"
	}
}
