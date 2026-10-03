package taxonomy

import (
	"slices"

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
	add := func(path, pattern string, shared, lookedUp bool) {
		question, seen := byPath[path]
		if !seen {
			question = &Question{Path: path}
			byPath[path] = question
			paths = append(paths, path)
		}
		question.Shared = question.Shared || shared
		question.LookedUp = question.LookedUp || lookedUp
		if !slices.Contains(question.Patterns, pattern) {
			question.Patterns = append(question.Patterns, pattern)
		}
	}

	for _, read := range opaengine.SubjectIndexedReads(a.Shape, a.Reads) {
		if !a.covers(read.Path) {
			add(read.Path, AttrSelfWrite, false, false)
		}
	}
	for _, read := range opaengine.SubjectMatchedReads(a.Shape, a.Reads) {
		if !a.covers(read.Path) {
			add(read.Path, AttrSelfWrite, false, true)
		}
	}
	for _, finding := range found.GlobalSwitch {
		if finding.Verdict == VerdictCandidate && finding.Path != "" {
			add(finding.Path, GlobalDocumentDecides, true, false)
		}
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

// covers reports whether the write model names a writer for a path. Without a
// model nothing is covered, so every pattern-relevant read is an open question.
func (a Analysis) covers(path string) bool {
	if a.Model == nil {
		return false
	}
	parsed, err := writemodel.ParsePath(path)
	if err != nil {
		return false
	}
	return a.Model.Covers(parsed)
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
