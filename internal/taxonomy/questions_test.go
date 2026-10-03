package taxonomy

import (
	"path/filepath"
	"testing"

	"github.com/saluc28/petard/internal/writemodel"
)

// questionFor returns the question about a path, and whether it was asked.
func questionFor(questions []Question, path string) (Question, bool) {
	for _, question := range questions {
		if question.Path == path {
			return question, true
		}
	}
	return Question{}, false
}

// Without a write model every path a write-path pattern reads is an open
// question: the self write reads, by index and by value, and the shared document
// the global switch found.
func TestOpenQuestionsWithoutAWriteModel(t *testing.T) {
	a := fixtureAnalysis(t)
	a.Model = nil

	found, err := Run(t.Context(), a)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	questions := OpenQuestions(a, found)

	want := map[string]string{
		"data.users[_].roles":              "can the subject write their own?",
		"data.users[_].profile.department": "can the subject write their own?",
		"data.projects[_].members":         "can the subject add themselves to it?",
		"data.settings.reading_room.open":  "who can write it?",
	}
	for path, asks := range want {
		question, asked := questionFor(questions, path)
		if !asked {
			t.Errorf("%s was not asked about", path)
			continue
		}
		if question.Asks() != asks {
			t.Errorf("%s asks %q, want %q", path, question.Asks(), asks)
		}
	}
	// The counter case console.enabled decides for somebody with a record, not
	// for anybody, so it is no question.
	if _, asked := questionFor(questions, "data.settings.console.enabled"); asked {
		t.Error("the global switch counter case was asked about")
	}
}

// A partial write model still shows what it leaves open. The closed world makes
// an uncovered self write produce no candidate, but it is still a question, so a
// self write question comes from the reads rather than the candidates and
// survives the model: covering roles answers that one and leaves the others.
func TestOpenQuestionsSurviveAPartialWriteModel(t *testing.T) {
	a := fixtureAnalysis(t)
	a.Model = partialModel(t)

	found, err := Run(t.Context(), a)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	questions := OpenQuestions(a, found)

	if _, asked := questionFor(questions, "data.users[_].roles"); asked {
		t.Error("data.users[_].roles is covered by the model but still asked about")
	}
	for _, path := range []string{"data.users[_].profile.department", "data.projects[_].members"} {
		if _, asked := questionFor(questions, path); !asked {
			t.Errorf("%s is left open by the partial model but not asked about", path)
		}
	}
}

// partialModel declares a writer for roles alone, leaving the rest of the
// fixture's paths undeclared.
func partialModel(t *testing.T) *writemodel.Model {
	t.Helper()

	path := filepath.Join(t.TempDir(), "partial.yaml")
	writeCaseFile(t, path, `schema_version: 1
model: write-paths
entries:
  - path: data.users.{owner}.roles
    writable_by:
      - principal: role:admin
        via: "PUT /api/v1/users/{id}/roles"
`)
	model, err := writemodel.Load(path)
	if err != nil {
		t.Fatalf("loading the partial model: %v", err)
	}
	return model
}
