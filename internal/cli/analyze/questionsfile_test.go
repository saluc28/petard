package analyze

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/saluc28/petard/internal/cli/zanzibarsetup"
	"github.com/saluc28/petard/internal/opaengine"
	"github.com/saluc28/petard/internal/taxonomy"
	"github.com/saluc28/petard/internal/writemodel"
	"github.com/saluc28/petard/internal/zanzibar"
)

func sampleQuestions() []taxonomy.Question {
	return []taxonomy.Question{
		{Path: "data.users[_].roles", Patterns: []string{"PTD-OPA-001"}, Writable: "data.users.{owner}.roles", Writer: "{owner}"},
		{Path: "data.settings.open", Patterns: []string{"PTD-OPA-008"}, Shared: true, Writable: "data.settings.open", Writer: "role:CHANGEME"},
		{Path: "data.projects[_].members", Patterns: []string{"PTD-OPA-001"}, LookedUp: true, Writable: "data.projects.{project}.members.{member}", Writer: "{member}"},
	}
}

// The skeleton is a write model with one entry per question: the path to declare,
// the principal to confirm, and an empty via to fill. The subject is named once
// at the top so a reader can tell whether the questions started from the right
// one.
func TestWriteQuestionsSkeleton(t *testing.T) {
	path := filepath.Join(t.TempDir(), "write-model.yaml")
	written, err := writeQuestions(path, "input.user", sampleQuestions(), nil)
	if err != nil {
		t.Fatalf("writeQuestions() error = %v", err)
	}
	if written != 3 {
		t.Errorf("entries = %d, want 3", written)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the skeleton: %v", err)
	}
	for _, want := range []string{
		"# The subject is input.user.",
		"- path: data.users.{owner}.roles",
		`principal: "{owner}"`,
		"- path: data.projects.{project}.members.{member}",
		`principal: "{member}"`,
		`principal: "role:CHANGEME"`,
		"via: \"\"",
	} {
		if !strings.Contains(string(content), want) {
			t.Errorf("the skeleton does not contain %q:\n%s", want, content)
		}
	}
}

// A key of the data is any string, and YAML reads some of them as something
// else: ": " opens a mapping, " #" a comment, and a line break ends the value.
// The skeleton quotes those, so the path the loader reads back is the path the
// question was about.
func TestSkeletonKeepsAKeyYAMLReadsAsSomethingElse(t *testing.T) {
	for _, writable := range []string{
		"data.cfg.a: b.{owner}.role",
		"data.cfg.x #y.{owner}.role",
		"data.cfg.two\nlines.{owner}.role",
		`data.cfg["a.b"].{owner}.role`,
	} {
		t.Run(writable, func(t *testing.T) {
			questions := []taxonomy.Question{
				{Path: "data.cfg[_][_].role", Patterns: []string{"PTD-OPA-001"}, Writable: writable, Writer: "{owner}"},
			}
			filled := strings.ReplaceAll(skeleton("input.user", questions, nil), `via: ""`, `via: "PUT /filled"`)
			path := filepath.Join(t.TempDir(), "write-model.yaml")
			if err := os.WriteFile(path, []byte(filled), 0o600); err != nil {
				t.Fatal(err)
			}

			model, err := writemodel.Load(path)
			if err != nil {
				t.Fatalf("the skeleton does not load: %v\n%s", err, filled)
			}
			if len(model.Entries) != 1 || model.Entries[0].RawPath != writable {
				t.Errorf("entries = %+v, want the one path %q", model.Entries, writable)
			}
		})
	}
}

// The writes a bundle authorizes are appended as commented authorized_by blocks,
// each with the decision and the method, so declaring a write allowed by another
// decision is attaching one rather than writing it from scratch. A branch whose
// path fixes variables comes without one, pointing at the line to read it from.
func TestWriteQuestionsListsTheWriteSurface(t *testing.T) {
	path := filepath.Join(t.TempDir(), "write-model.yaml")
	endpoints := []opaengine.WriteEndpoint{
		{Decision: "data.app.authz", Method: "POST", Path: `["users"]`, File: "app.rego", Line: 10},
		{Decision: "data.app.authz", Method: "PUT", Path: "", File: "app.rego", Line: 20},
	}
	if _, err := writeQuestions(path, "input.user", sampleQuestions(), endpoints); err != nil {
		t.Fatalf("writeQuestions() error = %v", err)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"# Writes this bundle authorizes.",
		"decision: data.app.authz",
		`input.method: "POST"`,
		`input.path: ["users"]`,
		`input.method: "PUT"`,
		"input.path at app.rego:20 fixes variables",
	} {
		if !strings.Contains(string(content), want) {
			t.Errorf("the skeleton does not list %q:\n%s", want, content)
		}
	}
}

// A write model somebody has filled in is the last thing to clobber, so the
// skeleton refuses a path that already exists.
func TestWriteQuestionsRefusesAnExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "write-model.yaml")
	if err := os.WriteFile(path, []byte("do not overwrite me\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := writeQuestions(path, "input.user", sampleQuestions(), nil); err == nil {
		t.Error("writeQuestions() overwrote an existing file")
	}
	content, _ := os.ReadFile(path)
	if string(content) != "do not overwrite me\n" {
		t.Errorf("the existing file was changed: %s", content)
	}
}

// Once the vias are filled, the skeleton is a write model the loader accepts, so
// answering the questions is editing this file and running again.
func TestSkeletonLoadsOnceFilled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "write-model.yaml")
	if _, err := writeQuestions(path, "input.user", sampleQuestions(), nil); err != nil {
		t.Fatalf("writeQuestions() error = %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	filled := strings.ReplaceAll(string(raw), `via: ""`, `via: "PUT /filled"`)
	filledPath := filepath.Join(t.TempDir(), "filled.yaml")
	if err := os.WriteFile(filledPath, []byte(filled), 0o600); err != nil {
		t.Fatal(err)
	}

	model, err := writemodel.Load(filledPath)
	if err != nil {
		t.Fatalf("the filled skeleton does not load: %v", err)
	}
	if len(model.Entries) != 3 {
		t.Errorf("entries = %d, want 3", len(model.Entries))
	}
}

// What a relation can raise sits above its entry, a few names to a line, so a relation
// that raises a whole model stays readable.
func TestWriteReachKeepsALongListReadable(t *testing.T) {
	var b strings.Builder
	writeReach(&b, []string{"a#1", "a#2", "a#3", "a#4", "b#1", "b#2"})
	want := "  # can raise a#1, a#2, a#3, a#4,\n  #   b#1, b#2\n"
	if b.String() != want {
		t.Errorf("writeReach =\n%q\nwant\n%q", b.String(), want)
	}
	b.Reset()
	writeReach(&b, nil)
	if b.String() != "" {
		t.Errorf("a relation that raises nothing gets %q", b.String())
	}
}

// A relation that can raise more than a handful shows the first few and a count of
// the rest, so one leaf relation does not print a whole model.
func TestWriteReachCapsALongList(t *testing.T) {
	var raises []string
	for i := range 10 {
		raises = append(raises, fmt.Sprintf("doc#p%d", i))
	}
	var b strings.Builder
	writeReach(&b, raises)
	got := b.String()
	if !strings.Contains(got, "and 2 more") {
		t.Errorf("writeReach did not cap a long list:\n%s", got)
	}
	if strings.Contains(got, "doc#p8") || strings.Contains(got, "doc#p9") {
		t.Errorf("writeReach listed past the cap:\n%s", got)
	}
}

// The skeleton keeps the relations that need a gate as full entries, caps what each
// can raise, and gathers the ones that raise nothing into one note that still names
// them, so a schema with many leaf relations does not bury the few levers.
func TestSchemaSkeletonGathersTheRelationsThatRaiseNothing(t *testing.T) {
	raises := make([]string, 10)
	for i := range raises {
		raises[i] = fmt.Sprintf("doc#p%d", i)
	}
	groups := []schemaProposals{{
		product: zanzibarsetup.OpenFGA,
		schema:  "model.fga",
		proposals: []zanzibar.GateProposal{
			{Type: "doc", Relation: "owner", Safe: []string{"admin"}, Raises: raises},
			{Type: "doc", Relation: "a"},
			{Type: "doc", Relation: "b"},
			{Type: "doc", Relation: "c"},
		},
	}}
	content, entries := schemaSkeleton(groups)
	if entries != 4 {
		t.Errorf("entries = %d, want 4", entries)
	}
	for _, want := range []string{
		"- resource: doc",
		"relation: owner",
		"and 2 more",
		"3 relations raise no permission and need no gate:",
		"doc#a", "doc#b", "doc#c",
	} {
		if !strings.Contains(content, want) {
			t.Errorf("the skeleton does not contain %q:\n%s", want, content)
		}
	}
	if strings.Contains(content, "doc#a raises no permission") {
		t.Errorf("a relation that raises nothing still has its own line:\n%s", content)
	}
}

// Two relations that can raise as many keep the order of the schema, so the same schema
// writes the same file on every run.
func TestByReachKeepsTheSchemaOrderBetweenEquals(t *testing.T) {
	var proposals []zanzibar.GateProposal
	byCount := map[int][]string{}
	for i := range 40 {
		name := fmt.Sprintf("r%02d", i)
		raises := []string{"document#a", "document#b"}[:(i*7)%3]
		proposals = append(proposals, zanzibar.GateProposal{Type: "document", Relation: name, Raises: raises})
		byCount[len(raises)] = append(byCount[len(raises)], name)
	}
	want := slices.Concat(byCount[2], byCount[1], byCount[0])
	var got []string
	for _, p := range byReach(proposals) {
		got = append(got, p.Relation)
	}
	if !slices.Equal(got, want) {
		t.Errorf("byReach = %v, want the schema order %v", got, want)
	}
}
