package opaengine

import (
	"errors"
	"slices"
	"testing"
)

func TestRecognizeShape(t *testing.T) {
	tests := []struct {
		name       string
		inputPaths []string
		expected   Shape
	}{
		{
			name:       "the AuthZEN shape",
			inputPaths: []string{"input.action.name", "input.context.time", "input.resource.id", "input.subject.id"},
			expected: Shape{
				Subject:    "input.subject.id",
				Action:     "input.action",
				Resource:   "input.resource",
				Confidence: ConfidenceAuthZEN,
				Recognizer: "authzen",
			},
		},
		{
			// Type and properties name no principal, so the subject stays the
			// object when the policy never reads its id.
			name:       "the AuthZEN shape without the id of the subject",
			inputPaths: []string{"input.action.name", "input.resource.type", "input.subject.properties.department"},
			expected: Shape{
				Subject:    "input.subject",
				Action:     "input.action",
				Resource:   "input.resource",
				Confidence: ConfidenceAuthZEN,
				Recognizer: "authzen",
			},
		},
		{
			// One field called action does not make a request AuthZEN, and
			// claiming level B for it would be worth less than claiming
			// nothing.
			name:       "a policy that merely has an action field",
			inputPaths: []string{"input.action", "input.user"},
			expected: Shape{
				Subject:    "input.user",
				Action:     "input.action",
				Confidence: ConfidenceNames,
				Recognizer: "field names",
			},
		},
		{
			name:       "names that say nothing",
			inputPaths: []string{"input.foo", "input.bar"},
			expected:   Shape{Confidence: ConfidenceNone, Recognizer: "none"},
		},
		{
			// The shape of the gatekeeper-library corpus, and of any policy
			// behind a Kubernetes admission webhook: the decision is about the
			// object being admitted, and nothing in it is about who asked.
			name:       "an admission review that reads only the object",
			inputPaths: []string{"input.parameters.repos", "input.review.object.spec.containers[_]"},
			expected: Shape{
				Resource:   "input.review.object",
				Confidence: ConfidenceDomain,
				Recognizer: "kubernetes admission review",
			},
		},
		{
			name: "an admission review that reads the requester too",
			inputPaths: []string{
				"input.review.object.metadata.name",
				"input.review.operation",
				"input.review.userInfo.username",
			},
			expected: Shape{
				Subject:    "input.review.userInfo",
				Action:     "input.review.operation",
				Resource:   "input.review.object",
				Confidence: ConfidenceDomain,
				Recognizer: "kubernetes admission review",
			},
		},
		{
			// A domain convention outranks a guess about names, which is the
			// whole reason the recognizers are ordered: input.review.object
			// would otherwise be read as a resource called object at level D,
			// with no subject either way, and the level would be the only
			// difference that shows.
			name:       "an admission review beats the field names below it",
			inputPaths: []string{"input.review.object.spec", "input.user"},
			expected: Shape{
				Resource:   "input.review.object",
				Confidence: ConfidenceDomain,
				Recognizer: "kubernetes admission review",
			},
		},
		{
			// The request of Chef Automate: the user and every team the user is
			// in, in one list the policy ranges over.
			name:       "a list of subjects",
			inputPaths: []string{"input.action", "input.projects[_]", "input.resource", "input.subjects[_]"},
			expected: Shape{
				Subject:    "input.subjects[_]",
				Action:     "input.action",
				Resource:   "input.resource",
				Confidence: ConfidenceNames,
				Recognizer: "field names",
			},
		},
		{
			// Ranging over the field is what makes it a list, not its name.
			name:       "a plural name the policy never ranges over",
			inputPaths: []string{"input.subjects"},
			expected: Shape{
				Subject:    "input.subjects",
				Confidence: ConfidenceNames,
				Recognizer: "field names",
			},
		},
		{
			// A subject and nothing else is a normal outcome. Reaching for the
			// least bad candidate to fill the other two would be a guess on
			// top of a guess.
			name:       "only the subject is recognizable",
			inputPaths: []string{"input.principal.id", "input.tenant"},
			expected: Shape{
				Subject:    "input.principal",
				Confidence: ConfidenceNames,
				Recognizer: "field names",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RecognizeShape(&ReadSet{InputPaths: tt.inputPaths})

			if got != tt.expected {
				t.Errorf("shape = %+v, want %+v", got, tt.expected)
			}
		})
	}
}

// AuthZEN makes the subject an object and its id the identity, so a document
// picked by data.users[input.subject.id] is picked by whoever is asking.
func TestSubjectIndexedReadsUnderAuthZEN(t *testing.T) {
	dir := writeSources(t, map[string]string{
		"policy.rego": `package authzen

default allow["decision"] := false

allow["decision"] if {
	input.action.name == "can_delete_todo"
	input.resource.properties.ownerID == data.users[input.subject.id].email
}
`,
	})
	bundle, err := Load([]string{dir}, ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	bundle.Entrypoints = []string{"authzen/allow"}

	reads, err := Reads(bundle, Limits{})
	if err != nil {
		t.Fatalf("Reads() error = %v", err)
	}
	shape := RecognizeShape(reads)
	if shape.Subject != "input.subject.id" {
		t.Fatalf("Subject = %q, want input.subject.id", shape.Subject)
	}

	indexed := SubjectIndexedReads(shape, reads)
	if len(indexed) != 1 || indexed[0].Path != "data.users[_].email" {
		t.Errorf("SubjectIndexedReads() = %v, want the read of data.users[_].email", indexed)
	}
}

func TestIsSubject(t *testing.T) {
	list := Shape{Subject: "input.subjects[_]"}
	one := Shape{Subject: "input.user"}

	tests := []struct {
		name     string
		shape    Shape
		term     string
		expected bool
	}{
		{name: "the element of the list", shape: list, term: "input.subjects[_]", expected: true},
		{name: "the element through a named index", shape: list, term: "input.subjects[i]", expected: true},
		{name: "the list itself", shape: list, term: "input.subjects", expected: false},
		{name: "the same field", shape: one, term: "input.user", expected: true},
		{name: "a field of the subject", shape: one, term: "input.user.name", expected: false},
		{name: "nothing", shape: one, term: "", expected: false},
		{name: "no subject at all", shape: Shape{}, term: "input.user", expected: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.shape.IsSubject(tt.term); got != tt.expected {
				t.Errorf("IsSubject(%q) = %v, want %v", tt.term, got, tt.expected)
			}
		})
	}

	if path, isList := list.SubjectList(); !isList || path != "input.subjects" {
		t.Errorf("SubjectList() = %q, %v, want input.subjects, true", path, isList)
	}
	if _, isList := one.SubjectList(); isList {
		t.Error("SubjectList() says input.user is a list")
	}
}

func TestConfidenceLevels(t *testing.T) {
	levels := map[Confidence]string{
		ConfidenceDeclared: "A",
		ConfidenceAuthZEN:  "B",
		ConfidenceDomain:   "C",
		ConfidenceNames:    "D",
		ConfidenceNone:     "E",
	}
	for level, expected := range levels {
		if got := level.String(); got != expected {
			t.Errorf("confidence %d = %q, want %q", level, got, expected)
		}
	}

	// The order is the point: a declaration has to outrank a guess, and the
	// comparison is what decides which recognizer wins.
	descending := []Confidence{
		ConfidenceDeclared,
		ConfidenceAuthZEN,
		ConfidenceDomain,
		ConfidenceNames,
		ConfidenceNone,
	}
	for i := 1; i < len(descending); i++ {
		if descending[i-1] <= descending[i] {
			t.Errorf("%s does not outrank %s, so the levels are not ordered from A down to E",
				descending[i-1], descending[i])
		}
	}
}

// A request read through object.get is read at the field the call names. The
// compiler hands the call a variable bound to input, and that binding is the
// way to the field rather than a read of the whole request.
func TestInputPathsFollowObjectGet(t *testing.T) {
	tests := []struct {
		name     string
		policy   string
		expected []string
	}{
		{
			name: "a path and a field",
			policy: `package t

# METADATA
# scope: document
# entrypoint: true
allow if {
	lower(object.get(input, ["created_by", "username"], "")) == "alice"
	count(object.get(input, "labels", [])) > 0
}
`,
			expected: []string{"input.created_by.username", "input.labels"},
		},
		{
			// A key the policy computes could be any field, and one field read
			// next to it does not narrow that down.
			name: "a computed key",
			policy: `package t

# METADATA
# scope: document
# entrypoint: true
allow if {
	object.get(input, data.settings.field, "") == "alice"
	object.get(input, "name", "") != ""
}
`,
			expected: []string{"input.name", "input[_]"},
		},
		{
			// A rule that takes the request whole takes all of it, whatever the
			// other rules read.
			name: "a rule that takes the request whole",
			policy: `package t

# METADATA
# scope: document
# entrypoint: true
allow if object.get(input, "name", "") != ""

# METADATA
# scope: document
# entrypoint: true
audited if count(input) > 0
`,
			expected: []string{"input", "input.name"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bundle, err := Load([]string{writeSources(t, map[string]string{"policy.rego": tt.policy})}, ParseModeAuto)
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			reads, err := Reads(bundle, Limits{})
			if err != nil {
				t.Fatalf("Reads() error = %v", err)
			}
			if !slices.Equal(reads.InputPaths, tt.expected) {
				t.Errorf("InputPaths = %v, want %v", reads.InputPaths, tt.expected)
			}
		})
	}
}

// A subject declared from outside replaces recognition, and a declaration
// nothing reads is refused the way an entrypoint that names no rule is.
func TestShapeOf(t *testing.T) {
	aap := []string{"input.created_by.is_superuser", "input.created_by.teams", "input.created_by.username", "input.user"}

	tests := []struct {
		name       string
		inputPaths []string
		subject    string
		expected   Shape
		err        error
	}{
		{
			name:       "declared",
			inputPaths: aap,
			subject:    "input.created_by.username",
			expected: Shape{
				Subject:    "input.created_by.username",
				Confidence: ConfidenceDeclared,
				Recognizer: "declared",
			},
		},
		{
			name:       "declared inside a field the decisions read whole",
			inputPaths: []string{"input.created_by"},
			subject:    "input.created_by.username",
			expected: Shape{
				Subject:    "input.created_by.username",
				Confidence: ConfidenceDeclared,
				Recognizer: "declared",
			},
		},
		{
			name:       "declared as a list the decisions range over",
			inputPaths: []string{"input.subjects[_]"},
			subject:    "input.subjects",
			expected: Shape{
				Subject:    "input.subjects[_]",
				Confidence: ConfidenceDeclared,
				Recognizer: "declared",
			},
		},
		{
			name:       "not declared",
			inputPaths: aap,
			expected: Shape{
				Subject:    "input.user",
				Confidence: ConfidenceNames,
				Recognizer: "field names",
			},
		},
		{name: "read by no decision", inputPaths: aap, subject: "input.launched_by.name", err: ErrSubjectNotRead},
		{name: "not in the request", inputPaths: aap, subject: "data.users", err: ErrBadSubject},
		{name: "not a path at all", inputPaths: aap, subject: "input.", err: ErrBadSubject},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ShapeOf(&ReadSet{InputPaths: tt.inputPaths}, tt.subject)
			if !errors.Is(err, tt.err) {
				t.Fatalf("ShapeOf() error = %v, want %v", err, tt.err)
			}
			if got != tt.expected {
				t.Errorf("shape = %+v, want %+v", got, tt.expected)
			}
		})
	}
}

// The fixture writes its request the way most policies do, so it lands on
// level D. That is the honest answer, and it is also the realistic one: the
// design says the common case is that nobody declares anything.
func TestRecognizeShapeOnFixture(t *testing.T) {
	bundle, err := Load([]string{fixtureDir(t, "policy-v1")}, ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	reads, err := Reads(bundle, Limits{})
	if err != nil {
		t.Fatalf("Reads() error = %v", err)
	}

	expectedInput := []string{
		"input.action", "input.doc", "input.group_ids", "input.groups", "input.mfa",
		"input.reviews", "input.role", "input.scheduled", "input.tenant", "input.user",
	}
	if !slices.Equal(reads.InputPaths, expectedInput) {
		t.Errorf("input paths = %v, want %v", reads.InputPaths, expectedInput)
	}

	shape := RecognizeShape(reads)
	expected := Shape{
		Subject:    "input.user",
		Action:     "input.action",
		Resource:   "input.doc",
		Confidence: ConfidenceNames,
		Recognizer: "field names",
	}
	if shape != expected {
		t.Errorf("shape = %+v, want %+v", shape, expected)
	}
}

// This is the signal PTD-OPA-001 is built on: the requester is on both ends of
// the decision, choosing the document that decides about them. The counter
// case matters as much: a document indexed by the resource is the ordinary way
// a policy works.
func TestSubjectIndexedReadsOnFixture(t *testing.T) {
	bundle, err := Load([]string{fixtureDir(t, "policy-v1")}, ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	reads, err := Reads(bundle, Limits{})
	if err != nil {
		t.Fatalf("Reads() error = %v", err)
	}

	shape := RecognizeShape(reads)
	var paths []string
	for _, read := range SubjectIndexedReads(shape, reads) {
		paths = append(paths, read.Path)
	}
	slices.Sort(paths)
	paths = slices.Compact(paths)

	expected := []string{"data.users[_].profile.department", "data.users[_].roles"}
	if !slices.Equal(paths, expected) {
		t.Errorf("indexed by the subject = %v, want %v", paths, expected)
	}
}

// The fixture looks the requester up once, among the members of a project, and
// the owner route is not a lookup: the document there is the one the request
// names, and its owner is checked rather than searched.
func TestSubjectMatchedReadsOnFixture(t *testing.T) {
	bundle, err := Load([]string{fixtureDir(t, "policy-v1")}, ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	reads, err := Reads(bundle, Limits{})
	if err != nil {
		t.Fatalf("Reads() error = %v", err)
	}

	shape := RecognizeShape(reads)
	matched := SubjectMatchedReads(shape, reads)
	if len(matched) != 1 || matched[0].Path != "data.projects[_].members" {
		t.Fatalf("matched by the subject = %v, want the members of a project", matched)
	}
	if match, found := shape.MatchedBySubject(matched[0]); !found || !match.Member || match.Position != 4 {
		t.Errorf("match = %+v, want a search of the members, at segment 4", match)
	}

	values := SubjectValues(shape, reads)
	if !slices.Equal(values, []string{"data.projects[_].members[_]"}) {
		t.Errorf("SubjectValues() = %v, want the members themselves", values)
	}
}
