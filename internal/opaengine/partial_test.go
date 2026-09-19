package opaengine

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"

	"github.com/saluc28/petard/internal/fixture"
)

func fixtureData(t *testing.T) *Data {
	t.Helper()

	data, err := LoadData([]string{filepath.Join("..", "..", "fixtures", "vulnerable-bundle", "data")})
	if err != nil {
		t.Fatalf("LoadData() error = %v", err)
	}
	return data
}

// residualsFor asks what a principal can read, by leaving the document unknown
// and giving the rest of the request.
func residualsFor(t *testing.T, dir string, user string, limits Limits) *ResidualSet {
	t.Helper()

	bundle, err := Load([]string{dir}, ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	residuals, err := Residuals(t.Context(), bundle, fixtureData(t), Request{
		Decision: "data.quill.authz.allow",
		Unknowns: []string{"input.doc"},
		Input:    map[string]any{"user": user, "action": "read"},
	}, limits)
	if err != nil {
		t.Fatalf("Residuals() error = %v", err)
	}
	return residuals
}

// The numbers of EXPECTED.md section 2, measured through the engine: dave holds
// a position in the root of the hierarchy and reaches the whole dataset, while
// mallory holds nothing and reaches nothing. One condition per document, which
// is partial evaluation expanding the concrete data into a disjunction.
func TestResidualsCountWhatAPrincipalCanRead(t *testing.T) {
	tests := []struct {
		name     string
		user     string
		expected int
	}{
		{name: "member of the root reaches everything", user: "dave", expected: 18},
		{name: "no membership reaches nothing", user: "mallory", expected: 0},
		{name: "owner and member of one leaf", user: "alice", expected: 7},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			residuals := residualsFor(t, fixtureDir(t, "policy-v1"), tt.user, Limits{})

			if len(residuals.Conditions) != tt.expected {
				t.Errorf("conditions = %d, want %d:\n%v", len(residuals.Conditions), tt.expected, residuals.Conditions)
			}
			if tt.expected == 0 && !residuals.Never() {
				t.Error("no condition holds and Never() is false")
			}
			if residuals.Default != "false" {
				t.Errorf("default = %q, want false: the decision declares one", residuals.Default)
			}
			for _, condition := range residuals.Conditions {
				if !strings.Contains(condition.Query, "input.doc") {
					t.Errorf("condition %q does not constrain the unknown", condition.Query)
				}
				if condition.Value != "true" {
					t.Errorf("condition %q grants %q, want true", condition.Query, condition.Value)
				}
			}
		})
	}
}

// The trap of EXPECTED.md section 5, and the reason this file exists rather
// than a reachability walk of our own.
//
// graph.reachable includes a node only if that node is a key of the graph
// object, so a hierarchy written the natural way, where a project without a
// parent gets no entry, silently omits the root. The policy then grants dave
// nothing, because his only membership is on the root.
//
// Computing reachability ourselves would answer the mathematical question and
// report eighteen documents in both cases. Here the two answers differ, and
// they differ because OPA evaluates the construct the policy really uses. The
// control is alice, whose membership is on a leaf: her count does not move,
// which is what says the naive variant broke the root and not everything.
func TestResidualsFollowTheConstructThePolicyUses(t *testing.T) {
	naive := naiveHierarchy(t)

	tests := []struct {
		name     string
		user     string
		fixture  int
		degraded int
	}{
		{name: "member of the root", user: "dave", fixture: 18, degraded: 0},
		{name: "member of a leaf", user: "alice", fixture: 7, degraded: 7},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			asWritten := residualsFor(t, fixtureDir(t, "policy-v1"), tt.user, Limits{})
			if len(asWritten.Conditions) != tt.fixture {
				t.Errorf("conditions with the fixture hierarchy = %d, want %d",
					len(asWritten.Conditions), tt.fixture)
			}

			degraded := residualsFor(t, naive, tt.user, Limits{})
			if len(degraded.Conditions) != tt.degraded {
				t.Errorf("conditions with the naive hierarchy = %d, want %d",
					len(degraded.Conditions), tt.degraded)
			}
		})
	}
}

// naiveHierarchy copies the fixture policy and writes parent_of the natural
// way, the one that leaves the root out of the graph object.
func naiveHierarchy(t *testing.T) string {
	t.Helper()

	const (
		guarded = "parents := [p | p := project.parent]"
		naive   = "parents := [project.parent]"
	)

	source := fixtureDir(t, "policy-v1")
	entries, err := os.ReadDir(source)
	if err != nil {
		t.Fatalf("reading the fixture policy: %v", err)
	}

	dir := t.TempDir()
	rewritten := false
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != regoExt {
			continue
		}
		content, err := os.ReadFile(filepath.Join(source, entry.Name()))
		if err != nil {
			t.Fatalf("reading %s: %v", entry.Name(), err)
		}
		text := string(content)
		if strings.Contains(text, guarded) {
			text = strings.Replace(text, guarded, naive, 1)
			rewritten = true
		}
		if err := os.WriteFile(filepath.Join(dir, entry.Name()), []byte(text), 0o600); err != nil {
			t.Fatalf("writing %s: %v", entry.Name(), err)
		}
	}
	if !rewritten {
		t.Fatalf("the fixture no longer contains %q, so this test compares nothing", guarded)
	}
	return dir
}

// Analyzing a policy must not call the addresses written in it.
//
// Partial evaluation can be told to evaluate nondeterministic builtins, to pull
// the external data in and let it inform the result. That is the wrong side of
// the trade for a tool that reads other people's policies: it would turn a run
// of the analysis into HTTP requests to hosts chosen by whoever wrote the file.
// The call stays in the condition instead, where it says something true, that
// the decision cannot be settled from the data alone.
//
// The fixture points at .invalid hosts, so a run that did make requests would
// still pass its assertions. That is exactly why this checks the condition and
// not the outcome.
func TestResidualsDoNotCallTheEndpointsThePolicyNames(t *testing.T) {
	bundle, err := Load([]string{fixtureDir(t, "policy-v1")}, ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	residuals, err := Residuals(t.Context(), bundle, fixtureData(t),
		Request{Decision: "data.quill.enrichment.allow"}, Limits{})
	if err != nil {
		t.Fatalf("Residuals() error = %v", err)
	}
	if len(residuals.Conditions) != 1 {
		t.Fatalf("conditions = %v, want the one the call is in", residuals.Conditions)
	}

	condition := residuals.Conditions[0].Query
	if !strings.Contains(condition, "http.send") {
		t.Errorf("the call is not in the condition, so it was evaluated instead: %s", condition)
	}
	if !strings.Contains(condition, "idp.petard-fixture.invalid") {
		t.Errorf("the condition does not name the endpoint the decision depends on: %s", condition)
	}
}

// A decision without a default leaves its conditions in the residual queries
// themselves, with no support module in between. It is the simplest shape a
// decision can have, and the one real policies are least likely to have.
func TestResidualsWithoutADefault(t *testing.T) {
	dir := writeSources(t, map[string]string{
		"policy.rego": `package t

# METADATA
# scope: document
# entrypoint: true
allow if input.role == data.roles[_]
`,
	})
	bundle, err := Load([]string{dir}, ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	data := writeData(t, `{"roles": ["admin", "dev"]}`)
	residuals, err := Residuals(t.Context(), bundle, data, Request{Decision: "data.t.allow"}, Limits{})
	if err != nil {
		t.Fatalf("Residuals() error = %v", err)
	}

	if len(residuals.Conditions) != 2 {
		t.Fatalf("conditions = %v, want one per role", residuals.Conditions)
	}
	if residuals.Default != "" {
		t.Errorf("default = %q, want none: the policy declares no default", residuals.Default)
	}
	for _, condition := range residuals.Conditions {
		if !strings.Contains(condition.Query, "input.role") {
			t.Errorf("condition %q does not name the unknown", condition.Query)
		}
	}
}

// Nothing left to check is a different answer from a list of things to check,
// and it must not read as the same thing.
func TestResidualsWhenTheDataDecidesAlone(t *testing.T) {
	dir := writeSources(t, map[string]string{
		"policy.rego": `package t

# METADATA
# scope: document
# entrypoint: true
allow if data.settings.open == true
`,
	})
	bundle, err := Load([]string{dir}, ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	open, err := Residuals(t.Context(), bundle, writeData(t, `{"settings": {"open": true}}`),
		Request{Decision: "data.t.allow"}, Limits{})
	if err != nil {
		t.Fatalf("Residuals() error = %v", err)
	}
	if !open.Always {
		t.Errorf("Always = false, want true: the data alone decides (%v)", open.Conditions)
	}
	if open.Never() {
		t.Error("Never() and Always cannot both hold")
	}

	shut, err := Residuals(t.Context(), bundle, writeData(t, `{"settings": {"open": false}}`),
		Request{Decision: "data.t.allow"}, Limits{})
	if err != nil {
		t.Fatalf("Residuals() error = %v", err)
	}
	if !shut.Never() {
		t.Errorf("Never() = false, want true: nothing can make it hold (%v)", shut.Conditions)
	}
}

// A rule that answers with an object is defined whatever it says, so the
// question has to be asked of the field the enforcement point reads. Asked as a
// whole it holds on the data alone, and the document behind the answer drops
// out of it.
func TestResidualsAskAFieldOfWhatADecisionReturns(t *testing.T) {
	dir := writeSources(t, map[string]string{
		"policy.rego": `package t

violations contains "the gate is shut" if {
	not data.settings.open
	input.user != "admin"
}

decision := {"allowed": count(violations) == 0, "violations": [v | some v in violations]}
`,
	})
	bundle, err := Load([]string{dir}, ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	shut := writeData(t, `{"settings": {"open": false}}`)
	stranger := Request{Unknowns: []string{"input.nothing"}, Input: map[string]any{"user": "nobody"}}

	whole := stranger
	whole.Decision = "data.t.decision"
	residuals, err := Residuals(t.Context(), bundle, shut, whole, Limits{})
	if err != nil {
		t.Fatalf("Residuals() error = %v", err)
	}
	if !residuals.Always {
		t.Errorf("the whole answer: Always = false, want true, it is an object whatever it says (%v)",
			residuals.Conditions)
	}

	field := stranger
	field.Decision = "data.t.decision.allowed"
	residuals, err = Residuals(t.Context(), bundle, shut, field, Limits{})
	if err != nil {
		t.Fatalf("Residuals() error = %v", err)
	}
	if !residuals.Never() {
		t.Errorf("the field: Never() = false, want true, the gate is shut (%v)", residuals.Conditions)
	}

	depends, err := DependsOn(t.Context(), bundle, shut, field, "data.settings.open")
	if err != nil {
		t.Fatalf("DependsOn() error = %v", err)
	}
	if !depends {
		t.Error("DependsOn() = false, want true: the setting decides the field for whoever asks")
	}
}

// A rule with an else is rewritten before partial evaluation, so a role checked
// in one is measured for whoever asks: the principal who holds it is left with
// the rest of the request to meet, and the one who does not gets nothing.
// Handed back whole, the rule read the same for both.
func TestResidualsGoThroughARuleWithAnElse(t *testing.T) {
	dir := writeSources(t, map[string]string{
		"policy.rego": `package t

default publish := false

publish if may_publish

may_publish := true if {
	input.action == "publish"
	"editor" in data.users[input.user].roles
} else := false
`,
	})
	bundle, err := Load([]string{dir}, ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	data := writeData(t, `{"users": {"alice": {"roles": ["editor"]}, "carol": {"roles": ["support"]}}}`)

	for user, expected := range map[string][]string{"alice": {`input.action = "publish"`}, "carol": nil} {
		residuals, err := Residuals(t.Context(), bundle, data, Request{
			Decision: "data.t.publish",
			Unknowns: []string{"input.action"},
			Input:    map[string]any{"user": user},
		}, Limits{})
		if err != nil {
			t.Fatalf("Residuals() error = %v", err)
		}
		var got []string
		for _, condition := range residuals.Conditions {
			got = append(got, condition.Query)
		}
		if residuals.Always || !slices.Equal(got, expected) {
			t.Errorf("%s: always = %v, conditions = %v, want %v", user, residuals.Always, got, expected)
		}
	}
}

// A setting merged over its defaults decides the decisions that read it, and
// the one next to them that never does is left alone. In a rule with an else
// the merge is rewritten and partial evaluation names the document itself. In
// a function with an else, called with part of the request, it is not: the
// call comes back as it is written, and the document is found in the function.
func TestDependsOnFindsTheDocumentBehindAnElse(t *testing.T) {
	dir := writeSources(t, map[string]string{
		"policy.rego": `package t

_defaults := {"open": false}

_gate := object.union(_defaults, data.settings.gate) if {
	is_object(data.settings.gate)
} else := _defaults

allow if {
	_gate.open
	input.action == "read"
}

gate(kind) := object.union(_defaults, data.settings.gate) if {
	kind == "reading"
	is_object(data.settings.gate)
} else := _defaults

allow_by_kind if {
	gate(input.kind).open
	input.action == "read"
}

audit if input.action == "read"
`,
	})
	bundle, err := Load([]string{dir}, ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	data := writeData(t, `{"settings": {"gate": {"open": true}}}`)

	for decision, expected := range map[string]bool{"data.t.allow": true, "data.t.allow_by_kind": true, "data.t.audit": false} {
		depends, err := DependsOn(t.Context(), bundle, data, Request{
			Decision: decision,
			Unknowns: []string{"input.action", "input.kind"},
		}, "data.settings.gate")
		if err != nil {
			t.Fatalf("DependsOn(%s) error = %v", decision, err)
		}
		if depends != expected {
			t.Errorf("DependsOn(%s) = %v, want %v", decision, depends, expected)
		}
	}
}

// A decision that collects grants what it holds, and an empty answer grants
// nothing. In Rego only false and undefined are not true, so an empty set is a
// value the query naming it holds on, and a principal authorized on nothing
// would otherwise read as one the decision cannot refuse.
func TestResidualsAskACollectedDecisionForWhatItHolds(t *testing.T) {
	dir := writeSources(t, map[string]string{
		"policy.rego": `package t

# METADATA
# scope: document
# entrypoint: true
authorized contains project if {
	some project in data.projects
	data.members[project][_] == input.user
}
`,
	})
	bundle, err := Load([]string{dir}, ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	data := writeData(t, `{"projects": ["one"], "members": {"one": ["alice"]}}`)

	for user, granted := range map[string]bool{"alice": true, "bob": false} {
		residuals, err := Residuals(t.Context(), bundle, data, Request{
			Decision: "data.t.authorized",
			Unknowns: []string{"input.nothing"},
			Input:    map[string]any{"user": user},
		}, Limits{})
		if err != nil {
			t.Fatalf("Residuals() error = %v", err)
		}
		if got := residuals.Always || len(residuals.Conditions) > 0; got != granted {
			t.Errorf("%s is granted %v, want %v (always = %v, conditions = %v)",
				user, got, granted, residuals.Always, residuals.Conditions)
		}
	}
}

// The claim this package makes about scale, measured instead of asserted: the
// number of residual conditions follows the cardinality of the data and not the
// size of the policy.
//
// The same four rules against three generated worlds, and the count tracks the
// documents rather than the rego. It is what defaultMaxResiduals exists for,
// and it is the measurement behind a value that would otherwise only be
// declared.
//
// Measured, it bites early. Forty documents leave a hundred and sixty
// conditions, because a document is reachable by more than one branch of the
// decision, so the default is reached at somewhere around sixty four documents:
// on a real dataset a report is nearly always truncated. That is a choice about
// what a report can show rather than a limit on what the analysis can do, and
// it is worth knowing which of the two it is.
func TestResidualsFollowTheCardinalityOfTheData(t *testing.T) {
	tests := []struct {
		name    string
		params  fixture.Params
		atLeast int
		bounded bool
	}{
		{name: "small", params: fixture.Small(11), atLeast: 100},
		{name: "medium", params: fixture.Medium(11), bounded: true},
		{name: "large", params: fixture.Large(11), bounded: true},
	}

	bundle, err := Load([]string{fixtureDir(t, "policy-v1")}, ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := generatedData(t, tt.params)

			// The default bound, so that what is measured is what a run without
			// flags would report.
			residuals, err := Residuals(t.Context(), bundle, data,
				Request{Decision: "data.quill.authz.allow"}, Limits{})
			if err != nil {
				t.Fatalf("Residuals() error = %v", err)
			}

			t.Logf("%d documents, %d users: %d conditions, truncated %v",
				tt.params.Documents, tt.params.Users, len(residuals.Conditions), residuals.Truncated)

			if residuals.Truncated != tt.bounded {
				t.Errorf("truncated = %v, want %v: the bound is meant to bite here and not there",
					residuals.Truncated, tt.bounded)
			}
			if tt.bounded {
				if len(residuals.Conditions) != defaultMaxResiduals {
					t.Errorf("conditions = %d, want the %d the bound allows", len(residuals.Conditions), defaultMaxResiduals)
				}
				return
			}
			if len(residuals.Conditions) < tt.atLeast {
				t.Errorf("conditions = %d, want at least %d: the count should follow the documents",
					len(residuals.Conditions), tt.atLeast)
			}
		})
	}
}

// generatedData writes a generated world and loads it.
func generatedData(t *testing.T, params fixture.Params) *Data {
	t.Helper()

	dataset, err := fixture.Generate(params)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	dir := t.TempDir()
	if err := dataset.Write(dir); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	data, err := LoadData([]string{dir})
	if err != nil {
		t.Fatalf("LoadData() error = %v", err)
	}
	return data
}

// The count of residuals follows the cardinality of the data, so it has a
// bound. A bound that cuts has to be visible in the result and not only in a
// log, which is why a truncated set is not allowed to look like an empty one.
func TestResidualsAreBounded(t *testing.T) {
	residuals := residualsFor(t, fixtureDir(t, "policy-v1"), "dave", Limits{MaxResiduals: 5})

	if len(residuals.Conditions) != 5 {
		t.Errorf("conditions = %d, want the 5 the bound allows", len(residuals.Conditions))
	}
	if !residuals.Truncated {
		t.Error("the set was cut and does not say so")
	}
	if residuals.Never() {
		t.Error("a truncated set reads as if nothing could make the decision hold")
	}
	if len(residuals.Warnings) != 1 || !strings.Contains(residuals.Warnings[0], "MaxResiduals") {
		t.Errorf("warnings = %v, want one naming the bound to raise", residuals.Warnings)
	}
}

// The measurement PTD-OPA-002 rests on, taken on the real fixture: the field
// the deny rule reads is there for one tenant and not for the other, while the
// field the counter case reads is there for both. Same policy, same request,
// and only the data tells the two checks apart.
func TestPresenceOnFixture(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		present []string
		absent  []string
	}{
		{
			name:    "the check that does not cover",
			path:    "data.tenants[_].policy.require_mfa",
			present: []string{"berq"},
			absent:  []string{"dolm"},
		},
		{
			name:    "the check that covers",
			path:    "data.tenants[_].status",
			present: []string{"berq", "dolm"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			presence, err := fixtureData(t).Presence(t.Context(), tt.path)
			if err != nil {
				t.Fatalf("Presence() error = %v", err)
			}
			if !slices.Equal(presence.Present, tt.present) {
				t.Errorf("present = %v, want %v", presence.Present, tt.present)
			}
			if !slices.Equal(presence.Absent, tt.absent) {
				t.Errorf("absent = %v, want %v", presence.Absent, tt.absent)
			}
			if presence.Keys() != len(tt.present)+len(tt.absent) {
				t.Errorf("keys = %d, want %d", presence.Keys(), len(tt.present)+len(tt.absent))
			}
		})
	}
}

// A document holding false, or null, is present. The distinction is the whole
// pattern: a value that says no is a check answering, and a missing one is a
// check that never ran, so folding them together would report every disabled
// control as a hole.
func TestPresenceTellsAMissingDocumentFromOneThatSaysNo(t *testing.T) {
	data := writeData(t, `{"tenants": {
		"a": {"policy": {"require_mfa": false}},
		"b": {"policy": {"require_mfa": null}},
		"c": {"policy": {}},
		"d": {}
	}}`)

	presence, err := data.Presence(t.Context(), "data.tenants[_].policy.require_mfa")
	if err != nil {
		t.Fatalf("Presence() error = %v", err)
	}
	if expected := []string{"a", "b"}; !slices.Equal(presence.Present, expected) {
		t.Errorf("present = %v, want %v", presence.Present, expected)
	}
	if expected := []string{"c", "d"}; !slices.Equal(presence.Absent, expected) {
		t.Errorf("absent = %v, want %v", presence.Absent, expected)
	}
}

// A path with no dynamic segment names one document, so there is no key to name
// the answer with, and the question is only whether that document is there.
func TestPresenceOfAPathWrittenOut(t *testing.T) {
	data := writeData(t, `{"settings": {"open": true}}`)

	open, err := data.Presence(t.Context(), "data.settings.open")
	if err != nil {
		t.Fatalf("Presence() error = %v", err)
	}
	if !slices.Equal(open.Present, []string{""}) || len(open.Absent) != 0 {
		t.Errorf("present = %v, absent = %v, want the one document present", open.Present, open.Absent)
	}

	missing, err := data.Presence(t.Context(), "data.settings.closed")
	if err != nil {
		t.Fatalf("Presence() error = %v", err)
	}
	if !slices.Equal(missing.Absent, []string{""}) || len(missing.Present) != 0 {
		t.Errorf("present = %v, absent = %v, want the one document absent", missing.Present, missing.Absent)
	}
}

// A collection can be an array, and then the documents are named by position.
func TestPresenceOverAnArray(t *testing.T) {
	data := writeData(t, `{"rules": [{"effect": "allow"}, {}]}`)

	presence, err := data.Presence(t.Context(), "data.rules[_].effect")
	if err != nil {
		t.Fatalf("Presence() error = %v", err)
	}
	if !slices.Equal(presence.Present, []string{"0"}) {
		t.Errorf("present = %v, want the first element", presence.Present)
	}
	if !slices.Equal(presence.Absent, []string{"1"}) {
		t.Errorf("absent = %v, want the second element", presence.Absent)
	}
}

// Where a path crosses two collections the key names the pair, because a pair
// is what identifies the document the check did not reach.
func TestPresenceAcrossTwoCollections(t *testing.T) {
	data := writeData(t, `{"tenants": {"berq": {"users": {"alice": {"mfa": true}, "bob": {}}}}}`)

	presence, err := data.Presence(t.Context(), "data.tenants[_].users[_].mfa")
	if err != nil {
		t.Fatalf("Presence() error = %v", err)
	}
	if !slices.Equal(presence.Present, []string{"berq.alice"}) {
		t.Errorf("present = %v, want berq.alice", presence.Present)
	}
	if !slices.Equal(presence.Absent, []string{"berq.bob"}) {
		t.Errorf("absent = %v, want berq.bob", presence.Absent)
	}
}

// A scalar where the path expects a collection to index is an answer of its
// own, and the honest one is that nothing under it exists. Reporting no keys at
// all would read as a path that covers everything.
func TestPresenceWhenThereIsNothingToIndex(t *testing.T) {
	data := writeData(t, `{"tenants": 5}`)

	presence, err := data.Presence(t.Context(), "data.tenants[_].status")
	if err != nil {
		t.Fatalf("Presence() error = %v", err)
	}
	if !slices.Equal(presence.Absent, []string{""}) || len(presence.Present) != 0 {
		t.Errorf("present = %v, absent = %v, want nothing reachable", presence.Present, presence.Absent)
	}
}

func TestPresenceOfSomethingThatIsNotAPath(t *testing.T) {
	data := writeData(t, `{"tenants": {"berq": {}}}`)

	if _, err := data.Presence(t.Context(), "data.tenants["); err == nil {
		t.Error("Presence() accepted a path that does not parse")
	}
	if _, err := data.Presence(t.Context(), "input.tenant"); err == nil {
		t.Error("Presence() accepted a path that reads no document")
	}
}

// Cutting a relation is how a pattern asks what that relation was granting,
// without ever deciding for itself what following it means. The data it is
// asked of has to come back untouched, or the second question of the pair would
// be asked against something the first one changed.
func TestWithoutCutsARelationAndLeavesTheOriginalAlone(t *testing.T) {
	data := fixtureData(t)

	cut, err := data.Without(t.Context(), "data.projects[_].parent")
	if err != nil {
		t.Fatalf("Without() error = %v", err)
	}

	before, err := data.Presence(t.Context(), "data.projects[_].parent")
	if err != nil {
		t.Fatalf("Presence() error = %v", err)
	}
	if len(before.Present) != 9 {
		t.Errorf("parents in the data = %d, want the 9 of the fixture", len(before.Present))
	}

	after, err := cut.Presence(t.Context(), "data.projects[_].parent")
	if err != nil {
		t.Fatalf("Presence() error = %v", err)
	}
	if len(after.Present) != 0 {
		t.Errorf("parents left after the cut = %v, want none", after.Present)
	}

	// The documents around the cut are still there: the copy is a copy of
	// everything, not a projection of what the caller asked about.
	members, err := cut.Presence(t.Context(), "data.projects[_].members")
	if err != nil {
		t.Fatalf("Presence() error = %v", err)
	}
	if len(members.Present) != 10 {
		t.Errorf("projects left after the cut = %d, want all 10", len(members.Present))
	}
}

// The modules come in through Load, which decides between the two syntaxes.
// Letting the data loader parse them too would compile the policy a second
// time without that decision, and on a v0 bundle it would fail outright.
func TestLoadDataSkipsRegoFiles(t *testing.T) {
	dir := writeSources(t, map[string]string{
		"users.json": `{"users": {"alice": {"tenant": "berq"}}}`,
		"legacy.rego": `package legacy

allow {
	input.user == "alice"
}
`,
	})

	data, err := LoadData([]string{dir})
	if err != nil {
		t.Fatalf("LoadData() error = %v, and the v0 module is what it tripped on", err)
	}
	if len(data.Files) != 1 || !strings.HasSuffix(data.Files[0], "users.json") {
		t.Errorf("documents = %v, want only the json one", data.Files)
	}
}

// The mount point of a document is the directory it sits in. It is a
// convention of OPA replicated here rather than reused, so it needs a test of
// its own: getting it wrong would put every document one level off, and the
// analysis would report a policy that reads nothing rather than an error.
func TestLoadDataMountsSubdirectoriesAsSegments(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "eu", "berq"), 0o750); err != nil {
		t.Fatalf("making the tree: %v", err)
	}
	write := func(path, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, path), []byte(content), 0o600); err != nil {
			t.Fatalf("writing %s: %v", path, err)
		}
	}
	write("users.json", `{"users": {"alice": {"tenant": "berq"}}}`)
	write(filepath.Join("eu", "berq", "settings.json"), `{"settings": {"open": true}}`)

	data, err := LoadData([]string{root})
	if err != nil {
		t.Fatalf("LoadData() error = %v", err)
	}
	if len(data.Files) != 2 {
		t.Fatalf("files = %v, want both documents", data.Files)
	}

	dir := writeSources(t, map[string]string{
		"policy.rego": `package t

# METADATA
# scope: document
# entrypoint: true
allow if {
	data.users.alice.tenant == "berq"
	data.eu.berq.settings.open == true
}
`,
	})
	bundle, err := Load([]string{dir}, ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	residuals, err := Residuals(t.Context(), bundle, data, Request{Decision: "data.t.allow"}, Limits{})
	if err != nil {
		t.Fatalf("Residuals() error = %v", err)
	}
	if !residuals.Always {
		t.Errorf("the decision does not hold, so a document did not land where opa eval -d puts it (%v)",
			residuals.Conditions)
	}
}

// Two documents that meet on a value would silently overwrite each other, and
// which one won would depend on the order the directory was read in.
func TestLoadDataRefusesOverlappingDocuments(t *testing.T) {
	dir := writeSources(t, map[string]string{
		"one.json": `{"settings": {"open": true}}`,
		"two.json": `{"settings": {"open": false}}`,
	})

	if _, err := LoadData([]string{dir}); err == nil {
		t.Error("LoadData() accepted two documents that overwrite each other")
	}
}

func TestLoadDataWithoutDocuments(t *testing.T) {
	if _, err := LoadData([]string{t.TempDir()}); !errors.Is(err, ErrNoData) {
		t.Errorf("LoadData() error = %v, want ErrNoData", err)
	}
}

func TestResidualsWithoutData(t *testing.T) {
	bundle, err := Load([]string{fixtureDir(t, "policy-v1")}, ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	_, err = Residuals(t.Context(), bundle, nil, Request{Decision: "data.quill.authz.allow"}, Limits{})
	if !errors.Is(err, ErrNoData) {
		t.Errorf("Residuals() error = %v, want ErrNoData", err)
	}
}

func TestResidualsOnAQueryThatDoesNotParse(t *testing.T) {
	bundle, err := Load([]string{fixtureDir(t, "policy-v1")}, ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	_, err = Residuals(t.Context(), bundle, fixtureData(t), Request{Decision: "data.quill.authz.["}, Limits{})
	if !errors.Is(err, ErrPartial) {
		t.Errorf("Residuals() error = %v, want ErrPartial", err)
	}
}

// The third signal of PTD-OPA-006, measured through the engine: the publishing
// decision grants to holders of "editor" and holders of "admin", and those are
// the two constants it compares carol's roles against. "publish" and "withdraw"
// are compared against input.action, not the document, and must not be
// collected: the pattern asks what would grant if the document changed, not
// what the rest of the request has to be.
func TestValuesComparedWithCollectsTheGrantingConstants(t *testing.T) {
	bundle, err := Load([]string{fixtureDir(t, "policy-v1")}, ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	values, err := ValuesComparedWith(t.Context(), bundle, fixtureData(t), Request{
		Decision: "data.quill.publish.allow",
		Unknowns: []string{"input.action", "input.doc"},
		Input:    map[string]any{"user": "carol"},
	}, "data.users.carol.roles")
	if err != nil {
		t.Fatalf("ValuesComparedWith() error = %v", err)
	}

	got := map[string]bool{}
	for _, value := range values {
		if !value.Membership {
			t.Errorf("%q collected as an equality, want membership: the document is `value in roles`", value.Text)
		}
		got[value.Text] = true
	}
	if len(values) != 2 || !got["editor"] || !got["admin"] {
		t.Errorf("values = %v, want editor and admin, and nothing compared against input", values)
	}
}

// The document written for the counter case has to leave the original data
// alone: the pattern evaluates the decision against the world as it stands and
// against a world where the write happened, and the two must not be the same
// map underneath.
func TestDataWithSetsADocumentAndLeavesTheOriginal(t *testing.T) {
	data := fixtureData(t)

	written, err := data.With(t.Context(), "data.users.carol.roles", []any{"support", "editor"})
	if err != nil {
		t.Fatalf("With() error = %v", err)
	}

	before, found, err := data.Value(t.Context(), "data.users.carol.roles")
	if err != nil || !found {
		t.Fatalf("Value() on the original = %v, %t", err, found)
	}
	if !reflect.DeepEqual(before, []any{"support"}) {
		t.Errorf("the original changed under us: carol holds %v, want [support]", before)
	}

	after, found, err := written.Value(t.Context(), "data.users.carol.roles")
	if err != nil || !found {
		t.Fatalf("Value() on the written data = %v, %t", err, found)
	}
	if !reflect.DeepEqual(after, []any{"support", "editor"}) {
		t.Errorf("the write did not take: carol holds %v, want [support editor]", after)
	}
}

// A path that names a collection rather than one document is not somewhere a
// write can land, and saying so beats writing to a place that is not a record.
func TestDataWithRefusesACollection(t *testing.T) {
	if _, err := fixtureData(t).With(t.Context(), "data.users[_].roles", []any{"editor"}); err == nil {
		t.Error("With() accepted a collection path, and a write lands on one record")
	}
}

// writeData writes one JSON document and loads it.
func writeData(t *testing.T, content string) *Data {
	t.Helper()

	data, err := LoadData([]string{writeSources(t, map[string]string{"data.json": content})})
	if err != nil {
		t.Fatalf("LoadData() error = %v", err)
	}
	return data
}

// A condition on constants is decided, and one that names anything left open,
// or calls something that answers differently each time, is left as it is: a
// call to http.send is never made.
func TestDecidedConditions(t *testing.T) {
	tests := []struct {
		condition string
		holds     bool
		closed    bool
	}{
		{condition: "count(set()) == 0", holds: true, closed: true},
		{condition: `count({"x"}) == 0`, holds: false, closed: true},
		{condition: "input.mfa == true", closed: false},
		{condition: "x := 1; x == 1", closed: false},
		{condition: "time.now_ns() > 0", closed: false},
		{condition: `is_object(http.send({"method": "get", "url": "https://petard-fixture.invalid"}))`, closed: false},
	}
	for _, tt := range tests {
		t.Run(tt.condition, func(t *testing.T) {
			holds, closed := decided(t.Context(), ast.MustParseBody(tt.condition))
			if closed != tt.closed || holds != tt.holds {
				t.Errorf("decided() = %v, %v, want %v, %v", holds, closed, tt.holds, tt.closed)
			}
		})
	}
}
