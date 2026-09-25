package opaengine

import (
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"
)

// The eleven paths below are copied from fixtures/vulnerable-bundle/EXPECTED.md
// section 6, word for word, captures included. The fixture declared them
// before this code existed, which is what makes them a criterion rather than a
// description of whatever the engine happens to produce.
var expectedFixturePaths = []string{
	"data.users.{u}.profile.department",
	"data.users.{u}.roles",
	"data.projects.{p}.members",
	"data.tenants.{t}.policy.require_mfa",
	"data.tenants.{t}.status",
	"data.documents.{d}.owner",
	"data.documents.{d}.project",
	"data.projects.{p}.department",
	"data.projects.{p}.parent",
	"data.settings.reading_room.open",
	"data.settings.console.enabled",
}

// asEnginePaths rewrites the captures of EXPECTED.md into the placeholder the
// engine uses. The names of the captures carry no meaning to match on: the
// write model spells the same positions {owner} and {project}, and a path
// matches on the shape of its segments, not on what they are called.
func asEnginePaths(declared []string) []string {
	converted := make([]string, 0, len(declared))
	for _, path := range declared {
		var built strings.Builder
		for i, segment := range strings.Split(path, ".") {
			switch {
			case strings.HasPrefix(segment, "{"):
				built.WriteString("[_]")
			case i == 0:
				built.WriteString(segment)
			default:
				built.WriteString("." + segment)
			}
		}
		converted = append(converted, built.String())
	}
	slices.Sort(converted)
	return converted
}

// TestReadsFindsExactlyTheDeclaredPaths is the criterion of this vertical
// slice. Not "find eleven paths", but "find these eleven".
func TestReadsFindsExactlyTheDeclaredPaths(t *testing.T) {
	for _, version := range []string{"policy-v1", "policy-v0"} {
		t.Run(version, func(t *testing.T) {
			bundle, err := Load([]string{fixtureDir(t, version)}, ParseModeAuto)
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}

			reads, err := Reads(bundle, Limits{})
			if err != nil {
				t.Fatalf("Reads() error = %v", err)
			}

			expected := asEnginePaths(expectedFixturePaths)
			if got := reads.Paths(); !slices.Equal(got, expected) {
				t.Errorf("paths found:\n  %v\nwant:\n  %v", got, expected)
			}
		})
	}
}

// The second measure, kept apart from the first on purpose.
//
// Twelve of the seventeen reads name a document the caller of the decision
// chooses. Three are chosen by the data: two index data.projects with a project
// that comes out of ancestors_of, which walks the hierarchy stored in data, and
// one iterates over data.projects in the head of parent_of. The last two name a
// document nobody chooses, the platform settings, which are the same whatever
// the request.
//
// None of them is unresolved, and that matters as much as the twelve.
// "The data picks it" is an answer, and it excludes those reads from the self
// write family with a reason; "I do not know" would leave them as maybes
// forever.
func TestReadsSeparatesProvenanceFromDiscovery(t *testing.T) {
	bundle, err := Load([]string{fixtureDir(t, "policy-v1")}, ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	reads, err := Reads(bundle, Limits{})
	if err != nil {
		t.Fatalf("Reads() error = %v", err)
	}

	counts := map[Provenance]int{
		ProvenanceInput:      12,
		ProvenanceData:       3,
		ProvenanceUnresolved: 0,
		ProvenanceBuiltin:    0,
		ProvenanceStatic:     2,
	}
	total := 0
	for provenance, expected := range counts {
		got := reads.CountWithProvenance(provenance)
		total += got
		if got != expected {
			t.Errorf("reads with provenance %s = %d, want %d", provenance, got, expected)
		}
	}
	if len(reads.Reads) != total {
		t.Errorf("reads = %d, but the provenances add up to %d", len(reads.Reads), total)
	}
	if len(reads.Reads) != 17 {
		t.Errorf("reads = %d, want 17: eleven distinct paths, roles read six times and the department twice", len(reads.Reads))
	}
}

// Every read has to be traceable back to a line of Rego, because that is what
// an analyst checks first when a finding shows up.
func TestReadsCarryTheirSource(t *testing.T) {
	bundle, err := Load([]string{fixtureDir(t, "policy-v1")}, ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	reads, err := Reads(bundle, Limits{})
	if err != nil {
		t.Fatalf("Reads() error = %v", err)
	}

	for _, read := range reads.Reads {
		if read.File == "" || read.Line == 0 || read.Rule == "" {
			t.Errorf("read %s has no source: file=%q line=%d rule=%q", read.Path, read.File, read.Line, read.Rule)
		}
		if !slices.Contains(bundle.Files, read.File) {
			t.Errorf("read %s names file %q, which is not one of the loaded files", read.Path, read.File)
		}
	}
}

// A value read to deny is not a value read to grant, and Rego says which is
// which in a bool. The taxonomy needs it, and it costs nothing to carry it
// along while the body is already being walked.
func TestReadsRecordNegation(t *testing.T) {
	reads := readsOf(t, `package t

# METADATA
# scope: document
# entrypoint: true
default allow := false

allow if {
	not data.blocklist[input.user]
	data.users[input.user].active
}
`, Limits{})

	if read := readOfPath(t, reads, "data.blocklist[_]"); !read.UnderNegation {
		t.Error("the read under not is not marked as negated")
	}
	if read := readOfPath(t, reads, "data.users[_].active"); read.UnderNegation {
		t.Error("a read outside a negation is marked as negated")
	}
}

// With the keywords imported, and, or and not are expressions holding bodies of
// their own, and every negation of the module takes that form, the plain one
// included. The reads inside them are reads like any other, and each keeps its
// side: a not flips it, a not inside a not flips it back, and and and or leave
// it where it is.
func TestReadsGoIntoAndOrAndNot(t *testing.T) {
	reads := readsOf(t, `package t

import future.keywords.and
import future.keywords.not
import future.keywords.or

# METADATA
# scope: document
# entrypoint: true
default allow := false

allow if {
	data.roles[input.user] == "admin" or data.groups[input.group].open
	data.flags.enabled and data.flags.visible
	not data.blocklist[input.user]
	not {
		data.suspended[input.user]
		not data.pardoned[input.user]
	}
	not banned
}

banned if data.bans[input.user]
`, Limits{})

	tests := []struct {
		path    string
		negated bool

		// wayDown is whether the rule holding the read is reached under a
		// negation, which a not holding a rule sets like any other.
		wayDown bool
	}{
		{path: "data.roles[_]", negated: false},
		{path: "data.groups[_].open", negated: false},
		{path: "data.flags.enabled", negated: false},
		{path: "data.flags.visible", negated: false},
		{path: "data.blocklist[_]", negated: true},
		{path: "data.suspended[_]", negated: true},
		{path: "data.pardoned[_]", negated: false},
		{path: "data.bans[_]", negated: false, wayDown: true},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			read := readOfPath(t, reads, tt.path)
			if read.UnderNegation != tt.negated {
				t.Errorf("UnderNegation = %v, want %v", read.UnderNegation, tt.negated)
			}
			expected := []ReachedDecision{{Name: "data.t.allow", UnderNegation: tt.wayDown}}
			if !slices.Equal(read.Decisions, expected) {
				t.Errorf("decisions = %v, want %v", read.Decisions, expected)
			}
		})
	}
}

// A count of the domain guards an every only where it has to hold. Next to the
// every, or in an operand of an and, it does; under a not it asks for the
// opposite, and in an operand of an or the other operand can hold instead.
func TestQuantifiersTakeAGuardOnlyWhereItHolds(t *testing.T) {
	reads := readsOf(t, `package t

import future.keywords.and
import future.keywords.not
import future.keywords.or

# METADATA
# scope: document
# entrypoint: true
plain if {
	count(input.reviews) > 0
	every review in input.reviews { review.approved }
}

# METADATA
# scope: document
# entrypoint: true
joined if {
	count(input.reviews) > 0 and input.ready
	every review in input.reviews { review.approved }
}

# METADATA
# scope: document
# entrypoint: true
either if {
	count(input.reviews) > 0 or input.trusted
	every review in input.reviews { review.approved }
}

# METADATA
# scope: document
# entrypoint: true
negated if {
	not count(input.reviews) > 0
	every review in input.reviews { review.approved }
}
`, Limits{})

	expected := map[string]bool{
		"data.t.plain":   true,
		"data.t.joined":  true,
		"data.t.either":  false,
		"data.t.negated": false,
	}
	seen := map[string]bool{}
	for _, quantifier := range reads.Quantifiers {
		for _, decision := range quantifier.Decisions {
			seen[decision.Name] = true
			if want, known := expected[decision.Name]; known && quantifier.Guarded != want {
				t.Errorf("%s: guarded = %v, want %v", decision.Name, quantifier.Guarded, want)
			}
		}
	}
	for name := range expected {
		if !seen[name] {
			t.Errorf("%s: no every found, so its guard was never judged", name)
		}
	}
}

// __local6__ is the truth and it is unreadable. The compiler keeps the names
// the author wrote for exactly this, and a report nobody can read is a report
// nobody checks.
func TestReadsUseTheAuthorsVariableNames(t *testing.T) {
	bundle, err := Load([]string{fixtureDir(t, "policy-v1")}, ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	reads, err := Reads(bundle, Limits{})
	if err != nil {
		t.Fatalf("Reads() error = %v", err)
	}

	for _, read := range reads.Reads {
		if strings.Contains(read.Ref, "__local") {
			t.Errorf("read %s still shows a generated variable: %s", read.Path, read.Ref)
		}
	}

	// The one inside is_member indexes by the parameter, and says so by name.
	for _, read := range reads.Reads {
		if read.Rule == "data.quill.authz.is_member" && read.Path == "data.users[_].profile.department" {
			if read.Ref != "data.users[user].profile.department" {
				t.Errorf("ref = %q, want data.users[user].profile.department", read.Ref)
			}
		}
	}
}

func TestReadsListsTheDecisions(t *testing.T) {
	bundle, err := Load([]string{fixtureDir(t, "policy-v1")}, ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	reads, err := Reads(bundle, Limits{})
	if err != nil {
		t.Fatalf("Reads() error = %v", err)
	}

	// Fifteen decisions: the three counter cases of PTD-OPA-005 are consumed by
	// the PEP like the others, PTD-OPA-006, 007 and 008 add two each, and
	// PTD-OPA-009 and 010 add one each, which holds the case and the counter
	// case. Leaving any of them unannotated made the engine ignore them, so a
	// counter case "the engine must not flag" was satisfied for the wrong reason
	// and a case "it must flag" could not be satisfied at all.
	expected := []string{
		"data.quill.admin.allow",
		"data.quill.authz.allow",
		"data.quill.enrichment.allow",
		"data.quill.platform.allow_audit_log",
		"data.quill.platform.allow_console",
		"data.quill.platform.allow_reading_room",
		"data.quill.publish.allow",
		"data.quill.review.allow_guarded",
		"data.quill.review.allow_unguarded",
		"data.quill.risk.allow_default_option",
		"data.quill.risk.allow_defensive",
		"data.quill.risk.allow_positive_side",
		"data.quill.risk.allow_vulnerable",
		"data.quill.tenant_policy.allow",
		"data.quill.tenant_policy.allow_export",
	}
	if !slices.Equal(reads.Decisions, expected) {
		t.Errorf("decisions = %v, want %v", reads.Decisions, expected)
	}
}

// A read carries the decisions it feeds and how it feeds them, which is the
// half of the negation that Expr.Negated cannot answer. Nothing inside
// denied_mfa says that the only way down to it goes through a not, and that is
// exactly what makes the check it performs skippable when the document is
// missing.
//
// The default of the rule travels with it for the same reason: it is what
// decides whether an undefined body stays silent or answers no, and it lives in
// a sibling rule that a read has no other way of reaching.
func TestReadsCarryTheDecisionsTheyReach(t *testing.T) {
	tests := []struct {
		name          string
		rule          string
		path          string
		decision      string
		underNegation bool
		ruleDefault   string
	}{
		{
			name:          "a deny rule the decision negates",
			rule:          "data.quill.tenant_policy.denied_mfa",
			path:          "data.tenants[_].policy.require_mfa",
			decision:      "data.quill.tenant_policy.allow",
			underNegation: true,
			ruleDefault:   "",
		},
		{
			name:          "the decision reading for itself",
			rule:          "data.quill.authz.allow",
			path:          "data.users[_].roles",
			decision:      "data.quill.authz.allow",
			underNegation: false,
			ruleDefault:   "false",
		},
		{
			name:          "a helper the decision calls",
			rule:          "data.quill.authz.is_member",
			path:          "data.projects[_].members",
			decision:      "data.quill.authz.allow",
			underNegation: false,
			ruleDefault:   "",
		},
	}

	bundle, err := Load([]string{fixtureDir(t, "policy-v1")}, ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	reads, err := Reads(bundle, Limits{})
	if err != nil {
		t.Fatalf("Reads() error = %v", err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			read := oneRead(t, reads, tt.rule+" reading "+tt.path, func(read Read) bool {
				return read.Rule == tt.rule && read.Path == tt.path
			})
			if read.RuleDefault != tt.ruleDefault {
				t.Errorf("rule default = %q, want %q", read.RuleDefault, tt.ruleDefault)
			}

			expected := []ReachedDecision{{Name: tt.decision, UnderNegation: tt.underNegation}}
			if !slices.Equal(read.Decisions, expected) {
				t.Errorf("decisions = %v, want %v", read.Decisions, expected)
			}
		})
	}
}

// A hierarchy in Rego cannot be a rule that calls itself, so it is a call to
// one of a small set of builtins, and the relation it follows is whatever the
// rule building the adjacency list reads. Both halves have to come out of the
// walk: the call alone would say a hierarchy exists, and the relation is what
// makes it measurable.
func TestReadsFindsTheTransitiveConstruct(t *testing.T) {
	for _, version := range []string{"policy-v1", "policy-v0"} {
		t.Run(version, func(t *testing.T) {
			bundle, err := Load([]string{fixtureDir(t, version)}, ParseModeAuto)
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			reads, err := Reads(bundle, Limits{})
			if err != nil {
				t.Fatalf("Reads() error = %v", err)
			}

			if len(reads.Closures) != 1 {
				t.Fatalf("closures = %v, want the one of the fixture", reads.Closures)
			}
			closure := reads.Closures[0]

			if closure.Builtin != "graph.reachable" {
				t.Errorf("builtin = %q, want graph.reachable", closure.Builtin)
			}
			if closure.Rule != "data.quill.authz.ancestors_of" {
				t.Errorf("rule = %q, want the function holding the call", closure.Rule)
			}
			if expected := []string{"data.projects[_].parent"}; !slices.Equal(closure.Relation, expected) {
				t.Errorf("relation = %v, want %v: it is what the adjacency rule reads", closure.Relation, expected)
			}
			expected := []ReachedDecision{{Name: "data.quill.authz.allow"}}
			if !slices.Equal(closure.Decisions, expected) {
				t.Errorf("decisions = %v, want %v", closure.Decisions, expected)
			}
			if closure.Line == 0 {
				t.Error("the closure carries no line, so a report cannot point at it")
			}
		})
	}
}

// The seed of the walk is reported only where the policy writes it out. In the
// idiomatic form it is the parameter of the function holding the call, which
// the compiler has renamed, and a generated name in a report reads as a defect
// in the tool.
func TestReadsLeavesAGeneratedSeedUnreported(t *testing.T) {
	bundle, err := Load([]string{fixtureDir(t, "policy-v1")}, ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	reads, err := Reads(bundle, Limits{})
	if err != nil {
		t.Fatalf("Reads() error = %v", err)
	}

	if seed := reads.Closures[0].Seed; seed != "" {
		t.Errorf("seed = %q, want none: the fixture seeds the walk with a parameter", seed)
	}
}

// A reference can turn into a rule while being substituted, and then it is not
// a read of anything.
//
// Found on the gatekeeper-library corpus, on the shape half of it is written
// in: a container is bound from a rule and then a field of it is checked, which
// substituted to data.pkg.input_containers[_].securityContext.privileged and was
// counted as a path under data. No store holds that path, nobody can be
// declared to write it, and every number measured over the corpus carried it.
func TestReadsIgnoresFieldsOfARuleTheBundleComputes(t *testing.T) {
	dir := writeSources(t, map[string]string{
		"policy.rego": `package t

# METADATA
# scope: document
# entrypoint: true
default deny := false

deny if {
	data.settings.strict
	container := containers[_]
	container.securityContext.privileged
}

containers contains container if {
	container := input.review.object.spec.containers[_]
}
`,
	})
	bundle, err := Load([]string{dir}, ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	reads, err := Reads(bundle, Limits{})
	if err != nil {
		t.Fatalf("Reads() error = %v", err)
	}

	// The genuine read stays, which is what says the fix removed a wrong claim
	// and not the analysis of the rule.
	if paths := reads.Paths(); !slices.Equal(paths, []string{"data.settings.strict"}) {
		t.Errorf("Paths() = %v, want [data.settings.strict]: containers is computed, not stored", paths)
	}
	if !slices.Contains(reads.Decisions, "data.t.deny") {
		t.Errorf("Decisions = %v, want the annotated entrypoint", reads.Decisions)
	}
}

func TestReadsWithoutEntrypoints(t *testing.T) {
	dir := writeSources(t, map[string]string{
		"policy.rego": "package t\n\nallow if data.users[input.user].active\n",
	})
	bundle, err := Load([]string{dir}, ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if _, err := Reads(bundle, Limits{}); !errors.Is(err, ErrNoDecisions) {
		t.Errorf("Reads() error = %v, want ErrNoDecisions", err)
	}
}

// gatekeeperShaped is the form whole families of Rego are written in: a partial
// set whose non emptiness denies, in Rego v0, with no annotation anywhere.
const gatekeeperShaped = `package t

violation[{"msg": msg}] {
	not data.settings.exempt[input.name]
	msg := "not allowed"
}
`

// A policy that annotates nothing is the normal case outside the fixture, and
// there are only three ways to treat it: guess, refuse, or let it be declared.
// Declaring is what opa build offers with -e, so it is what this offers, in
// both the spelling a report prints and the spelling that CLI takes.
func TestReadsFromADeclaredEntrypoint(t *testing.T) {
	tests := []struct {
		name     string
		declared string
	}{
		{name: "spelled the way a report prints it", declared: "data.t.violation"},
		{name: "spelled the way opa build takes it", declared: "t/violation"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeSources(t, map[string]string{"policy.rego": gatekeeperShaped})
			bundle, err := Load([]string{dir}, ParseModeAuto)
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			bundle.Entrypoints = []string{tt.declared}

			reads, err := Reads(bundle, Limits{})
			if err != nil {
				t.Fatalf("Reads() error = %v", err)
			}
			if !slices.Equal(reads.Decisions, []string{"data.t.violation"}) {
				t.Errorf("Decisions = %v, want [data.t.violation]", reads.Decisions)
			}
			if !slices.Equal(reads.Paths(), []string{"data.settings.exempt[_]"}) {
				t.Errorf("Paths() = %v, want the one read of the rule", reads.Paths())
			}
		})
	}
}

// A decision can be a document that rules with a reference in their head build
// together, the way allow["decision"] builds data.authzen.allow. opa build takes
// that document as an entrypoint, so it is taken here too.
func TestReadsFromADeclaredDocumentBuiltByRefHeads(t *testing.T) {
	dir := writeSources(t, map[string]string{
		"policy.rego": `package authzen

default allow["decision"] := false

allow["decision"] if "admin" in data.users[input.subject.id].roles
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
	if !slices.Equal(reads.Decisions, []string{"data.authzen.allow.decision"}) {
		t.Errorf("Decisions = %v, want the rules that build the document", reads.Decisions)
	}
	if !slices.Equal(reads.Paths(), []string{"data.users[_].roles"}) {
		t.Errorf("Paths() = %v, want the read indexed by the subject", reads.Paths())
	}
}

// A decision can be a field of what a rule returns, when the rule answers with
// an object and the enforcement point reads one field of it, the way AWX reads
// allowed. The walk starts from the rule, and the decision keeps the name it is
// asked at.
func TestReadsFromADeclaredFieldOfWhatARuleReturns(t *testing.T) {
	tests := []struct {
		name     string
		declared string
	}{
		{name: "spelled the way a report prints it", declared: "data.t.decision.allowed"},
		{name: "spelled the way opa build takes it", declared: "t/decision/allowed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeSources(t, map[string]string{
				"policy.rego": `package t

violations contains "the gate is shut" if not data.settings.open

decision := {"allowed": count(violations) == 0, "violations": [v | some v in violations]}
`,
			})
			bundle, err := Load([]string{dir}, ParseModeAuto)
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			bundle.Entrypoints = []string{tt.declared}

			reads, err := Reads(bundle, Limits{})
			if err != nil {
				t.Fatalf("Reads() error = %v", err)
			}
			if !slices.Equal(reads.Decisions, []string{"data.t.decision.allowed"}) {
				t.Errorf("Decisions = %v, want the field", reads.Decisions)
			}
			if len(reads.Reads) != 1 || reads.Reads[0].Path != "data.settings.open" {
				t.Fatalf("Reads = %+v, want the one read of the rule the field comes from", reads.Reads)
			}
			reached := reads.Reads[0].Decisions
			if len(reached) != 1 || reached[0].Name != "data.t.decision.allowed" {
				t.Errorf("the read reaches %+v, want the field", reached)
			}
		})
	}
}

// object.get reads the document it lands on, the same as the path written out:
// a lookup keyed by the subject is picked by the subject, and a setting read
// with a default is that setting and not the whole of the settings. What a call
// returned is not followed into a second call.
func TestReadsFollowObjectGetIntoData(t *testing.T) {
	dir := writeSources(t, map[string]string{
		"policy.rego": `package t

# METADATA
# scope: document
# entrypoint: true
allow if {
	"admin" in object.get(data.users, [input.user, "roles"], [])
	object.get(data.settings, ["console", "enabled"], false)
	count(object.get(object.get(data.teams, input.team, {}), "members", [])) > 0
}
`,
	})
	bundle, err := Load([]string{dir}, ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	reads, err := Reads(bundle, Limits{})
	if err != nil {
		t.Fatalf("Reads() error = %v", err)
	}

	provenance := map[string]Provenance{}
	for _, read := range reads.Reads {
		provenance[read.Path] = read.Provenance
	}
	expected := map[string]Provenance{
		"data.settings.console.enabled": ProvenanceStatic,
		"data.teams[_]":                 ProvenanceInput,
		"data.users[_].roles":           ProvenanceInput,
	}
	if !maps.Equal(provenance, expected) {
		t.Errorf("reads = %v, want %v", provenance, expected)
	}

	indexed := SubjectIndexedReads(RecognizeShape(reads), reads)
	if len(indexed) != 1 || indexed[0].Path != "data.users[_].roles" {
		t.Errorf("indexed by the subject = %v, want the roles of whoever asks", indexed)
	}
}

// violationsPolicy is a check written as a violation, the form a decision takes
// when it answers with its violations as well as with a verdict.
const violationsPolicy = `package t

violations contains "multi-factor authentication is required" if {
	data.tenants[input.tenant].policy.require_mfa == true
	not input.mfa
}

decision := {"allowed": count(violations) == 0, "violations": [v | some v in violations]}

allow_when_none if count(violations) == 0

allow_when_empty if violations == set()

deny_when_some if count(violations) > 0

deny_when_not_none if not count(violations) == 0

deny_when_not_empty if not violations == set()
`

// Counting nothing is asking for nothing: a decision that grants on
// count(violations) == 0 denies through every violation, since a partial set
// exists even when it is empty. The list of violations in the same answer
// reaches the rule with no negation, and is left out of the field the
// enforcement point reads; asked as a whole, the answer lists them, and the
// check is no longer only on the side that denies. A not in front of the
// comparison asks for something again, and the two negations cancel out.
func TestReadsTakeCountingNothingAsANegation(t *testing.T) {
	tests := []struct {
		declared string
		negated  bool
	}{
		{declared: "data.t.decision.allowed", negated: true},
		{declared: "data.t.decision", negated: false},
		{declared: "data.t.allow_when_none", negated: true},
		{declared: "data.t.allow_when_empty", negated: true},
		{declared: "data.t.deny_when_some", negated: false},
		{declared: "data.t.deny_when_not_none", negated: false},
		{declared: "data.t.deny_when_not_empty", negated: false},
	}
	for _, tt := range tests {
		t.Run(tt.declared, func(t *testing.T) {
			bundle, err := Load([]string{writeSources(t, map[string]string{"policy.rego": violationsPolicy})}, ParseModeAuto)
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			bundle.Entrypoints = []string{tt.declared}
			reads, err := Reads(bundle, Limits{})
			if err != nil {
				t.Fatalf("Reads() error = %v", err)
			}

			read := readOfPath(t, reads, "data.tenants[_].policy.require_mfa")
			if len(read.Decisions) != 1 || read.Decisions[0].Name != tt.declared {
				t.Fatalf("the check reaches %+v, want %s alone", read.Decisions, tt.declared)
			}
			if read.Decisions[0].UnderNegation != tt.negated {
				t.Errorf("under negation = %v, want %v", read.Decisions[0].UnderNegation, tt.negated)
			}
		})
	}
}

// Two negations on the way down cancel out. A check written as violations with
// an exemption inside grants through the exemption: the exemption holding takes
// a violation away, and no violation is what the decision asks for. The side is
// the parity of the negations met on the way.
func TestReadsCountNegationsByParity(t *testing.T) {
	reads := readsOf(t, `package t

# METADATA
# scope: document
# entrypoint: true
allow if count(violations) == 0

violations contains "the image is not allowed" if {
	some container in input.containers
	data.settings.enforced
	not allowed_image(container.image)
	not exempt
}

allowed_image(image) if startswith(image, data.registries[_])

exempt if data.exemptions[input.namespace]
`, Limits{})

	tests := []struct {
		path    string
		negated bool
	}{
		{path: "data.settings.enforced", negated: true},
		{path: "data.registries[_]", negated: false},
		{path: "data.exemptions[_]", negated: false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			read := readOfPath(t, reads, tt.path)
			expected := []ReachedDecision{{Name: "data.t.allow", UnderNegation: tt.negated}}
			if !slices.Equal(read.Decisions, expected) {
				t.Errorf("decisions = %v, want %v", read.Decisions, expected)
			}
		})
	}
}

// denyingPolicy is a check written the way an admission controller queries
// one: a set of violations, with an exemption inside.
const denyingPolicy = `package t

violation contains "the image is not allowed" if {
	some container in input.containers
	data.settings.enforced
	not exempt
}

exempt if data.exemptions[input.namespace]

allow if count(violation) == 0
`

// A decision can deny: Gatekeeper refuses the request when violation returns
// anything, and conftest when deny does. Declared that way, the side of a read
// is counted from the side that denies, and it comes out the same as for the
// decision that grants on no violation. Declared the other way, the same rule
// is read as granting whatever it collects.
func TestReadsFromADecisionThatDenies(t *testing.T) {
	tests := []struct {
		name    string
		declare func(*Bundle)
		denying []string
		negated map[string]bool
	}{
		{
			name:    "declared to deny",
			declare: func(b *Bundle) { b.DenyEntrypoints = []string{"t/violation"} },
			denying: []string{"data.t.violation"},
			negated: map[string]bool{"data.settings.enforced": true, "data.exemptions[_]": false},
		},
		{
			name:    "the decision that grants on none",
			declare: func(b *Bundle) { b.Entrypoints = []string{"data.t.allow"} },
			negated: map[string]bool{"data.settings.enforced": true, "data.exemptions[_]": false},
		},
		{
			name:    "declared to grant",
			declare: func(b *Bundle) { b.Entrypoints = []string{"t/violation"} },
			negated: map[string]bool{"data.settings.enforced": false, "data.exemptions[_]": true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bundle, err := Load([]string{writeSources(t, map[string]string{"policy.rego": denyingPolicy})}, ParseModeAuto)
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			tt.declare(bundle)
			reads, err := Reads(bundle, Limits{})
			if err != nil {
				t.Fatalf("Reads() error = %v", err)
			}

			if !slices.Equal(reads.Denying, tt.denying) {
				t.Errorf("Denying = %v, want %v", reads.Denying, tt.denying)
			}
			for _, decision := range reads.Decisions {
				if reads.Denies(decision) != slices.Contains(tt.denying, decision) {
					t.Errorf("Denies(%s) = %v", decision, reads.Denies(decision))
				}
			}
			negated := map[string]bool{}
			for _, read := range reads.Reads {
				for _, decision := range read.Decisions {
					negated[read.Path] = decision.UnderNegation
				}
			}
			if !maps.Equal(negated, tt.negated) {
				t.Errorf("under negation = %v, want %v", negated, tt.negated)
			}
		})
	}
}

// A rule the policy annotates, or the caller declares, and also declares to
// deny is one decision, and it denies: the first two say it is queried, and
// the third says how its answer is read.
func TestReadsTakeTheDeclarationToDenyAlongWithTheOthers(t *testing.T) {
	const policy = `package t

# METADATA
# scope: document
# entrypoint: true
deny contains "blocked" if data.blocklist[input.user]
`
	tests := []struct {
		name        string
		entrypoints []string
	}{
		{name: "annotated", entrypoints: nil},
		{name: "annotated and declared", entrypoints: []string{"t/deny"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bundle, err := Load([]string{writeSources(t, map[string]string{"policy.rego": policy})}, ParseModeAuto)
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			bundle.Entrypoints = tt.entrypoints
			bundle.DenyEntrypoints = []string{"data.t.deny"}
			reads, err := Reads(bundle, Limits{})
			if err != nil {
				t.Fatalf("Reads() error = %v", err)
			}

			if !slices.Equal(reads.Decisions, []string{"data.t.deny"}) || !slices.Equal(reads.Denying, reads.Decisions) {
				t.Fatalf("Decisions = %v, Denying = %v, want the one rule, denying", reads.Decisions, reads.Denying)
			}
			expected := []ReachedDecision{{Name: "data.t.deny", UnderNegation: true}}
			if read := readOfPath(t, reads, "data.blocklist[_]"); !slices.Equal(read.Decisions, expected) {
				t.Errorf("decisions = %v, want %v", read.Decisions, expected)
			}
		})
	}
}

// A declaration to deny that matches nothing is a typo like any other.
func TestReadsRefusesADecisionToDenyItCannotFind(t *testing.T) {
	bundle, err := Load([]string{writeSources(t, map[string]string{"policy.rego": denyingPolicy})}, ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	bundle.DenyEntrypoints = []string{"t/violations"}
	if _, err := Reads(bundle, Limits{}); !errors.Is(err, ErrNoSuchEntrypoint) {
		t.Errorf("Reads() error = %v, want ErrNoSuchEntrypoint", err)
	}
}

// The field an enforcement point reads depends on what can make the rule fail,
// whatever field it computes, and not on a list only another field holds. A
// setting read inside that list is no read of the decision; one read to fill
// in another field is, since without it the rule has no fields at all.
func TestReadsOfAFieldLeaveOutWhatOnlyBuildsAnother(t *testing.T) {
	dir := writeSources(t, map[string]string{
		"policy.rego": `package t

violations contains "blocked" if data.blocklist[input.user]

decision := {
	"allowed": count(violations) == 0,
	"violations": [v | some v in violations; data.settings.verbose],
	"contact": data.settings.contact,
}
`,
	})
	bundle, err := Load([]string{dir}, ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	bundle.Entrypoints = []string{"data.t.decision.allowed"}
	reads, err := Reads(bundle, Limits{})
	if err != nil {
		t.Fatalf("Reads() error = %v", err)
	}

	if !slices.Equal(reads.Paths(), []string{"data.blocklist[_]", "data.settings.contact"}) {
		t.Errorf("Paths() = %v, want the check and the setting the answer cannot do without", reads.Paths())
	}
	if read := readOfPath(t, reads, "data.blocklist[_]"); !read.Decisions[0].UnderNegation {
		t.Error("the blocklist reaches the answer without a negation, and it only ever denies")
	}
}

// A declaration that matches nothing is a typo, and taking it as zero decisions
// would report a policy nobody looked at as a policy that reads nothing.
func TestReadsRefusesEntrypointsItCannotUse(t *testing.T) {
	tests := []struct {
		name     string
		declared string
		expected error
	}{
		{name: "names no rule", declared: "data.t.allow", expected: ErrNoSuchEntrypoint},
		{name: "names a rule of no package", declared: "violation", expected: ErrNoSuchEntrypoint},
		{name: "names a package rather than a document in it", declared: "data.t", expected: ErrNoSuchEntrypoint},
		{name: "names more than one document", declared: "data.t.violation[_]", expected: ErrBadEntrypoint},
		{name: "is not a reference at all", declared: "data.t.", expected: ErrBadEntrypoint},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeSources(t, map[string]string{"policy.rego": gatekeeperShaped})
			bundle, err := Load([]string{dir}, ParseModeAuto)
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			bundle.Entrypoints = []string{tt.declared}

			if _, err := Reads(bundle, Limits{}); !errors.Is(err, tt.expected) {
				t.Errorf("Reads() error = %v, want %v", err, tt.expected)
			}
		})
	}
}

// The two sources of decisions add up rather than one silencing the other,
// which is what OPA does with an entrypoint given on the command line next to
// an annotated one.
func TestReadsMergesDeclaredAndAnnotatedEntrypoints(t *testing.T) {
	dir := writeSources(t, map[string]string{
		"policy.rego": `package t

# METADATA
# scope: document
# entrypoint: true
allow if data.users[input.user].active

violation contains msg if {
	not data.settings.exempt[input.name]
	msg := "not allowed"
}
`,
	})
	bundle, err := Load([]string{dir}, ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	// The same decision declared twice, and in both spellings, is one decision.
	bundle.Entrypoints = []string{"data.t.violation", "t/violation"}

	reads, err := Reads(bundle, Limits{})
	if err != nil {
		t.Fatalf("Reads() error = %v", err)
	}
	if !slices.Equal(reads.Decisions, []string{"data.t.allow", "data.t.violation"}) {
		t.Errorf("Decisions = %v, want both, once each", reads.Decisions)
	}
}

// RulesNamed states a fact and decides nothing: that a rule called violation is
// a decision is a convention of whoever deploys OPA, and the engine is not the
// place where that convention is applied.
func TestRulesNamed(t *testing.T) {
	dir := writeSources(t, map[string]string{
		"policy.rego": gatekeeperShaped,
		"lib.rego": `package lib.exempt

is_exempt(name) {
	name == "kube-system"
}
`,
	})
	bundle, err := Load([]string{dir}, ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if found := bundle.RulesNamed("violation"); !slices.Equal(found, []string{"data.t.violation"}) {
		t.Errorf("RulesNamed(violation) = %v, want [data.t.violation]", found)
	}
	if found := bundle.RulesNamed("allow"); len(found) != 0 {
		t.Errorf("RulesNamed(allow) = %v, want none", found)
	}
}

// A rule that only a with modifier reaches is test scaffolding wearing the
// clothes of a policy. It is left out of the decisions, and listed, so that
// leaving it out stays visible.
func TestReadsSkipsRulesReachedOnlyUnderWith(t *testing.T) {
	dir := writeSources(t, map[string]string{
		"policy.rego": `package t

# METADATA
# scope: document
# entrypoint: true
default check := false

check if mocked with input as {"user": "mallory"}

mocked if data.users[input.user].active
`,
	})
	bundle, err := Load([]string{dir}, ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	reads, err := Reads(bundle, Limits{})
	if err != nil {
		t.Fatalf("Reads() error = %v", err)
	}

	if len(reads.Reads) != 0 {
		t.Errorf("reads = %v, want none: the only read is behind a with", reads.Reads)
	}
	if !slices.Equal(reads.SkippedUnderWith, []string{"data.t.mocked"}) {
		t.Errorf("SkippedUnderWith = %v, want [data.t.mocked]", reads.SkippedUnderWith)
	}
}

// Turning a path everybody shares into one person's document is what lets a
// pattern ask about that person, and the result has to be a reference OPA will
// parse: a key that is not a bare name comes back quoted rather than pasted in.
func TestDocumentPath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		at       int
		key      string
		expected string
	}{
		{
			name:     "a bare name",
			path:     "data.users[_].profile.department",
			at:       2,
			key:      "mallory",
			expected: "data.users.mallory.profile.department",
		},
		{
			name:     "a key that is not an identifier",
			path:     "data.users[_].roles",
			at:       2,
			key:      "a-b",
			expected: `data.users["a-b"].roles`,
		},
		{
			name:     "the collection itself",
			path:     "data.users[_]",
			at:       2,
			key:      "dave",
			expected: "data.users.dave",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			document, err := DocumentPath(tt.path, tt.at, tt.key)
			if err != nil {
				t.Fatalf("DocumentPath() error = %v", err)
			}
			if document != tt.expected {
				t.Errorf("DocumentPath() = %q, want %q", document, tt.expected)
			}
		})
	}
}

// A position that belongs to another path is a mistake worth stopping for: a
// document built from it would be about somebody else, and the measurement
// taken against it would look like an answer.
func TestDocumentPathRefusesAPositionThatIsNotThere(t *testing.T) {
	for _, at := range []int{0, 9} {
		if _, err := DocumentPath("data.users[_].roles", at, "dave"); err == nil {
			t.Errorf("DocumentPath() accepted position %d", at)
		}
	}
	if _, err := DocumentPath("data.users[", 2, "dave"); err == nil {
		t.Error("DocumentPath() accepted a path that does not parse")
	}
}
