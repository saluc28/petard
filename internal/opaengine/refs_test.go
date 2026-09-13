package opaengine

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// The nine paths below are copied from fixtures/vulnerable-bundle/EXPECTED.md
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
// slice. Not "find nine paths", but "find these nine".
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
// Seven of the ten reads name a document the caller of the decision chooses.
// The other three are chosen by the data: two index data.projects with a
// project that comes out of ancestors_of, which walks the hierarchy stored in
// data, and one iterates over data.projects in the head of parent_of.
//
// None of the three is unresolved, and that matters as much as the seven.
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
		ProvenanceInput:      7,
		ProvenanceData:       3,
		ProvenanceUnresolved: 0,
		ProvenanceBuiltin:    0,
		ProvenanceStatic:     0,
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
	if len(reads.Reads) != 10 {
		t.Errorf("reads = %d, want 10: nine distinct paths, one of which is read twice", len(reads.Reads))
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

	// Seven, not four: the three counter cases of PTD-OPA-005 are decisions
	// the PEP consumes like the others. Leaving them unannotated made the
	// engine ignore them, so "the engine must not flag allow_defensive" was
	// satisfied for the wrong reason, and "it must flag allow_default_option"
	// could not be satisfied at all.
	expected := []string{
		"data.quill.authz.allow",
		"data.quill.enrichment.allow",
		"data.quill.risk.allow_default_option",
		"data.quill.risk.allow_defensive",
		"data.quill.risk.allow_positive_side",
		"data.quill.risk.allow_vulnerable",
		"data.quill.tenant_policy.allow",
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
