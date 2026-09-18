package opaengine

import (
	"slices"
	"strings"
	"testing"
)

// What a call asked to happen when it fails is read from the request, and it is
// the difference between a deployment that still has a switch for noticing the
// failure and one that has none. A request the policy computes is reported as
// unknown, because assuming the default would claim a mitigation exists without
// having read anything that says so.
func TestTaintsReadWhatACallAsksOnFailure(t *testing.T) {
	tests := []struct {
		name     string
		before   string
		request  string
		expected ErrorHandling
		endpoint string
	}{
		{
			name:     "the call suppresses its errors",
			request:  `{"method": "GET", "url": "https://a.invalid", "raise_error": false}`,
			expected: ErrorHandlingSuppressed,
			endpoint: "https://a.invalid",
		},
		{
			name:     "the call says nothing about them",
			request:  `{"method": "GET", "url": "https://a.invalid"}`,
			expected: ErrorHandlingDefault,
			endpoint: "https://a.invalid",
		},
		{
			name:     "the call asks for them",
			request:  `{"method": "GET", "url": "https://a.invalid", "raise_error": true}`,
			expected: ErrorHandlingDefault,
			endpoint: "https://a.invalid",
		},
		{
			name:     "the option is computed",
			request:  `{"method": "GET", "url": "https://a.invalid", "raise_error": input.strict}`,
			expected: ErrorHandlingUnknown,
			endpoint: "https://a.invalid",
		},
		{
			// A request built above the call and passed by name is the same
			// request, only not written in one line, and the resolver already
			// knows how to follow that step.
			name:     "the request is passed by name",
			before:   `request := {"method": "GET", "url": "https://a.invalid", "raise_error": false}`,
			request:  "request",
			expected: ErrorHandlingSuppressed,
			endpoint: "https://a.invalid",
		},
		{
			name:     "the request itself is computed",
			before:   `request := object.union({"method": "GET"}, input.request)`,
			request:  "request",
			expected: ErrorHandlingUnknown,
			endpoint: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeSources(t, map[string]string{
				"policy.rego": `package t

# METADATA
# scope: document
# entrypoint: true
default allow := false

allow if {
	` + tt.before + `
	answer := http.send(` + tt.request + `)
	answer.body.ok == true
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

			if len(reads.Taints) != 1 {
				t.Fatalf("taints = %v, want the one call", reads.Taints)
			}
			if got := reads.Taints[0].Errors; got != tt.expected {
				t.Errorf("error handling = %s, want %s", got, tt.expected)
			}
			if got := reads.Taints[0].Endpoint; got != tt.endpoint {
				t.Errorf("endpoint = %q, want %q: it is read from the same request object", got, tt.endpoint)
			}
		})
	}
}

// The fixture is built around one distinction, and this is it: two rules call
// the same builtin, and only one of them contributes to a decision. The seven
// values below are what the engine measures, and the two that reach a decision
// in a position to grant are the ones a pattern can act on.
func TestTaintsOnFixture(t *testing.T) {
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

			// The measure the fixture is checked against must not move because
			// a second measure was added next to it: a tainted value names no
			// document under data, so it is not one of the seventeen reads.
			if len(reads.Reads) != 17 || len(reads.Paths()) != 11 {
				t.Errorf("reads = %d over %d paths, want 17 over 11: taints must not be counted as reads",
					len(reads.Reads), len(reads.Paths()))
			}

			if len(reads.Taints) != 7 {
				t.Fatalf("taints = %d, want 7:\n%v", len(reads.Taints), reads.Taints)
			}

			var granting []string
			for _, taint := range reads.Taints {
				if taint.Origin != "http.send" {
					t.Errorf("taint in %s comes from %q, want http.send", taint.Rule, taint.Origin)
				}
				if taint.Grants() {
					granting = append(granting, taint.Rule)
				}
			}
			slices.Sort(granting)

			expected := []string{"data.quill.enrichment.allow", "data.quill.risk.allow_positive_side"}
			if !slices.Equal(granting, expected) {
				t.Errorf("values reaching a decision to grant = %v, want %v", granting, expected)
			}
		})
	}
}

// The case of PTD-OPA-004: which decision depends on which endpoint. Naming the
// endpoint is the whole point of the pattern, because that host is what ends up
// in the graph as an actor next to the real users.
func TestTaintsNameTheEndpointOfTheFixtureCase(t *testing.T) {
	reads := fixtureReads(t)

	taint := taintOfRule(t, reads, "data.quill.enrichment.allow")
	if taint.Ref != "enrichment.body.clearance" {
		t.Errorf("ref = %q, want enrichment.body.clearance", taint.Ref)
	}
	if taint.Endpoint != "https://idp.petard-fixture.invalid/attrs" {
		t.Errorf("endpoint = %q, want the url written in the call", taint.Endpoint)
	}
	if taint.File == "" || taint.Line == 0 {
		t.Errorf("taint has no source: file=%q line=%d", taint.File, taint.Line)
	}
	if len(taint.Decisions) != 1 || taint.Decisions[0].Name != "data.quill.enrichment.allow" {
		t.Fatalf("decisions = %v, want the enrichment decision alone", taint.Decisions)
	}
	if taint.Decisions[0].UnderNegation {
		t.Error("the decision reads the value to grant, and it is reported as denying")
	}
}

// The counter case of the fixture, audit_trace, calls the same builtin and is
// never reported. The reason has to be the right one, and on the fixture alone
// it cannot be told apart from an engine that simply never looked: nothing
// reaches audit_trace, so the walk does not visit it.
//
// So the same shape is put under the engine twice. Once as the fixture has it,
// where the telemetry rule hangs off nothing, and once with a decision that
// depends on it. If the second variant were silent too, the silence of the
// first would prove nothing at all.
func TestTaintsNeedTheValueToReachADecision(t *testing.T) {
	const decision = `package t

# METADATA
# scope: document
# entrypoint: true
default allow := false

allow if {
	enrichment := http.send({"method": "GET", "url": "https://idp.invalid/attrs"})
	enrichment.body.clearance == "high"
}
`
	const telemetry = `
telemetry := trace_id if {
	response := http.send({"method": "GET", "url": "https://logs.invalid/trace"})
	trace_id := response.body.trace_id
}
`

	unreached := readsOf(t, decision+telemetry, Limits{})
	if len(unreached.Taints) != 1 {
		t.Fatalf("taints = %d, want 1: the telemetry value reaches no decision\n%v",
			len(unreached.Taints), unreached.Taints)
	}
	if got := unreached.Taints[0].Endpoint; got != "https://idp.invalid/attrs" {
		t.Errorf("the reported taint came from %q, want the one the decision reads", got)
	}

	// The same telemetry rule, now read by the decision.
	reached := readsOf(t, decision+telemetry+"\nallow if telemetry != \"\"\n", Limits{})
	if len(reached.Taints) != 2 {
		t.Fatalf("taints = %d, want 2: the same value now reaches a decision\n%v",
			len(reached.Taints), reached.Taints)
	}
	for _, taint := range reached.Taints {
		if !taint.Grants() {
			t.Errorf("taint in %s reaches no decision to grant: %v", taint.Rule, taint.Decisions)
		}
	}
}

// A rule reached only under not is a rule that denies, and no property of that
// rule can say so: the negation belongs to the expression that reaches it, in
// another rule. Here the same value reaches one decision each way, which is
// also why the flag sits on the decision and not on the taint.
func TestTaintsFollowNegationThroughTheRuleGraph(t *testing.T) {
	reads := readsOf(t, `package t

# METADATA
# scope: document
# entrypoint: true
default guarded := false

# METADATA
# scope: document
# entrypoint: true
default enriched := false

guarded if not risky

enriched if risky

risky if {
	response := http.send({"method": "GET", "url": "https://score.invalid/s"})
	response.body.score > 80
}
`, Limits{})

	taint := taintOfRule(t, reads, "data.t.risky")
	negation := map[string]bool{}
	for _, decision := range taint.Decisions {
		negation[decision.Name] = decision.UnderNegation
	}

	if len(negation) != 2 {
		t.Fatalf("decisions = %v, want both", taint.Decisions)
	}
	if !negation["data.t.guarded"] {
		t.Error("the decision that reaches the value through not is not marked as denying")
	}
	if negation["data.t.enriched"] {
		t.Error("the decision that reaches the value directly is marked as denying")
	}
	if !taint.Grants() {
		t.Error("Grants() is false, but one decision reads the value to grant")
	}
}

// A pure builtin returns nothing its arguments did not already hold, so it is
// not where the trail ends: a decision reading sort(response.body.groups)
// depends on the response as much as one reading the response itself.
func TestTaintsPassThroughPureBuiltins(t *testing.T) {
	reads := readsOf(t, `package t

# METADATA
# scope: document
# entrypoint: true
default allow := false

allow if {
	response := http.send({"method": "GET", "url": "https://idp.invalid/attrs"})
	groups := sort(response.body.groups)
	groups[0] == "admin"
}
`, Limits{})

	if len(reads.Taints) == 0 {
		t.Fatal("no taint: a pure builtin was treated as the end of the chain")
	}
	for _, taint := range reads.Taints {
		if taint.Origin != "http.send" {
			t.Errorf("origin = %q, want the builtin that reached outside, not the one in between", taint.Origin)
		}
	}
}

// Nondeterministic is what makes a value something the policy did not compute,
// and a builtin that only rearranges its arguments is not that. Without the
// distinction the engine would invent taint on every policy that sorts a list.
func TestTaintsIgnoreValuesThePolicyComputed(t *testing.T) {
	reads := readsOf(t, `package t

# METADATA
# scope: document
# entrypoint: true
default allow := false

allow if {
	ordered := sort(data.users[input.user].roles)
	ordered[0] == "admin"
}
`, Limits{})

	if len(reads.Taints) != 0 {
		t.Errorf("taints = %v, want none: nothing here came from outside the policy", reads.Taints)
	}
	if len(reads.Reads) != 1 {
		t.Errorf("reads = %d, want the one under data", len(reads.Reads))
	}
}

// The call that reaches outside is often not in the rule that decides. The
// chain is followed through what a rule of the policy returns, and the origin
// reported is the far end of it: the endpoint, not the helper in the middle.
func TestTaintsFollowWhatAPolicyRuleReturns(t *testing.T) {
	reads := readsOf(t, `package t

# METADATA
# scope: document
# entrypoint: true
default allow := false

enrich(kind) := http.send({
	"method": "GET",
	"url": "https://idp.invalid/attrs",
	"headers": {"kind": kind},
})

allow if {
	enrichment := enrich("clearance")
	enrichment.body.clearance == "high"
}
`, Limits{})

	taint := taintOfRule(t, reads, "data.t.allow")
	if taint.Origin != "http.send" {
		t.Errorf("origin = %q, want http.send", taint.Origin)
	}
	if taint.Endpoint != "https://idp.invalid/attrs" {
		t.Errorf("endpoint = %q, want the url the helper calls", taint.Endpoint)
	}
}

// A destination the request steers is the worse case of the two, so it must not
// come out looking like a destination nobody managed to read. It is reported
// empty, deliberately, and the report says the policy computes it.
func TestTaintsLeaveAComputedDestinationEmpty(t *testing.T) {
	reads := readsOf(t, `package t

# METADATA
# scope: document
# entrypoint: true
default allow := false

allow if {
	enrichment := http.send({"method": "GET", "url": input.idp})
	enrichment.body.clearance == "high"
}
`, Limits{})

	taint := taintOfRule(t, reads, "data.t.allow")
	if taint.Endpoint != "" {
		t.Errorf("endpoint = %q, want empty: the policy computes it", taint.Endpoint)
	}
	if taint.Origin != "http.send" {
		t.Errorf("origin = %q, want http.send", taint.Origin)
	}
}

// A value read to deny inside its own rule is not a value read to grant, and
// that half of the question is a bool in the AST.
func TestTaintsRecordNegationInsideTheRule(t *testing.T) {
	reads := fixtureReads(t)

	var negated int
	for _, taint := range reads.Taints {
		if taint.UnderNegation {
			negated++
		}
	}
	if negated != 1 {
		t.Errorf("taints negated in their own rule = %d, want 1: not enrichment.error in denied_defensive", negated)
	}
}

func fixtureReads(t *testing.T) *ReadSet {
	t.Helper()

	bundle, err := Load([]string{fixtureDir(t, "policy-v1")}, ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	reads, err := Reads(bundle, Limits{})
	if err != nil {
		t.Fatalf("Reads() error = %v", err)
	}
	return reads
}

// taintOfRule returns the single taint of a rule, failing if there is not
// exactly one.
func taintOfRule(t *testing.T, reads *ReadSet, rule string) Taint {
	t.Helper()

	var found []Taint
	for _, taint := range reads.Taints {
		if taint.Rule == rule {
			found = append(found, taint)
		}
	}
	if len(found) != 1 {
		t.Fatalf("taints in %s = %d, want 1 (all: %s)", rule, len(found), describeTaints(reads))
	}
	return found[0]
}

func describeTaints(reads *ReadSet) string {
	described := make([]string, 0, len(reads.Taints))
	for _, taint := range reads.Taints {
		described = append(described, taint.Rule+" "+taint.Ref)
	}
	return strings.Join(described, ", ")
}
