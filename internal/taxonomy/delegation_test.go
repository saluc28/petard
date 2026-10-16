package taxonomy

import (
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/saluc28/petard/internal/graph"
	"github.com/saluc28/petard/internal/opaengine"
	"github.com/saluc28/petard/internal/pep"
)

// delegationAnalysis compiles an inline policy, declares an inline gateway over
// it, and gives it inline data, for the delegation pattern, which asks the
// decision about a witness and so needs all three.
func delegationAnalysis(t *testing.T, policy, gateway, data string, entrypoints ...string) Analysis {
	t.Helper()

	dir := t.TempDir()
	writeCaseFile(t, filepath.Join(dir, "policy", "p.rego"), policy)
	bundle, err := opaengine.Load([]string{filepath.Join(dir, "policy")}, opaengine.ParseModeAuto)
	if err != nil {
		t.Fatalf("the policy does not compile: %v", err)
	}
	bundle.Entrypoints = entrypoints
	reads, err := opaengine.Reads(bundle, opaengine.Limits{})
	if err != nil {
		t.Fatalf("Reads() error = %v", err)
	}

	file := filepath.Join(dir, "pep.yaml")
	writeCaseFile(t, file, gateway)
	point, err := pep.Load(file)
	if err != nil {
		t.Fatalf("the gateway does not load: %v", err)
	}
	shape, err := ShapeOf(reads, Inputs{}, point)
	if err != nil {
		t.Fatalf("ShapeOf() error = %v", err)
	}

	writeCaseFile(t, filepath.Join(dir, "data", "data.json"), data)
	documents, err := opaengine.LoadData([]string{filepath.Join(dir, "data")})
	if err != nil {
		t.Fatalf("LoadData() error = %v", err)
	}
	return Analysis{Bundle: bundle, Reads: reads, Shape: shape, EnforcementPoint: point, Data: documents}
}

// bounded_by names two ceilings. The decision narrows the requested scopes by
// the agent's own role but never by the delegating edge, so a request asking for
// one scope outside the edge is granted all the same, and the pattern reports
// the edge as the ceiling that is not enforced.
func TestDelegationFindsAnUnboundedScope(t *testing.T) {
	policy := `package p

# METADATA
# entrypoint: true
default allow := false

allow if {
	every scope in input.requested_scopes {
		scope in input.role_scopes
	}
}
`
	a := delegationAnalysis(t, policy, delegationGateway, `{"unused": true}`)

	findings, err := GrantsBeyondDelegatedScope(t.Context(), a)
	if err != nil {
		t.Fatalf("GrantsBeyondDelegatedScope() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %v, want one", findings)
	}
	finding := findings[0]
	if finding.Verdict != VerdictFinding {
		t.Errorf("verdict %s, want a finding: the edge does not bound the request", finding.Verdict)
	}
	if finding.Path != "input.requested_scopes" || finding.Decision != "data.p.allow" {
		t.Errorf("finding on %s for %s, want input.requested_scopes for data.p.allow", finding.Path, finding.Decision)
	}
	if finding.Summary == "" || finding.Reads == nil {
		t.Errorf("finding carries no summary or no place to look: %+v", finding)
	}
	// The request names no subject, and the finding rests on the declaration.
	if finding.Confidence != "A" {
		t.Errorf("confidence %s, want A: the enforcement point declares the requested authority", finding.Confidence)
	}
}

// The same decision, narrowed by the delegating edge as well, bounds the
// request both ways. A scope outside the edge is refused, so the pattern leaves
// it alone.
func TestDelegationLeavesANarrowedScopeAlone(t *testing.T) {
	policy := `package p

# METADATA
# entrypoint: true
default allow := false

allow if {
	every scope in input.requested_scopes {
		scope in input.delegation_edge.scopes
	}
	every scope in input.requested_scopes {
		scope in input.role_scopes
	}
}
`
	a := delegationAnalysis(t, policy, delegationGateway, `{"unused": true}`)

	findings, err := GrantsBeyondDelegatedScope(t.Context(), a)
	if err != nil {
		t.Fatalf("GrantsBeyondDelegatedScope() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("findings = %v, want none: the edge bounds the request", findings)
	}
}

// The verdict does not rest on how a bound is written, or on there being one to
// read. A decision that reads the requested authority is asked, and each of
// these grants a request one scope past the edge: bounded by the role alone as
// a subset, a difference, a count of the offenders or an every in a function,
// or not bounded at all.
func TestDelegationAsksWhateverTheBoundLooksLike(t *testing.T) {
	const role = "input.role_scopes"
	const edge = "input.delegation_edge.scopes"
	tests := []struct {
		name string
		body string
		past string
	}{
		{
			name: "no bound",
			body: `	count(input.requested_scopes) > 0
`,
			past: edge + " or by " + role,
		},
		{
			name: "a subset",
			body: `	object.subset({s | some s in input.role_scopes}, {s | some s in input.requested_scopes})
`,
			past: edge,
		},
		{
			name: "a difference",
			body: `	count({s | some s in input.requested_scopes} - {s | some s in input.role_scopes}) == 0
`,
			past: edge,
		},
		{
			name: "a count of the offenders",
			body: `	count([s | some s in input.requested_scopes; not s in input.role_scopes]) == 0
`,
			past: edge,
		},
		{
			name: "an every in a function",
			body: `	within(input.requested_scopes, input.role_scopes)
`,
			past: edge,
		},
		{
			name: "the whole request handed to a function",
			body: `	role_bounds(input)
`,
			past: edge,
		},
		{
			name: "both ceilings, one as a difference and one in a function",
			body: `	count({s | some s in input.requested_scopes} - {s | some s in input.delegation_edge.scopes}) == 0
	within(input.requested_scopes, input.role_scopes)
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := `package p

# METADATA
# entrypoint: true
default allow := false

allow if {
	input.action == "mint"
` + tt.body + `}

within(asked, held) if {
	every scope in asked {
		scope in held
	}
}

role_bounds(request) if {
	every scope in request.requested_scopes {
		scope in request.role_scopes
	}
}
`
			a := delegationAnalysis(t, policy, delegationGateway, `{"unused": true}`)

			findings, err := GrantsBeyondDelegatedScope(t.Context(), a)
			if err != nil {
				t.Fatalf("GrantsBeyondDelegatedScope() error = %v", err)
			}
			if tt.past == "" {
				if len(findings) != 0 {
					t.Errorf("findings = %v, want none: both ceilings bound the request", findings)
				}
				return
			}
			if len(findings) != 1 || findings[0].Verdict != VerdictFinding {
				t.Fatalf("findings = %v, want one finding", findings)
			}
			if want := "without bounding it by " + tt.past; !strings.HasSuffix(findings[0].Summary, want) {
				t.Errorf("the finding says %q, want it to end %q", findings[0].Summary, want)
			}
		})
	}
}

// A decision that never reads the requested authority does not grant on it,
// whatever it grants: there is nothing to ask it.
func TestDelegationLeavesADecisionThatDoesNotReadTheAuthority(t *testing.T) {
	policy := `package p

# METADATA
# entrypoint: true
default allow := false

allow if input.action == "read"
`
	a := delegationAnalysis(t, policy, delegationGateway, `{"unused": true}`)

	findings, err := GrantsBeyondDelegatedScope(t.Context(), a)
	if err != nil {
		t.Fatalf("GrantsBeyondDelegatedScope() error = %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("findings = %v, want none: the decision does not read the requested scopes", findings)
	}
}

// With a requested authority declared and no ceiling, the question is open: what
// bounds this authority? The pattern reports a candidate rather than a finding.
func TestDelegationWithoutACeilingIsACandidate(t *testing.T) {
	policy := `package p

# METADATA
# entrypoint: true
default allow := false

allow if {
	every scope in input.requested_scopes {
		scope in input.role_scopes
	}
}
`
	gateway := `schema_version: 1
id: test-gateway
engine: opa
source:
  kind: documentation
  note: a gateway for the test
decisions:
  - rule: allow
    side: grants
fields:
  - path: input.requested_scopes
    set_by: caller
    authority: requested
    evidence:
      - the test
`
	a := delegationAnalysis(t, policy, gateway, `{"unused": true}`)

	findings, err := GrantsBeyondDelegatedScope(t.Context(), a)
	if err != nil {
		t.Fatalf("GrantsBeyondDelegatedScope() error = %v", err)
	}
	if len(findings) != 1 || findings[0].Verdict != VerdictCandidate {
		t.Fatalf("findings = %v, want one candidate: nothing says what bounds the authority", findings)
	}
}

// A decision that answers every request with an object holds where it answers
// something other than its default, the deny here. This one bounds the request
// by the edge and by the role and answers the default when either fails, so
// there is nothing to report on it, asked as the object or as the field of it
// that is true or false.
func TestDelegationReadsADecisionThatAnswersWithAValue(t *testing.T) {
	policy := `package p

# METADATA
# entrypoint: true
default allow := {"decision": "deny", "allowed": false}

allow := {"decision": "allow", "allowed": true} if {
	count(input.requested_scopes) > 0
	every scope in input.requested_scopes {
		scope in input.delegation_edge.scopes
	}
	every scope in input.requested_scopes {
		scope in input.role_scopes
	}
}
`
	for _, entrypoints := range [][]string{nil, {"data.p.allow.allowed"}} {
		a := delegationAnalysis(t, policy, delegationGateway, `{"unused": true}`, entrypoints...)

		findings, err := GrantsBeyondDelegatedScope(t.Context(), a)
		if err != nil {
			t.Fatalf("GrantsBeyondDelegatedScope() error = %v", err)
		}
		if len(findings) != 0 {
			t.Errorf("with %v declared, findings = %v, want none: the decision bounds the request by both ceilings",
				entrypoints, findings)
		}
	}

	// Without the bound by the edge the request past it is answered allow, and
	// both ways of asking report it.
	unbounded := strings.Replace(policy, `	every scope in input.requested_scopes {
		scope in input.delegation_edge.scopes
	}
`, "", 1)
	a := delegationAnalysis(t, unbounded, delegationGateway, `{"unused": true}`, "data.p.allow.allowed")

	findings, err := GrantsBeyondDelegatedScope(t.Context(), a)
	if err != nil {
		t.Fatalf("GrantsBeyondDelegatedScope() error = %v", err)
	}
	var reported []string
	for _, finding := range findings {
		reported = append(reported, finding.Decision)
	}
	if !slices.Equal(reported, []string{"data.p.allow", "data.p.allow.allowed"}) {
		t.Errorf("findings on %v, want one on data.p.allow and one on data.p.allow.allowed", reported)
	}
}

// A decision contract answers a refusal of its own, with the reason, next to
// the default it falls back to. Taken to grant wherever it answers something
// other than that default, it grants the request it refuses with a reason, and
// a decision that bounds the authority by every ceiling is reported. Declared
// with the answer that grants, it is asked whether it answers allow, and there
// is nothing to report. The same declaration reports the contract that does not
// bound by the edge.
func TestDelegationAsksForTheAnswerThatGrants(t *testing.T) {
	policy := `package p

default result := {"decision": "deny", "why": "no_rule_matched"}

result := {"decision": "allow", "why": "narrowed"} if {
	count(input.requested_scopes) > 0
	every scope in input.requested_scopes {
		scope in input.delegation_edge.scopes
	}
	every scope in input.requested_scopes {
		scope in input.role_scopes
	}
}

result := {"decision": "deny", "why": "scope_exceeded"} if {
	some scope in input.requested_scopes
	not scope in input.delegation_edge.scopes
}
`
	reported := func(policy string, entrypoints ...string) []string {
		t.Helper()
		a := delegationAnalysis(t, policy, delegationGateway, `{"unused": true}`, entrypoints...)
		findings, err := GrantsBeyondDelegatedScope(t.Context(), a)
		if err != nil {
			t.Fatalf("GrantsBeyondDelegatedScope() error = %v", err)
		}
		var decisions []string
		for _, finding := range findings {
			decisions = append(decisions, finding.Decision)
		}
		return decisions
	}

	if got := reported(policy, "data.p.result"); !slices.Equal(got, []string{"data.p.result"}) {
		t.Errorf("asked whole, findings on %v, want one on data.p.result: a refusal with a reason is not the default", got)
	}
	if got := reported(policy, "data.p.result.decision=allow"); len(got) != 0 {
		t.Errorf("asked for allow, findings on %v, want none: the request past the edge is answered deny", got)
	}

	unbounded := strings.Replace(policy, `	every scope in input.requested_scopes {
		scope in input.delegation_edge.scopes
	}
`, "", 1)
	unbounded = strings.Replace(unbounded, `
result := {"decision": "deny", "why": "scope_exceeded"} if {
	some scope in input.requested_scopes
	not scope in input.delegation_edge.scopes
}
`, "", 1)
	if got := reported(unbounded, "data.p.result.decision=allow"); !slices.Equal(got, []string{"data.p.result.decision"}) {
		t.Errorf("with no bound by the edge, findings on %v, want one on data.p.result.decision", got)
	}
}

// A token service that decides on the request alone has no document to load, and
// is asked with no data given. One whose decision reads the data is not, and
// the run says the data is what is missing.
func TestDelegationRunsWithoutDataWhenTheDecisionReadsNone(t *testing.T) {
	onTheRequestAlone := `package p

# METADATA
# entrypoint: true
default allow := false

allow if {
	every scope in input.requested_scopes {
		scope in input.role_scopes
	}
}
`
	a := delegationAnalysis(t, onTheRequestAlone, delegationGateway, `{"unused": true}`)
	a.Data = nil

	findings, err := Run(t.Context(), a)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if why, skipped := findings.Skipped[GrantBeyondDelegatedScope]; skipped {
		t.Errorf("skipped because %q, want it asked: the decision reads no data", why)
	}
	if len(findings.Delegation) != 1 {
		t.Errorf("findings = %v, want the edge the decision does not enforce", findings.Delegation)
	}

	overTheData := `package p

# METADATA
# entrypoint: true
default allow := false

allow if {
	every scope in input.requested_scopes {
		scope in data.roles[input.role].scopes
	}
}
`
	a = delegationAnalysis(t, overTheData, delegationGateway, `{"roles": {"agent": {"scopes": ["read"]}}}`)
	a.Data = nil

	findings, err = Run(t.Context(), a)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if why := findings.Skipped[GrantBeyondDelegatedScope]; why != needsData {
		t.Errorf("skipped because %q, want %q: the decision reads the roles", why, needsData)
	}
}

// A decision OPA panics on leaves the pattern that asks it skipped, with the
// decision named, and the run goes on. OPA v1.21.2 panics on a negated rule
// whose body holds an every over a value left unknown; an OPA that answers
// instead lets the pattern report the edge the decision does not enforce.
func TestRunSkipsAPatternWhenOPAPanics(t *testing.T) {
	policy := `package p

# METADATA
# entrypoint: true
default allow := false

allow if {
	every scope in input.requested_scopes {
		scope in input.role_scopes
	}
	not revoked
}

revoked if {
	every flag in input.flags {
		flag == "off"
	}
}
`
	a := delegationAnalysis(t, policy, delegationGateway, `{"unused": true}`)

	findings, err := Run(t.Context(), a)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	why, skipped := findings.Skipped[GrantBeyondDelegatedScope]
	switch {
	case skipped && !strings.Contains(why, "data.p.allow"):
		t.Errorf("skipped because %q, want the decision OPA panicked on named", why)
	case !skipped && len(findings.Delegation) != 1:
		t.Errorf("findings = %v, want the edge the decision does not enforce", findings.Delegation)
	}
}

// The same for the graph: a question OPA panics on is counted and left out, and
// the graph is still built.
func TestAssembleCountsWhatOPAPanicsOn(t *testing.T) {
	policy := `package p

# METADATA
# entrypoint: true
default allow := false

allow if {
	data.users[input.user].active
	not revoked
}

revoked if {
	every flag in input.flags {
		flag == "off"
	}
}
`
	a := delegationAnalysis(t, policy, delegationGateway, `{"users": {"alice": {"active": true}}}`)

	findings, err := Run(t.Context(), a)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	g, gaps, err := Assemble(t.Context(), a, findings)
	if err != nil {
		t.Fatalf("Assemble() error = %v", err)
	}
	if g == nil {
		t.Fatal("no graph")
	}
	if gaps.UnaskedCapabilities == 0 && len(edgesOfKind(g, graph.EdgeKindCanPerform)) == 0 {
		t.Error("alice has no capability and no question went unasked, want one or the other")
	}
}

// delegationGateway declares the requested authority and the two ceilings it
// must sit under, the delegating edge and the agent's own role.
const delegationGateway = `schema_version: 1
id: test-gateway
engine: opa
source:
  kind: documentation
  note: a gateway for the test
decisions:
  - rule: allow
    side: grants
fields:
  - path: input.requested_scopes
    set_by: caller
    authority: requested
    bounded_by:
      - input.delegation_edge.scopes
      - input.role_scopes
    evidence:
      - the test
`

// A decision that grants named scopes alone refuses the synthetic element the
// pattern builds a request with, so without a request of its own it cannot be
// asked, and says so. Given one it grants, it is asked like any other: the
// request is asked again with the edge holding none of the scopes it asks for.
func TestDelegationStartsFromARequestGivenAsGranted(t *testing.T) {
	const roleOnly = `allow if {
	every scope in input.requested_scopes {
		scope in {"docs:read", "docs:write"}
	}
	every scope in input.requested_scopes {
		scope in input.role_scopes
	}
}
`
	const narrowed = roleOnly + `
allow_narrowed if {
	every scope in input.requested_scopes {
		scope in {"docs:read", "docs:write"}
	}
	every scope in input.requested_scopes {
		scope in input.delegation_edge.scopes
	}
	every scope in input.requested_scopes {
		scope in input.role_scopes
	}
}
`
	read := map[string]any{
		"requested_scopes": []any{"docs:read"},
		"role_scopes":      []any{"docs:read", "docs:write"},
		"delegation_edge":  map[string]any{"scopes": []any{"docs:read"}},
	}

	tests := []struct {
		name     string
		body     string
		granted  []GrantedRequest
		expected []string
	}{
		{
			name:     "no request given",
			body:     roleOnly,
			expected: []string{"candidate data.p.allow"},
		},
		{
			name:     "a request the decision grants",
			body:     roleOnly,
			granted:  []GrantedRequest{{File: "granted.json", Input: read, Decisions: []string{"data.p.allow"}}},
			expected: []string{"finding data.p.allow input.delegation_edge.scopes"},
		},
		{
			name: "the same request, and a decision narrowed by the edge as well",
			body: narrowed,
			granted: []GrantedRequest{{File: "granted.json", Input: read,
				Decisions: []string{"data.p.allow", "data.p.allow_narrowed"}}},
			expected: []string{"finding data.p.allow input.delegation_edge.scopes"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := "package p\n\n# METADATA\n# entrypoint: true\ndefault allow := false\n\n" +
				"# METADATA\n# entrypoint: true\ndefault allow_narrowed := false\n\n" + tt.body
			gateway := strings.Replace(delegationGateway, "  - rule: allow\n", "  - rule: allow\n    side: grants\n  - rule: allow_narrowed\n", 1)
			a := delegationAnalysis(t, policy, gateway, `{"unused": true}`)
			a.Granted = tt.granted

			findings, err := GrantsBeyondDelegatedScope(t.Context(), a)
			if err != nil {
				t.Fatalf("GrantsBeyondDelegatedScope() error = %v", err)
			}
			if got := delegationResults(findings); !slices.Equal(got, tt.expected) {
				t.Errorf("results = %v, want %v", got, tt.expected)
			}
			for _, finding := range findings {
				if finding.Verdict == VerdictFinding && !strings.Contains(finding.Note, `"docs:read"`) {
					t.Errorf("note = %q, want the request given, with the scope it asks for", finding.Note)
				}
				if finding.Verdict == VerdictCandidate && !strings.Contains(finding.Summary, "none was given") {
					t.Errorf("summary = %q, want it to say no request was there to ask about", finding.Summary)
				}
			}
		})
	}
}

// A ceiling can be a document in the data, the scopes of the role the request
// names. It is asked about with every document its path names holding none of
// what is asked for, since the request picks one of them. Where the request
// picks the role inside the every, partial evaluation keeps the every whole and
// leaves no condition to build a request from: the decision is a candidate that
// says it could not be asked, and a request given as granted asks it.
func TestDelegationAsksACeilingInTheData(t *testing.T) {
	const gateway = `schema_version: 1
id: test-gateway
engine: opa
source:
  kind: documentation
  note: a gateway for the test
decisions:
  - rule: allow
    side: grants
fields:
  - path: input.requested_scopes
    set_by: caller
    authority: requested
    bounded_by:
      - input.delegation_edge.scopes
      - data.roles[_].scopes
    evidence:
      - the test
`
	const data = `{"roles": {"agent": {"scopes": ["docs:read"]}, "auditor": {"scopes": ["logs:read"]}}}`
	const roleInside = `allow if {
	every scope in input.requested_scopes {
		scope in data.roles[input.role].scopes
	}
}
`
	const bothInside = `allow if {
	every scope in input.requested_scopes {
		scope in data.roles[input.role].scopes
	}
	every scope in input.requested_scopes {
		scope in input.delegation_edge.scopes
	}
}
`
	agent := []GrantedRequest{{
		File: "granted.json",
		Input: map[string]any{
			"requested_scopes": []any{"docs:read"},
			"role":             "agent",
			"delegation_edge":  map[string]any{"scopes": []any{"docs:read"}},
		},
		Decisions: []string{"data.p.allow"},
	}}

	tests := []struct {
		name     string
		body     string
		granted  []GrantedRequest
		expected []string
	}{
		{
			name: "bounded by the edge, not by the role in the data",
			body: `allow if {
	data.roles[input.role]
	every scope in input.requested_scopes {
		scope in input.delegation_edge.scopes
	}
}
`,
			expected: []string{"finding data.p.allow data.roles[_].scopes"},
		},
		{
			name:     "bounded by the role, picked inside the every, and no request given",
			body:     roleInside,
			expected: []string{"candidate data.p.allow"},
		},
		{
			name:     "the same, with a request given",
			body:     roleInside,
			granted:  agent,
			expected: []string{"finding data.p.allow input.delegation_edge.scopes"},
		},
		{
			name:    "bounded by both, with a request given",
			body:    bothInside,
			granted: agent,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := "package p\n\n# METADATA\n# entrypoint: true\ndefault allow := false\n\n" + tt.body
			a := delegationAnalysis(t, policy, gateway, data)
			a.Granted = tt.granted

			findings, err := GrantsBeyondDelegatedScope(t.Context(), a)
			if err != nil {
				t.Fatalf("GrantsBeyondDelegatedScope() error = %v", err)
			}
			if got := delegationResults(findings); !slices.Equal(got, tt.expected) {
				t.Errorf("results = %v, want %v", got, tt.expected)
			}
		})
	}
}

// Scopes can come as one string, the way OAuth writes them. The synthetic
// request asks for a list and builds nothing here, and a request given as
// granted is what the question starts from: the edge is then a string holding
// none of the scopes asked for.
func TestDelegationAsksAScopeString(t *testing.T) {
	const gateway = `schema_version: 1
id: test-gateway
engine: opa
source:
  kind: documentation
  note: a gateway for the test
decisions:
  - rule: allow
    side: grants
fields:
  - path: input.scope
    set_by: caller
    authority: requested
    bounded_by:
      - input.edge_scope
      - input.role_scope
    evidence:
      - the test
`
	policy := `package p

# METADATA
# entrypoint: true
default allow := false

allow if {
	every scope in split(input.scope, " ") {
		scope in split(input.role_scope, " ")
	}
}
`
	a := delegationAnalysis(t, policy, gateway, `{"unused": true}`)
	a.Granted = []GrantedRequest{{
		File:      "granted.json",
		Input:     map[string]any{"scope": "docs:read", "role_scope": "docs:read docs:write", "edge_scope": "docs:read"},
		Decisions: []string{"data.p.allow"},
	}}

	findings, err := GrantsBeyondDelegatedScope(t.Context(), a)
	if err != nil {
		t.Fatalf("GrantsBeyondDelegatedScope() error = %v", err)
	}
	if got := delegationResults(findings); !slices.Equal(got, []string{"finding data.p.allow input.edge_scope"}) {
		t.Errorf("results = %v, want a finding on the edge alone", got)
	}
}

// What a ceiling becomes when it holds none of what is asked for keeps the
// shape the decision reads it in.
func TestHoldingNothingAsked(t *testing.T) {
	tests := []struct {
		name    string
		ceiling any
		want    any
	}{
		{"a list", []any{"docs:read"}, []any{delegationBeyond}},
		{"nothing there", nil, []any{delegationBeyond}},
		{"a string", "docs:read docs:write", delegationBeyond},
		{"an object", map[string]any{"docs:read": map[string]any{"since": 2024}}, map[string]any{delegationBeyond: map[string]any{"since": 2024}}},
		{"an empty object", map[string]any{}, map[string]any{delegationBeyond: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := holdingNothingAsked(tt.ceiling); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("holdingNothingAsked(%v) = %v, want %v", tt.ceiling, got, tt.want)
			}
		})
	}
}

// delegationResults writes the results the way a test compares them: the
// verdict, the decision, and the ceilings a finding names, in the order the
// summary names them.
func delegationResults(findings []Finding) []string {
	var got []string
	for _, finding := range findings {
		line := string(finding.Verdict) + " " + finding.Decision
		if finding.Verdict == VerdictFinding {
			_, ceilings, _ := strings.Cut(finding.Summary, "without bounding it by ")
			line += " " + strings.ReplaceAll(ceilings, " or by ", " ")
		}
		got = append(got, line)
	}
	return got
}
