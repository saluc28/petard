package taxonomy

import (
	"slices"
	"strings"
	"testing"

	"github.com/saluc28/petard/internal/pep"
)

// canonicalGateway declares a gateway that hands the path of a call on to a
// client that collapses its dot segments, after the policy has decided on it.
func canonicalGateway(part string, forms ...string) string {
	return `schema_version: 1
id: test-gateway
engine: opa
source:
  kind: documentation
  note: a gateway for the test
decisions:
  - rule: allow
    side: grants
fields:
  - path: ` + part + `
    set_by: caller
    canonicalized_after_decision: [` + strings.Join(forms, ", ") + `]
    evidence:
      - the test
`
}

func canonicalPolicy(body string) string {
	return "package p\n\n# METADATA\n# entrypoint: true\ndefault allow := false\n\n" + body
}

// summaries writes the results the way a test compares them: the verdict, the
// part of the request, and the value granted when one was.
func summaries(findings []Finding) []string {
	var got []string
	for _, finding := range findings {
		line := string(finding.Verdict) + " " + finding.Path
		if finding.Value != "" {
			line += " " + finding.Value
		}
		got = append(got, line)
	}
	return got
}

// The decision is asked, so the verdict does not depend on how the match or the
// guard is written: a prefix the policy writes, a glob, a prefix taken from
// another part of the request. What is reported is a value granted that
// resolves to one refused, and a decision that refuses the first, or grants the
// second anyway, is left alone.
func TestGrantsBeforeCanonicalization(t *testing.T) {
	const part = "input.path"
	const dots = `"/public/petard-leaf/../../petard-beyond"`
	const encoded = `"/public/petard-leaf/%2e%2e/%2e%2e/petard-beyond"`

	tests := []struct {
		name     string
		body     string
		forms    []string
		expected []string
	}{
		{
			name:     "a prefix nothing guards",
			body:     "allow if {\n\tinput.method == \"GET\"\n\tstartswith(input.path, \"/public/\")\n}\n",
			forms:    []string{"dot-segments"},
			expected: []string{"finding input.path " + dots},
		},
		{
			name:     "a prefix behind a guard on the dot segments",
			body:     "allow if {\n\tnot contains(input.path, \"..\")\n\tstartswith(input.path, \"/public/\")\n}\n",
			forms:    []string{"dot-segments"},
			expected: nil,
		},
		{
			// The guard reads the two dots and not what a client decodes to them.
			name:     "the same guard, and a path decoded after the decision",
			body:     "allow if {\n\tnot contains(input.path, \"..\")\n\tstartswith(input.path, \"/public/\")\n}\n",
			forms:    []string{"dot-segments", "percent-encoding"},
			expected: []string{"finding input.path " + encoded},
		},
		{
			name:     "a guard on both forms",
			body:     "allow if {\n\tnot contains(input.path, \"..\")\n\tnot contains(lower(input.path), \"%2e\")\n\tstartswith(input.path, \"/public/\")\n}\n",
			forms:    []string{"dot-segments", "percent-encoding"},
			expected: nil,
		},
		{
			name:     "a glob",
			body:     "allow if glob.match(\"/public/**\", [\"/\"], input.path)\n",
			forms:    []string{"dot-segments"},
			expected: []string{"finding input.path " + dots},
		},
		{
			name:     "the whole value",
			body:     "allow if input.path == \"/public/index\"\n",
			forms:    []string{"dot-segments"},
			expected: nil,
		},
		{
			// The first component is public for a path that then climbs out of
			// it, so this decision is bypassed too. What the path is held against
			// is computed, and no request the decision grants is built to start
			// from: it could not be asked, and that is what is reported. Given
			// one, it is asked: see the test of a given request below.
			name:     "a component at a fixed place",
			body:     "allow if split(input.path, \"/\")[1] == \"public\"\n",
			forms:    []string{"dot-segments"},
			expected: []string{"candidate input.path"},
		},
		{
			// The paths are in the conditions partial evaluation leaves, and one
			// of them is where the question starts. An equality lets no traversal
			// through.
			name:     "one of the values a rule lists",
			body:     "allow if input.path in {\"/public/index\", \"/public/about\"}\n",
			forms:    []string{"dot-segments"},
			expected: nil,
		},
		{
			// Whoever holds the role is granted every path, the one the traversal
			// resolves to among them, so nothing is bypassed.
			name:     "a decision that grants any path",
			body:     "allow if input.role == \"admin\"\n\nallow if {\n\tinput.role == \"admin\"\n\tstartswith(input.path, \"/public/\")\n}\n",
			forms:    []string{"dot-segments"},
			expected: nil,
		},
		{
			// The paths an agent accepts come with the request, the way a gateway
			// sends them, and one without a wildcard is taken as a prefix.
			name: "a prefix taken from another part of the request",
			body: `allow if {
	some group in input.caller.groups
	group in input.target.allowed_groups
	some accepted in input.target.allowed_paths
	matches(accepted, input.path)
}

matches(accepted, asked) if accepted == asked

matches(accepted, asked) if startswith(asked, concat("", [accepted, "/"]))
`,
			forms:    []string{"dot-segments"},
			expected: []string{`finding input.path "/petard-root/petard-leaf/../../petard-beyond"`},
		},
		{
			name: "the same, behind a guard in a function",
			body: `allow if {
	some group in input.caller.groups
	group in input.target.allowed_groups
	safe(input.path)
	some accepted in input.target.allowed_paths
	matches(accepted, input.path)
}

safe(asked) if {
	not contains(asked, "../")
	not endswith(asked, "/..")
}

matches(accepted, asked) if accepted == asked

matches(accepted, asked) if startswith(asked, concat("", [accepted, "/"]))
`,
			forms:    []string{"dot-segments"},
			expected: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := analysisWithGateway(t, canonicalPolicy(tt.body), canonicalGateway(part, tt.forms...))

			findings, err := GrantsBeforeCanonicalization(t.Context(), a)
			if err != nil {
				t.Fatalf("GrantsBeforeCanonicalization() error = %v", err)
			}
			if got := summaries(findings); !slices.Equal(got, tt.expected) {
				t.Errorf("results = %v, want %v", got, tt.expected)
			}
			for _, finding := range findings {
				if finding.PatternID != GrantOnLooseMatch || finding.Confidence != "A" || len(finding.Reads) == 0 {
					t.Errorf("result = %+v, want one of PTD-OPA-012 at level A, with where the part is read", finding)
				}
				if finding.Verdict == VerdictFinding && !strings.HasPrefix(finding.Note, "proven by {") {
					t.Errorf("finding = %+v, want the request that proves it", finding)
				}
				if finding.Verdict == VerdictCandidate && !strings.Contains(finding.Summary, "no request it grants could be built") {
					t.Errorf("candidate = %+v, want it to say no request was built to ask about", finding)
				}
			}
		})
	}
}

// The prefix can be in a document: the decision is asked with a path under each
// value the document holds.
func TestGrantsBeforeCanonicalizationOnAPrefixFromTheData(t *testing.T) {
	policy := canonicalPolicy("allow if {\n\tsome prefix in data.public_prefixes\n\tstartswith(input.path, prefix)\n}\n")
	a := delegationAnalysis(t, policy, canonicalGateway("input.path", "dot-segments"), `{"public_prefixes": ["/static/", "/docs/"]}`)

	findings, err := GrantsBeforeCanonicalization(t.Context(), a)
	if err != nil {
		t.Fatalf("GrantsBeforeCanonicalization() error = %v", err)
	}
	if got := summaries(findings); len(got) != 1 || !strings.HasPrefix(got[0], `finding input.path "/`) ||
		!strings.HasSuffix(got[0], `/petard-leaf/../../petard-beyond"`) {
		t.Errorf("results = %v, want one finding on a path under a prefix of the document", got)
	}

	// Without the document the decision cannot be asked, and the run says so
	// rather than report nothing.
	a.Data = nil
	findings, err = GrantsBeforeCanonicalization(t.Context(), a)
	if err != nil {
		t.Fatalf("GrantsBeforeCanonicalization() error = %v", err)
	}
	if len(findings) != 1 || findings[0].Verdict != VerdictCandidate ||
		!strings.Contains(findings[0].Summary, "it reads the concrete data, and none was given") {
		t.Errorf("results = %v, want a candidate saying the data is missing", findings)
	}
}

// The paths a decision grants can be listed in a document and compared whole.
// Nothing in the policy writes one of them, and none is a prefix to stand
// under: with the path left open, partial evaluation leaves each of them as a
// condition, and that is where the question starts. Asked, the decision
// refuses a traversal out of any of them.
func TestGrantsBeforeCanonicalizationOnPathsADocumentLists(t *testing.T) {
	policy := canonicalPolicy("allow if {\n\tsome route in data.routes\n\troute.path == input.path\n\troute.method == input.method\n}\n")
	a := delegationAnalysis(t, policy, canonicalGateway("input.path", "dot-segments"),
		`{"routes": [{"path": "/public/index", "method": "GET"}, {"path": "/public/about", "method": "GET"}]}`)

	findings, err := GrantsBeforeCanonicalization(t.Context(), a)
	if err != nil {
		t.Fatalf("GrantsBeforeCanonicalization() error = %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("results = %v, want none: the decision was asked, and grants the listed paths alone", summaries(findings))
	}

	granted, err := requestsGrantingAnyValue(t.Context(), a, "data.p.allow")
	if err != nil {
		t.Fatalf("requestsGrantingAnyValue() error = %v", err)
	}
	var paths []string
	for _, request := range granted {
		if path, isString := request["path"].(string); isString {
			paths = append(paths, path)
		}
	}
	slices.Sort(paths)
	if !slices.Equal(paths, []string{"/public/about", "/public/index"}) {
		t.Errorf("requests built with the path left open carry %v, want the two paths of the document", paths)
	}
}

// A decision OPA panics on cannot be asked either, and is a candidate that says
// why. OPA v1.21.2 panics on the partial evaluation of a negated rule whose
// body holds an every over a part of the request left unknown.
func TestGrantsBeforeCanonicalizationWhenOPAPanics(t *testing.T) {
	policy := canonicalPolicy(`allow if {
	startswith(input.path, "/public/")
	not blocked
}

blocked if {
	every tag in input.tags {
		tag == "internal"
	}
}
`)
	a := analysisWithGateway(t, policy, canonicalGateway("input.path", "dot-segments"))

	findings, err := GrantsBeforeCanonicalization(t.Context(), a)
	if err != nil {
		t.Fatalf("GrantsBeforeCanonicalization() error = %v", err)
	}
	if len(findings) != 1 || findings[0].Verdict != VerdictCandidate ||
		!strings.Contains(findings[0].Summary, "OPA panicked evaluating it") {
		t.Errorf("results = %v, want a candidate saying OPA panicked", findings)
	}
}

// A decision that holds the path against something it computes leaves no
// condition to build a granted request from. Given one, the question starts
// there: the path the request carries is the place the traversal leaves.
func TestGrantsBeforeCanonicalizationStartsFromAGivenRequest(t *testing.T) {
	const component = "allow if {\n\tinput.method == \"GET\"\n\tsplit(input.path, \"/\")[1] == \"public\"\n}\n"
	const guarded = "allow if {\n\tinput.method == \"GET\"\n\tnot contains(input.path, \"..\")\n\tsplit(input.path, \"/\")[1] == \"public\"\n}\n"
	const unasked = "candidate input.path"

	given := func(decision string, input map[string]any) []GrantedRequest {
		return []GrantedRequest{{File: "granted.json", Input: input, Decisions: []string{decision}}}
	}
	intro := map[string]any{"method": "GET", "path": "/public/docs/intro"}

	tests := []struct {
		name     string
		body     string
		granted  []GrantedRequest
		expected []string
	}{
		{
			name:     "no request given",
			body:     component,
			expected: []string{unasked},
		},
		{
			name:     "a request the decision grants",
			body:     component,
			granted:  given("data.p.allow", intro),
			expected: []string{`finding input.path "/public/docs/intro/../../../petard-beyond"`},
		},
		{
			// The decision was asked, and refuses the traversal.
			name:    "the same request, and a guard on the dot segments",
			body:    guarded,
			granted: given("data.p.allow", intro),
		},
		{
			name:     "a request another decision grants",
			body:     component,
			granted:  given("data.p.other", intro),
			expected: []string{unasked},
		},
		{
			// There is no place for a traversal to leave.
			name:     "a request that carries no path",
			body:     component,
			granted:  given("data.p.allow", map[string]any{"method": "GET"}),
			expected: []string{unasked},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := analysisWithGateway(t, canonicalPolicy(tt.body), canonicalGateway("input.path", "dot-segments"))
			a.Granted = tt.granted

			findings, err := GrantsBeforeCanonicalization(t.Context(), a)
			if err != nil {
				t.Fatalf("GrantsBeforeCanonicalization() error = %v", err)
			}
			if got := summaries(findings); !slices.Equal(got, tt.expected) {
				t.Errorf("results = %v, want %v", got, tt.expected)
			}
			for _, finding := range findings {
				if finding.Verdict == VerdictFinding && !strings.Contains(finding.Note, `"method":"GET"`) {
					t.Errorf("note = %q, want the request given, with the path that leaves it", finding.Note)
				}
			}
		})
	}
}

// The two ways PTD-OPA-012 is found meet on one decision and one part of the
// request. The form of the match leaves a candidate on a prefix, asking whether
// the looseness matters; a request that proves it does is the answer, and the
// candidate goes. A guarded prefix keeps its candidate, and a substring, a
// finding whatever the enforcement point does, stays next to the proof.
func TestRunJoinsTheTwoWaysALooseMatchIsFound(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected []string
	}{
		{
			name:     "a prefix proven to let a traversal through",
			body:     "allow if startswith(input.path, \"/public/\")\n",
			expected: []string{`finding input.path "/public/petard-leaf/../../petard-beyond"`},
		},
		{
			name:     "a guarded prefix",
			body:     "allow if {\n\tnot contains(input.path, \"..\")\n\tstartswith(input.path, \"/public/\")\n}\n",
			expected: []string{`candidate input.path "/public/"`},
		},
		{
			name: "a substring",
			body: "allow if contains(input.path, \"/public/\")\n",
			expected: []string{
				`finding input.path "/public/"`,
				`finding input.path "/petard-root/public/petard-leaf/../../../petard-beyond"`,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := analysisWithGateway(t, canonicalPolicy(tt.body), canonicalGateway("input.path", "dot-segments"))

			found, err := Run(t.Context(), a)
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			if got := summaries(found.LooseMatch); !slices.Equal(got, tt.expected) {
				t.Errorf("results = %v, want %v", got, tt.expected)
			}
		})
	}
}

// What a value resolves to is what is asked last, so the two are built
// together: the value leaves the place it starts at by one segment for each
// segment of it, and lands on a place of its own.
func TestLeaving(t *testing.T) {
	tests := []struct {
		baseline string
		form     pep.Canonicalization
		written  string
		resolved string
	}{
		{"/public/petard-leaf", pep.CanonicalDotSegments, "/public/petard-leaf/../../petard-beyond", "/petard-beyond"},
		{"/public/petard-leaf", pep.CanonicalPercentEncoding, "/public/petard-leaf/%2e%2e/%2e%2e/petard-beyond", "/petard-beyond"},
		{"/a/b/c/", pep.CanonicalDotSegments, "/a/b/c/../../../petard-beyond", "/petard-beyond"},
		{"docs/petard-leaf", pep.CanonicalDotSegments, "docs/petard-leaf/../../petard-beyond", "petard-beyond"},
	}
	for _, tt := range tests {
		t.Run(tt.written, func(t *testing.T) {
			written, resolved := leaving(tt.baseline, tt.form)
			if written != tt.written || resolved != tt.resolved {
				t.Errorf("leaving(%s, %s) = %q and %q, want %q and %q", tt.baseline, tt.form, written, resolved, tt.written, tt.resolved)
			}
		})
	}
}
