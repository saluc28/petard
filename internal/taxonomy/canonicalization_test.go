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
			// A known false negative. The first component is public for a path
			// that then climbs out of it, so this decision is bypassed too, and
			// nothing is reported: the value the path is held against is computed,
			// and no request the decision grants is built to start from.
			name:     "a component at a fixed place",
			body:     "allow if split(input.path, \"/\")[1] == \"public\"\n",
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
				if finding.PatternID != GrantOnLooseMatch || finding.Confidence != "A" || len(finding.Reads) == 0 ||
					!strings.HasPrefix(finding.Note, "proven by {") {
					t.Errorf("finding = %+v, want one of PTD-OPA-012 at level A, with where the part is read and the request that proves it", finding)
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

// A decision OPA panics on cannot be asked either, and is a candidate that says
// why. OPA v1.21.1 panics on the partial evaluation of a negated rule whose
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
