package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func fixture(version string) string {
	return filepath.Join("..", "..", "fixtures", "vulnerable-bundle", version)
}

func TestRunReportsTheMeasures(t *testing.T) {
	var stdout, stderr bytes.Buffer

	if code := run([]string{fixture("policy-v1")}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}

	out := stdout.String()
	for _, expected := range []string{
		"parsed as rego v1",
		"data paths read by the decisions: 9",
		"reads:                            10",
		"data.users[_].profile.department",
		// The level travels with the shape: a guess about field names must not
		// read like a declaration.
		"subject=input.user",
		"level D",
	} {
		if !strings.Contains(out, expected) {
			t.Errorf("the report does not contain %q:\n%s", expected, out)
		}
	}
}

// Every kind the model declares has to have something in it, or it is a hole
// rather than a decision. This is the run that says so, and the numbers move
// with the fixture on purpose: what is asserted is that no kind is empty.
func TestRunBuildsEveryKindOfTheModel(t *testing.T) {
	var stdout, stderr bytes.Buffer

	args := []string{
		"-graph",
		"-registry", filepath.Join("..", "..", "taxonomy-registry", "opa"),
		"-write-model", filepath.Join("..", "..", "fixtures", "vulnerable-bundle", "write-model.yaml"),
		"-data", filepath.Join("..", "..", "fixtures", "vulnerable-bundle", "data"),
		fixture("policy-v1"),
	}
	if code := run(args, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}

	out := stdout.String()
	for _, kind := range []string{
		"PTD_Principal", "PTD_Action", "PTD_Resource", "PTD_Attribute", "PTD_Rule",
		"PTD_CanPerform", "PTD_Reads", "PTD_WrittenBy", "PTD_CanEscalateTo", "PTD_TaintedBy",
	} {
		if !strings.Contains(out, kind) {
			t.Errorf("the graph holds nothing of kind %s:\n%s", kind, out)
		}
	}

	// Leaving something out has to be said out loud, or an empty write model and
	// a model full of captures look the same. And the whole thing has to be
	// something BloodHound would accept, which is the only test of the model
	// that is not a test of our own opinion of it.
	for _, said := range []string{
		"declared writers name a rule for finding somebody",
		"ways of granting depend on something an edge cannot say",
		"the payload validates against schema/petard.json",
	} {
		if !strings.Contains(out, said) {
			t.Errorf("the report does not say what it left out (%q):\n%s", said, out)
		}
	}
}

// The same policy in the older syntax has to give the same answer, and the
// report says which syntax it read rather than leaving it to be assumed.
func TestRunFallsBackToRegoV0(t *testing.T) {
	var stdout, stderr bytes.Buffer

	if code := run([]string{fixture("policy-v0")}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}
	if out := stdout.String(); !strings.Contains(out, "parsed as rego v0") {
		t.Errorf("the report does not say it fell back to v0:\n%s", out)
	}
}

// The same policy read twice, once with the declaration of who writes what and
// once without it. What changes is not how much the engine found, it is what it
// is willing to claim.
func TestRunNeedsTheWriteModelToClaimAFinding(t *testing.T) {
	registry := filepath.Join("..", "..", "taxonomy-registry", "opa")
	model := filepath.Join("..", "..", "fixtures", "vulnerable-bundle", "write-model.yaml")

	tests := []struct {
		name       string
		args       []string
		expected   string
		unexpected string
	}{
		{
			name: "with the write model",
			args: []string{"-registry", registry, "-write-model", model, fixture("policy-v1")},
			// roles appears in the report, as a read like any other. What it
			// must not appear as is a finding.
			expected:   "PTD-OPA-001 finding: data.users[_].profile.department",
			unexpected: "finding: data.users[_].roles",
		},
		{
			name: "without it",
			args: []string{"-registry", registry, fixture("policy-v1")},
			// PTD-OPA-004 still reports findings here, and should: it needs no
			// write model, because the external source is the writer and its
			// identity is the endpoint.
			expected:   "PTD-OPA-001 candidate: data.users[_].profile.department",
			unexpected: "PTD-OPA-001 finding:",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			if code := run(tt.args, &stdout, &stderr); code != exitOK {
				t.Fatalf("exit code = %d (stderr: %s)", code, stderr.String())
			}
			out := stdout.String()
			if !strings.Contains(out, tt.expected) {
				t.Errorf("the report does not contain %q:\n%s", tt.expected, out)
			}
			if strings.Contains(out, tt.unexpected) {
				t.Errorf("the report contains %q, which it should not:\n%s", tt.unexpected, out)
			}
		})
	}
}

// The taint pattern names a decision and the party it depends on, and the run
// says how many values came from outside the policy. Both numbers are the point
// of the pattern: the second is what a linter can see, the first is not.
func TestRunReportsTheExternalSources(t *testing.T) {
	var stdout, stderr bytes.Buffer
	args := []string{
		"-registry", filepath.Join("..", "..", "taxonomy-registry", "opa"),
		fixture("policy-v1"),
	}

	if code := run(args, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d (stderr: %s)", code, stderr.String())
	}

	out := stdout.String()
	for _, expected := range []string{
		"values read from outside the policy: 7",
		"PTD-OPA-004 finding: data.quill.enrichment.allow depends on idp.petard-fixture.invalid",
		"reaches data.quill.risk.allow_vulnerable, to deny",
	} {
		if !strings.Contains(out, expected) {
			t.Errorf("the report does not contain %q:\n%s", expected, out)
		}
	}
	if strings.Contains(out, "audit_trace") {
		t.Errorf("the counter case was reported:\n%s", out)
	}
}

// With the data the run also says what is left of each decision once the
// documents are concrete. The tenant decision is the one worth looking at: two
// conditions, and the second is the tenant whose policy has no require_mfa key,
// which is the shape PTD-OPA-002 is about.
func TestRunPartiallyEvaluatesAgainstTheData(t *testing.T) {
	var stdout, stderr bytes.Buffer
	args := []string{
		"-registry", filepath.Join("..", "..", "taxonomy-registry", "opa"),
		"-data", filepath.Join("..", "..", "fixtures", "vulnerable-bundle", "data"),
		fixture("policy-v1"),
	}

	if code := run(args, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d (stderr: %s)", code, stderr.String())
	}

	out := stdout.String()
	for _, expected := range []string{
		"against 4 data documents, with the request unknown:",
		"data.quill.tenant_policy.allow",
	} {
		if !strings.Contains(out, expected) {
			t.Errorf("the report does not contain %q:\n%s", expected, out)
		}
	}
}

// A pattern that reads the data has to say when it did not get any: a silent
// pattern reads like one that found nothing, and here the two are opposite
// answers. With the data it names the tenant the check skips, and stays quiet
// about the field that is there for every tenant.
func TestRunSaysWhenAPatternCouldNotLook(t *testing.T) {
	registry := filepath.Join("..", "..", "taxonomy-registry", "opa")
	data := filepath.Join("..", "..", "fixtures", "vulnerable-bundle", "data")

	tests := []struct {
		name       string
		args       []string
		expected   []string
		unexpected string
	}{
		{
			name: "with the data",
			args: []string{"-registry", registry, "-data", data, fixture("policy-v1")},
			expected: []string{
				"PTD-OPA-002 finding: data.tenants[_].policy.require_mfa is absent for 1 of 2 documents",
				"absent for: dolm",
				"side that applies the check: declared entrypoint",
			},
			unexpected: "PTD-OPA-002 finding: data.tenants[_].status",
		},
		{
			name:       "without it",
			args:       []string{"-registry", registry, fixture("policy-v1")},
			expected:   []string{"not applied: it reads the concrete data"},
			unexpected: "PTD-OPA-002 finding:",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			if code := run(tt.args, &stdout, &stderr); code != exitOK {
				t.Fatalf("exit code = %d (stderr: %s)", code, stderr.String())
			}
			out := stdout.String()
			for _, expected := range tt.expected {
				if !strings.Contains(out, expected) {
					t.Errorf("the report does not contain %q:\n%s", expected, out)
				}
			}
			if strings.Contains(out, tt.unexpected) {
				t.Errorf("the report contains %q, which it should not:\n%s", tt.unexpected, out)
			}
		})
	}
}

// The two rules that go quiet when the scoring service stops answering are both
// findings, and the report has to tell them apart by what is left to mitigate
// with: one of them asked for its errors to be suppressed, so there is no error
// left to make fatal.
func TestRunReportsTheChecksThatGoQuiet(t *testing.T) {
	var stdout, stderr bytes.Buffer
	args := []string{
		"-registry", filepath.Join("..", "..", "taxonomy-registry", "opa"),
		fixture("policy-v1"),
	}

	if code := run(args, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d (stderr: %s)", code, stderr.String())
	}

	out := stdout.String()
	for _, expected := range []string{
		"PTD-OPA-005 finding: data.quill.risk.allow_vulnerable lets the request through",
		"PTD-OPA-005 finding: data.quill.risk.allow_default_option lets the request through",
		"raise_error is false, so there is no error left",
		"the caller can still make the failure fatal",
	} {
		if !strings.Contains(out, expected) {
			t.Errorf("the report does not contain %q:\n%s", expected, out)
		}
	}
	for _, unexpected := range []string{
		"PTD-OPA-005 finding: data.quill.risk.allow_defensive",
		"PTD-OPA-005 finding: data.quill.risk.allow_positive_side",
	} {
		if strings.Contains(out, unexpected) {
			t.Errorf("the report contains %q, which it should not:\n%s", unexpected, out)
		}
	}
}

// The transitive grant pattern reports a position rather than a defect, so the
// report has to carry the two numbers that make it worth reading: what the
// position reaches, and what it would reach with the hierarchy cut. bob is the
// one that must stay out of it, since he reaches plenty and none of it comes
// from the hierarchy.
func TestRunReportsWhatAPositionIsWorth(t *testing.T) {
	var stdout, stderr bytes.Buffer
	args := []string{
		"-registry", filepath.Join("..", "..", "taxonomy-registry", "opa"),
		"-data", filepath.Join("..", "..", "fixtures", "vulnerable-bundle", "data"),
		fixture("policy-v1"),
	}

	if code := run(args, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d (stderr: %s)", code, stderr.String())
	}

	out := stdout.String()
	for _, expected := range []string{
		"PTD-OPA-003 candidate: dave reaches data.quill.authz.allow in 18 ways",
		"through data.projects[_].parent, and in 0 without it",
		"graph.reachable at",
	} {
		if !strings.Contains(out, expected) {
			t.Errorf("the report does not contain %q:\n%s", expected, out)
		}
	}
	for _, unexpected := range []string{"candidate: bob", "candidate: alice", "candidate: carol"} {
		if strings.Contains(out, unexpected) {
			t.Errorf("the report contains %q, which it should not:\n%s", unexpected, out)
		}
	}
}

// The central criterion, seen from the command line: one
// escalation, and the report has to carry the three things that make it
// actionable, who ends up where, what to write, and how the write happens.
func TestRunReportsTheEscalation(t *testing.T) {
	var stdout, stderr bytes.Buffer
	args := []string{
		"-registry", filepath.Join("..", "..", "taxonomy-registry", "opa"),
		"-write-model", filepath.Join("..", "..", "fixtures", "vulnerable-bundle", "write-model.yaml"),
		"-data", filepath.Join("..", "..", "fixtures", "vulnerable-bundle", "data"),
		fixture("policy-v1"),
	}

	if code := run(args, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d (stderr: %s)", code, stderr.String())
	}

	out := stdout.String()
	for _, expected := range []string{
		"PTD-OPA-003 finding: mallory can reach what the position of dave reaches",
		"by writing data.users.mallory.profile.department",
		"written via PATCH /api/v1/me/profile",
	} {
		if !strings.Contains(out, expected) {
			t.Errorf("the report does not contain %q:\n%s", expected, out)
		}
	}
	if strings.Count(out, "can reach what the position of") != 1 {
		t.Errorf("the report claims more than one escalation, and the fixture injects one:\n%s", out)
	}
}

// Without the declaration of who writes what, the same run still measures
// everything else and claims no escalation: the chain rests on the one fact no
// policy can supply.
func TestRunClaimsNoEscalationWithoutTheWriteModel(t *testing.T) {
	var stdout, stderr bytes.Buffer
	args := []string{
		"-registry", filepath.Join("..", "..", "taxonomy-registry", "opa"),
		"-data", filepath.Join("..", "..", "fixtures", "vulnerable-bundle", "data"),
		fixture("policy-v1"),
	}

	if code := run(args, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d (stderr: %s)", code, stderr.String())
	}

	out := stdout.String()
	if strings.Contains(out, "can reach what the position of") {
		t.Errorf("an escalation was claimed with nobody declaring who writes the field:\n%s", out)
	}
	if !strings.Contains(out, "PTD-OPA-003 candidate: dave reaches") {
		t.Errorf("the position itself is no longer measured either:\n%s", out)
	}
}

// A bound that cuts has to be visible in the report, or a truncated answer
// reads like a complete one.
func TestRunSaysWhenTheResidualBoundCuts(t *testing.T) {
	var stdout, stderr bytes.Buffer
	args := []string{
		"-registry", filepath.Join("..", "..", "taxonomy-registry", "opa"),
		"-data", filepath.Join("..", "..", "fixtures", "vulnerable-bundle", "data"),
		"-max-residuals", "2",
		fixture("policy-v1"),
	}

	if code := run(args, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d (stderr: %s)", code, stderr.String())
	}

	out := stdout.String()
	if !strings.Contains(out, "the bound cut the rest") {
		t.Errorf("the report does not say a decision was cut short:\n%s", out)
	}
	if !strings.Contains(out, "raise MaxResiduals") {
		t.Errorf("the report does not say what to raise:\n%s", out)
	}
}

func TestRunReportsWriteModelCoverage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	args := []string{
		"-registry", filepath.Join("..", "..", "taxonomy-registry", "opa"),
		"-write-model", filepath.Join("..", "..", "fixtures", "vulnerable-bundle", "write-model.yaml"),
		fixture("policy-v1"),
	}

	if code := run(args, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d (stderr: %s)", code, stderr.String())
	}
	if out := stdout.String(); !strings.Contains(out, "write model: 4 of 9 paths covered (44%)") {
		t.Errorf("the coverage number is missing or wrong:\n%s", out)
	}
}

func TestRunUsageErrors(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "no paths", args: nil},
		{name: "both syntaxes forced", args: []string{"-rego-v0", "-rego-v1", fixture("policy-v1")}},
		{name: "unknown flag", args: []string{"-what", fixture("policy-v1")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			if code := run(tt.args, &stdout, &stderr); code != exitUsage {
				t.Errorf("exit code = %d, want %d", code, exitUsage)
			}
			if stdout.Len() != 0 {
				t.Errorf("a usage error wrote to stdout: %s", stdout.String())
			}
		})
	}
}

func TestRunReportsAFailureOnStderr(t *testing.T) {
	var stdout, stderr bytes.Buffer

	if code := run([]string{filepath.Join("does", "not", "exist")}, &stdout, &stderr); code != exitFailure {
		t.Errorf("exit code = %d, want %d", code, exitFailure)
	}
	if !strings.Contains(stderr.String(), "analyze-opa:") {
		t.Errorf("stderr does not name the program: %s", stderr.String())
	}
}
