package analyze

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"

	"github.com/saluc28/petard/internal/opaengine"
)

func fixture(version string) string {
	return filepath.Join("..", "..", "..", "fixtures", "vulnerable-bundle", version)
}

// detailed asks for the whole report and for an exit code that speaks about the
// run rather than about what was found. The tests below read the evidence,
// which is what -v prints, and the verdict has tests of its own further down.
func detailed(args ...string) []string {
	return append([]string{"-v", "-fail-on", failOnNone}, args...)
}

func TestRunReportsTheMeasures(t *testing.T) {
	var stdout, stderr bytes.Buffer

	if code := Run(detailed(fixture("policy-v1")), &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}

	out := stdout.String()
	for _, expected := range []string{
		"parsed as rego v1",
		"data paths read by the decisions: 11",
		"reads:                            17",
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

// The members of a project are searched for the requester rather than indexed
// by them, and the report says so apart from the indexed reads. Without the
// write model the search is a candidate, and the report says where the subject
// stands in it.
func TestRunReportsTheLookupsByValue(t *testing.T) {
	var stdout, stderr bytes.Buffer

	if code := Run(detailed(fixture("policy-v1")), &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}

	out := stdout.String()
	_, lookups, found := strings.Cut(out, "reads that look the subject (input.user) up by value:\n")
	if !found {
		t.Fatalf("the report has no section for the lookups by value:\n%s", out)
	}
	section, _, _ := strings.Cut(lookups, "\n\n")
	if !strings.Contains(section, "data.projects[_].members") || strings.Contains(section, "data.documents") {
		t.Errorf("the lookups are not the members of a project alone:\n%s", section)
	}
	for _, expected := range []string{
		"PTD-OPA-001 candidate: data.projects[_].members",
		"the subject is found in it by value, at segment 4",
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
		"-registry", filepath.Join("..", "..", "..", "taxonomy-registry", "opa"),
		"-write-model", filepath.Join("..", "..", "..", "fixtures", "vulnerable-bundle", "write-model.yaml"),
		"-data", filepath.Join("..", "..", "..", "fixtures", "vulnerable-bundle", "data"),
		fixture("policy-v1"),
	}
	if code := Run(detailed(args...), &stdout, &stderr); code != exitOK {
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

	if code := Run(detailed(fixture("policy-v0")), &stdout, &stderr); code != exitOK {
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
	registry := filepath.Join("..", "..", "..", "taxonomy-registry", "opa")
	model := filepath.Join("..", "..", "..", "fixtures", "vulnerable-bundle", "write-model.yaml")

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

			if code := Run(detailed(tt.args...), &stdout, &stderr); code != exitOK {
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
		"-registry", filepath.Join("..", "..", "..", "taxonomy-registry", "opa"),
		fixture("policy-v1"),
	}

	if code := Run(detailed(args...), &stdout, &stderr); code != exitOK {
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
		"-registry", filepath.Join("..", "..", "..", "taxonomy-registry", "opa"),
		"-data", filepath.Join("..", "..", "..", "fixtures", "vulnerable-bundle", "data"),
		fixture("policy-v1"),
	}

	if code := Run(detailed(args...), &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d (stderr: %s)", code, stderr.String())
	}

	out := stdout.String()
	for _, expected := range []string{
		"against 5 data documents, with the request unknown:",
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
	registry := filepath.Join("..", "..", "..", "taxonomy-registry", "opa")
	data := filepath.Join("..", "..", "..", "fixtures", "vulnerable-bundle", "data")

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

			if code := Run(detailed(tt.args...), &stdout, &stderr); code != exitOK {
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
		"-registry", filepath.Join("..", "..", "..", "taxonomy-registry", "opa"),
		fixture("policy-v1"),
	}

	if code := Run(detailed(args...), &stdout, &stderr); code != exitOK {
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
		"-registry", filepath.Join("..", "..", "..", "taxonomy-registry", "opa"),
		"-data", filepath.Join("..", "..", "..", "fixtures", "vulnerable-bundle", "data"),
		fixture("policy-v1"),
	}

	if code := Run(detailed(args...), &stdout, &stderr); code != exitOK {
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
		"-registry", filepath.Join("..", "..", "..", "taxonomy-registry", "opa"),
		"-write-model", filepath.Join("..", "..", "..", "fixtures", "vulnerable-bundle", "write-model.yaml"),
		"-data", filepath.Join("..", "..", "..", "fixtures", "vulnerable-bundle", "data"),
		fixture("policy-v1"),
	}

	if code := Run(detailed(args...), &stdout, &stderr); code != exitOK {
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

// The split grant, seen from the command line: carol writing herself editor is
// a second escalation next to the chain, under the id of the pattern that finds
// it, with the value to write and the decision that allows it.
func TestRunReportsTheSplitGrant(t *testing.T) {
	var stdout, stderr bytes.Buffer
	args := []string{
		"-registry", filepath.Join("..", "..", "..", "taxonomy-registry", "opa"),
		"-write-model", filepath.Join("..", "..", "..", "fixtures", "vulnerable-bundle", "write-model.yaml"),
		"-data", filepath.Join("..", "..", "..", "fixtures", "vulnerable-bundle", "data"),
		fixture("policy-v1"),
	}

	if code := Run(detailed(args...), &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d (stderr: %s)", code, stderr.String())
	}

	out := stdout.String()
	for _, expected := range []string{
		"PTD-OPA-006 finding: carol can write editor into data.users[_].roles",
		"which data.quill.admin.allow allows, and data.quill.publish.allow then grants the position alice holds",
	} {
		if !strings.Contains(out, expected) {
			t.Errorf("the report does not contain %q:\n%s", expected, out)
		}
	}
	// The counter case is the withdraw branch on admin, a value support cannot
	// write, so no edge to the principal who holds admin comes out.
	if strings.Contains(out, "the position bob holds") {
		t.Errorf("an edge to bob, who holds admin support cannot write, was reported:\n%s", out)
	}
}

// The reading room setting decides for somebody no document names, and the
// report says who writes it. The console setting next to it does not come out:
// it only decides for somebody with a record.
func TestRunReportsTheGlobalSwitch(t *testing.T) {
	var stdout, stderr bytes.Buffer
	args := []string{
		"-registry", filepath.Join("..", "..", "..", "taxonomy-registry", "opa"),
		"-write-model", filepath.Join("..", "..", "..", "fixtures", "vulnerable-bundle", "write-model.yaml"),
		"-data", filepath.Join("..", "..", "..", "fixtures", "vulnerable-bundle", "data"),
		fixture("policy-v1"),
	}

	if code := Run(detailed(args...), &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d (stderr: %s)", code, stderr.String())
	}

	out := stdout.String()
	for _, expected := range []string{
		"PTD-OPA-008, A document every request shares decides for anybody who asks",
		"PTD-OPA-008 finding: data.settings.reading_room.open decides data.quill.platform.allow_reading_room",
		"and system:config-sync writes it",
	} {
		if !strings.Contains(out, expected) {
			t.Errorf("the report does not contain %q:\n%s", expected, out)
		}
	}
	if strings.Contains(out, "PTD-OPA-008 finding: data.settings.console.enabled") {
		t.Errorf("the console setting was reported, and it only decides for somebody with a record:\n%s", out)
	}
}

// Without the declaration of who writes what, the same run still measures
// everything else and claims no escalation: the chain rests on the one fact no
// policy can supply.
func TestRunClaimsNoEscalationWithoutTheWriteModel(t *testing.T) {
	var stdout, stderr bytes.Buffer
	args := []string{
		"-registry", filepath.Join("..", "..", "..", "taxonomy-registry", "opa"),
		"-data", filepath.Join("..", "..", "..", "fixtures", "vulnerable-bundle", "data"),
		fixture("policy-v1"),
	}

	if code := Run(detailed(args...), &stdout, &stderr); code != exitOK {
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
		"-registry", filepath.Join("..", "..", "..", "taxonomy-registry", "opa"),
		"-data", filepath.Join("..", "..", "..", "fixtures", "vulnerable-bundle", "data"),
		"-max-residuals", "2",
		fixture("policy-v1"),
	}

	if code := Run(detailed(args...), &stdout, &stderr); code != exitOK {
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
		"-registry", filepath.Join("..", "..", "..", "taxonomy-registry", "opa"),
		"-write-model", filepath.Join("..", "..", "..", "fixtures", "vulnerable-bundle", "write-model.yaml"),
		fixture("policy-v1"),
	}

	if code := Run(detailed(args...), &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d (stderr: %s)", code, stderr.String())
	}
	if out := stdout.String(); !strings.Contains(out, "write model: 6 of 11 paths covered (54%)") {
		t.Errorf("the coverage number is missing or wrong:\n%s", out)
	}
}

// A subject declared from outside replaces the guess about field names, and the
// report says it was declared. A declaration nothing reads is refused.
func TestRunTakesADeclaredSubject(t *testing.T) {
	var stdout, stderr bytes.Buffer

	if code := Run(detailed("-subject", "input.user", fixture("policy-v1")), &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}
	if out := stdout.String(); !strings.Contains(out, "request shape:  subject=input.user (level A, declared)") {
		t.Errorf("the report does not say the subject was declared:\n%s", out)
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run(detailed("-subject", "input.requester", fixture("policy-v1")), &stdout, &stderr); code != exitFailure {
		t.Errorf("exit code = %d, want %d", code, exitFailure)
	}
	if !strings.Contains(stderr.String(), "no decision reads the declared subject: input.requester") {
		t.Errorf("stderr does not say the subject is read by nothing: %s", stderr.String())
	}
}

// A decision declared to deny is listed with its direction, next to the ones
// the policy annotates, since every side in the report is counted from it.
func TestRunTakesADecisionDeclaredToDeny(t *testing.T) {
	var stdout, stderr bytes.Buffer

	if code := Run(detailed("-deny-entrypoint", "quill/tenant_policy/denied_mfa", fixture("policy-v1")), &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "decisions: 16\n") || !strings.Contains(out, "  data.quill.tenant_policy.denied_mfa, to deny\n") {
		t.Errorf("the report does not list the decision declared to deny:\n%s", out)
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
		{name: "everything and nothing", args: []string{"-v", "-quiet", fixture("policy-v1")}},
		{name: "a threshold that is none of them", args: []string{"-fail-on", "warnings", fixture("policy-v1")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			if code := Run(tt.args, &stdout, &stderr); code != exitUsage {
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

	if code := Run(detailed(filepath.Join("does", "not", "exist")), &stdout, &stderr); code != exitFailure {
		t.Errorf("exit code = %d, want %d", code, exitFailure)
	}
	if !strings.Contains(stderr.String(), "petard analyze:") {
		t.Errorf("stderr does not name the program: %s", stderr.String())
	}
}

// Importing the not keyword changes the form of every negation in a module: the
// flag on the expression becomes a not holding a body of its own. The fixture
// with that one line added to each file is the same policy, and the whole
// report has to come out the same, graph included, down to the lines, which
// move by the two the import takes.
func TestRunReadsTheFixtureTheSameWithNotImported(t *testing.T) {
	variant := t.TempDir()
	sources, err := filepath.Glob(filepath.Join(fixture("policy-v1"), "*.rego"))
	if err != nil || len(sources) == 0 {
		t.Fatalf("no fixture policy to rewrite (error %v)", err)
	}
	for _, source := range sources {
		text, err := os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(string(text), "\n")
		for i, line := range lines {
			if strings.HasPrefix(line, "package ") {
				lines[i] = line + "\n\nimport future.keywords.not"
				break
			}
		}
		if err := os.WriteFile(filepath.Join(variant, filepath.Base(source)), []byte(strings.Join(lines, "\n")), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// The comparison proves nothing unless the negations really changed form.
	bundle, err := opaengine.Load([]string{variant}, opaengine.ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	withBody := 0
	for _, module := range bundle.Compiler.Modules {
		ast.WalkExprs(module, func(expr *ast.Expr) bool {
			if _, isNot := expr.Terms.(*ast.Not); isNot {
				withBody++
			}
			return false
		})
	}
	if withBody == 0 {
		t.Fatal("no negation of the variant holds a body, so the two runs read the same AST")
	}

	report := func(policy string) string {
		t.Helper()
		var stdout, stderr bytes.Buffer
		args := detailed(
			"-graph",
			"-write-model", fixture("write-model.yaml"),
			"-data", fixture("data"),
			policy,
		)
		if code := Run(args, &stdout, &stderr); code != exitOK {
			t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
		}
		out := strings.ReplaceAll(stdout.String(), filepath.ToSlash(policy), "POLICY")
		out = regexp.MustCompile(`\.rego:\d+`).ReplaceAllString(out, ".rego:N")
		out = regexp.MustCompile(`source_line=\d+`).ReplaceAllString(out, "source_line=N")
		return regexp.MustCompile(` +`).ReplaceAllString(out, " ")
	}

	written, imported := report(fixture("policy-v1")), report(variant)
	if written != imported {
		writtenLines, importedLines := strings.Split(written, "\n"), strings.Split(imported, "\n")
		for i := range min(len(writtenLines), len(importedLines)) {
			if writtenLines[i] != importedLines[i] {
				t.Fatalf("the reports part at line %d:\n  as written:   %s\n  not imported: %s", i+1, writtenLines[i], importedLines[i])
			}
		}
		t.Fatalf("the reports differ in length: %d lines as written, %d with not imported", len(writtenLines), len(importedLines))
	}
}

// An enforcement point named with -pep declares the decisions by the names the
// product asks for, splits them by the side they land on, and says in the
// summary how much of the request it speaks about. The login policy of the
// Spacelift starter repository reads the teams and nothing else.
func TestRunTakesADeclaredEnforcementPoint(t *testing.T) {
	policy := filepath.Join(t.TempDir(), "login.rego")
	source := `package spacelift

admin { input.session.teams[_] == "DevOps" }
allow { input.session.member }
deny  { not allow }
`
	if err := os.WriteFile(policy, []byte(source), 0o600); err != nil {
		t.Fatalf("writing the policy: %v", err)
	}

	var stdout, stderr bytes.Buffer
	if code := Run(detailed("-pep", "spacelift-login", policy), &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}
	out := stdout.String()
	for _, expected := range []string{
		"decisions: 3\n",
		"  data.spacelift.deny, to deny\n",
		"The enforcement point is spacelift-login: it says who sets 2 of the 2 parts",
		`input.session.teams[_] == "DevOps" at `,
	} {
		if !strings.Contains(out, expected) {
			t.Errorf("the report does not say %q:\n%s", expected, out)
		}
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run(detailed("-pep", "no-such-product", policy), &stdout, &stderr); code != exitFailure {
		t.Errorf("exit code with an enforcement point nobody declared = %d, want %d", code, exitFailure)
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run(detailed("-pep", "spacelift-login", filepath.Join(fixture("policy-v1"), "review.rego")), &stdout, &stderr); code != exitFailure {
		t.Errorf("exit code on a bundle with none of the decisions = %d, want %d", code, exitFailure)
	}
	if !strings.Contains(stderr.String(), "the bundle has no rule by any of those names") {
		t.Errorf("stderr does not say the decisions are missing: %s", stderr.String())
	}
}

// With the gateway of the fixture declared, the scheduled export is a finding
// and the second factor next to it is nothing. Without the declaration the
// pattern does not run and the report says so: the policy reads the two the
// same way.
func TestRunReportsTheSelfAssertedExemption(t *testing.T) {
	gateway := filepath.Join("..", "..", "..", "fixtures", "vulnerable-bundle", "pep.yaml")

	var stdout, stderr bytes.Buffer
	if code := Run(detailed("-pep", gateway, fixture("policy-v1")), &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "PTD-OPA-009 finding: input.scheduled lifts a refusal in data.quill.tenant_policy.allow_export") {
		t.Errorf("the report does not name the scheduled export:\n%s", out)
	}
	if strings.Contains(out, "PTD-OPA-009 finding: input.mfa") || strings.Contains(out, "PTD-OPA-009 candidate") {
		t.Errorf("the report names more than the scheduled export:\n%s", out)
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run(detailed(fixture("policy-v1")), &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}
	if out := stdout.String(); !strings.Contains(out, "PTD-OPA-009  it asks who sets each part of the request") {
		t.Errorf("without the declaration the report does not say the pattern did not run:\n%s", out)
	}
}

// With the gateway and the write model declared, the group called security is
// a finding, and the same group by its id is nothing. Without the write model
// the same match is a candidate: nobody is named as able to pick the name.
func TestRunReportsTheGrantOnAName(t *testing.T) {
	gateway := filepath.Join("..", "..", "..", "fixtures", "vulnerable-bundle", "pep.yaml")
	model := filepath.Join("..", "..", "..", "fixtures", "vulnerable-bundle", "write-model.yaml")

	var stdout, stderr bytes.Buffer
	if code := Run(detailed("-pep", gateway, "-write-model", model, fixture("policy-v1")), &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "PTD-OPA-010 finding: data.quill.platform.allow_audit_log grants on a name in input.groups[_]") {
		t.Errorf("the report does not name the group called security:\n%s", out)
	}
	if strings.Contains(out, "PTD-OPA-010 finding: data.quill.platform.allow_audit_log grants on a name in input.group_ids") {
		t.Errorf("the report names the id of the group:\n%s", out)
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run(detailed("-pep", gateway, fixture("policy-v1")), &stdout, &stderr); code != exitOK {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}
	if out := stdout.String(); !strings.Contains(out, "PTD-OPA-010 candidate: data.quill.platform.allow_audit_log") {
		t.Errorf("without the write model the report does not keep the match as a candidate:\n%s", out)
	}
}
