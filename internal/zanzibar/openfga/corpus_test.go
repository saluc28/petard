package openfga

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	yaml "go.yaml.in/yaml/v3"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/saluc28/petard/internal/zanzibar"
)

// corpusEnv names the directory of OpenFGA's own check tests, assets/tests in a
// checkout of OpenFGA, which hold models, tuples and the answers OpenFGA's suite
// holds OpenFGA to (tests/check/check.go:63-91 at fb8e7df8):
//
//	PETARD_OPENFGA_CORPUS="$(go list -m -f '{{.Dir}}' github.com/openfga/openfga)/assets/tests" go test ./internal/zanzibar/openfga -run TestCorpus -v
const corpusEnv = "PETARD_OPENFGA_CORPUS"

// The codes of OpenFGA's refusals that this tells apart. validationErrorCode is the
// first of the validation codes (pkg/server/errors/encoded_errors.go:16 at
// fb8e7df8): a request it does not take, or a condition it cannot decide, a parameter
// missing from the context among them. depthErrorCode is a check past its resolution
// depth, availability and not an answer (section 1 of the definitions).
const (
	validationErrorCode = 2000
	depthErrorCode      = 2002
)

type corpusFile struct {
	Tests []corpusTest `yaml:"tests"`
}

type corpusTest struct {
	Name   string        `yaml:"name"`
	Stages []corpusStage `yaml:"stages"`
}

type corpusStage struct {
	Model           string            `yaml:"model"`
	Tuples          []corpusTuple     `yaml:"tuples"`
	CheckAssertions []corpusAssertion `yaml:"checkAssertions"`
}

type corpusTuple struct {
	User      string `yaml:"user"`
	Relation  string `yaml:"relation"`
	Object    string `yaml:"object"`
	Condition *struct {
		Name    string         `yaml:"name"`
		Context map[string]any `yaml:"context"`
	} `yaml:"condition"`
}

type corpusAssertion struct {
	Tuple            corpusTuple    `yaml:"tuple"`
	ContextualTuples []corpusTuple  `yaml:"contextualTuples"`
	Context          map[string]any `yaml:"context"`
	Expectation      bool           `yaml:"expectation"`
	ErrorCode        int            `yaml:"errorCode"`
}

func (c corpusTuple) key(t *testing.T) *openfgav1.TupleKey {
	t.Helper()
	key := &openfgav1.TupleKey{User: c.User, Relation: c.Relation, Object: c.Object}
	if c.Condition != nil {
		context, err := structpb.NewStruct(c.Condition.Context)
		if err != nil {
			t.Fatalf("context of %s: %v", key, err)
		}
		key.Condition = &openfgav1.RelationshipCondition{Name: c.Condition.Name, Context: context}
	}
	return key
}

// corpusCount is what a run over the corpus found.
type corpusCount struct {
	agreed, refused, undecided, inline, wildcard, depth int
}

// The lowering against the answers of OpenFGA's own suite. For every stage of every
// test it compiles the model, keeps the tuples of this stage and the ones before it
// that the model admits, as a check of OpenFGA reads them, and asks each assertion.
//
// An answer of OpenFGA's is yes or no, or a refusal. Yes and no have to match. A
// refusal of the request itself, an unknown type or a contextual tuple the model does
// not admit, has to be refused here as well. A condition it cannot decide has to
// read as Conditional, which is what stands in for it.
//
// Three kinds have no answer to compare, and are counted apart rather than passed: a
// check resting on an inline condition, which is read as Conditional; a wildcard asked
// as a subject, which OpenFGA answers and the engine has no reason to ask; and a check
// past OpenFGA's resolution depth, which section 1 of the definitions leaves out.
func TestCorpus(t *testing.T) {
	dir := os.Getenv(corpusEnv)
	if dir == "" {
		t.Skipf("%s is not set: this runs over OpenFGA's own check tests", corpusEnv)
	}
	paths, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatalf("%s=%s holds no test file", corpusEnv, dir)
	}

	var total corpusCount
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var file corpusFile
		if err := yaml.Unmarshal(raw, &file); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		for _, test := range file.Tests {
			t.Run(filepath.Base(path)+"/"+test.Name, func(t *testing.T) {
				runCorpusTest(t, test, &total)
			})
		}
	}
	t.Logf("OpenFGA's suite agrees on %d answers and %d refusals, and %d conditions it cannot decide read as open; left out: %d on an inline condition, %d asking for a wildcard, %d past its depth",
		total.agreed, total.refused, total.undecided, total.inline, total.wildcard, total.depth)
}

func runCorpusTest(t *testing.T, test corpusTest, total *corpusCount) {
	var written []*openfgav1.TupleKey
	for number, stage := range test.Stages {
		schema, err := Compile(fmt.Sprintf("%s stage %d", test.Name, number), stage.Model)
		if err != nil {
			t.Fatalf("stage %d: %v", number, err)
		}
		for _, tuple := range stage.Tuples {
			written = append(written, tuple.key(t))
		}
		stored := admitted(schema, written)

		for i, assertion := range stage.CheckAssertions {
			label := fmt.Sprintf("stage %d assertion %d: %s#%s@%s %v", number, i, assertion.Tuple.Object, assertion.Tuple.Relation, assertion.Tuple.User, assertion.Context)
			checkAssertion(t, schema, stored, assertion, label, total)
		}
	}
}

// admitted is the tuples a model admits, the way a check of OpenFGA reads them.
func admitted(schema *Schema, keys []*openfgav1.TupleKey) []zanzibar.Relationship {
	var out []zanzibar.Relationship
	for _, key := range keys {
		r := LowerTuple(zanzibar.Position{}, key)
		if schema.Admit(r) == nil {
			out = append(out, r)
		}
	}
	return out
}

func checkAssertion(t *testing.T, schema *Schema, stored []zanzibar.Relationship, a corpusAssertion, label string, total *corpusCount) {
	t.Helper()

	asked := LowerTuple(zanzibar.Position{}, &openfgav1.TupleKey{User: a.Tuple.User, Relation: a.Tuple.Relation, Object: a.Tuple.Object})
	refusal := requestRefusal(schema, asked)

	tuples := stored
	for _, contextual := range a.ContextualTuples {
		r := LowerTuple(zanzibar.Position{}, contextual.key(t))
		if err := schema.Admit(r); err != nil {
			refusal = err
			continue
		}
		tuples = append(tuples[:len(tuples):len(tuples)], r)
	}

	switch {
	case a.ErrorCode == depthErrorCode:
		total.depth++
		return
	case a.ErrorCode != 0 && refusal != nil:
		total.refused++
		return
	case refusal != nil:
		t.Errorf("%s: refused here (%v), and OpenFGA answers", label, refusal)
		return
	case a.ErrorCode != 0 && a.ErrorCode != validationErrorCode:
		t.Errorf("%s: OpenFGA refuses it with %d, and nothing here does", label, a.ErrorCode)
		return
	}

	checker := zanzibar.NewChecker(schema.Model, tuples, schema, time.Now())
	got, err := checker.Check(asked.Resource, asked.Relation, asked.Subject, a.Context)
	switch {
	case errors.Is(err, zanzibar.ErrWildcardSubject):
		total.wildcard++
	case err != nil:
		t.Errorf("%s: %v", label, err)
	case got.Level == zanzibar.Conditional && restsOnInline(tuples):
		total.inline++
	case a.ErrorCode != 0:
		if got.Level != zanzibar.Conditional {
			t.Errorf("%s: OpenFGA cannot decide it, and this says %s", label, got.Level)
			return
		}
		total.undecided++
	case (got.Level == zanzibar.Yes) != a.Expectation || got.Level == zanzibar.Conditional:
		t.Errorf("%s: OpenFGA says %v, this says %s", label, a.Expectation, got.Level)
	default:
		total.agreed++
	}
}

// requestRefusal is what OpenFGA checks of a request before it answers
// (internal/validation/validation.go:19-33, :389-482 at fb8e7df8), which the engine
// has no reason to: nothing it asks names what the model does not declare.
func requestRefusal(schema *Schema, asked zanzibar.Relationship) error {
	t := schema.Model.Type(asked.Resource.Type)
	switch {
	case t == nil:
		return fmt.Errorf("type %s is not declared", asked.Resource.Type)
	case !t.Declares(asked.Relation):
		return fmt.Errorf("%s#%s is not declared", asked.Resource.Type, asked.Relation)
	}
	subject := schema.Model.Type(asked.Subject.Type)
	switch {
	case subject == nil:
		return fmt.Errorf("type %s is not declared", asked.Subject.Type)
	case asked.Subject.Relation != "" && !subject.Declares(asked.Subject.Relation):
		return fmt.Errorf("%s#%s is not declared", asked.Subject.Type, asked.Subject.Relation)
	}
	return nil
}

func restsOnInline(tuples []zanzibar.Relationship) bool {
	for _, r := range tuples {
		if r.Caveat != nil && r.Caveat.Name == inlineExpression {
			return true
		}
	}
	return false
}
