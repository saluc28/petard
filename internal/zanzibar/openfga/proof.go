package openfga

import (
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/openfga/language/pkg/go/transformer"
	yaml "go.yaml.in/yaml/v3"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/saluc28/petard/internal/zanzibar"
)

// ErrProof is returned for a proof fga model test cannot be asked to run: a tuple
// OpenFGA would refuse, a check it cannot answer, or a model its transformer cannot
// write back.
var ErrProof = errors.New("openfga: no proof")

// ProofFiles writes a proof as a store file fga model test reads, name.fga.yaml: the
// model written back in the DSL by OpenFGA's own transformer, and one test for each
// state of the proof with the tuples of the state and its checks. fga model test passes
// on it while the escalation is open. dir is the directory the file is written under, as
// the user named it, for the command the file says to run; title is the lines the file
// starts with.
//
// fga model test runs each test on a store of its own, written with the tuples of the
// file and those of the test (internal/storetest/tests.go:33 and localtest.go:244 at
// openfga/cli v0.8.2), so the file has no tuples outside its tests and the tuples of a
// test are the whole store of its state.
//
// OpenFGA answers a check that waits on a condition it has no context for with an error,
// and an error fails the check whatever it expected (testresult.go:24 there). Such a
// check is asked under the context of the store's own checks that decides it, and a
// proof with a check no such context decides is not written.
func (s *Schema) ProofFiles(dir, name string, title []string, p *zanzibar.Proof) ([]zanzibar.ProofFile, error) {
	text, err := s.modelText()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrProof, err)
	}
	file := name + ".fga.yaml"

	tests := &yaml.Node{Kind: yaml.SequenceNode}
	for i, state := range p.States {
		test, err := s.proofTest(state, fmt.Sprintf("%d of %d, %s", i+1, len(p.States), p.Where(i)))
		if err != nil {
			return nil, err
		}
		tests.Content = append(tests.Content, test)
	}

	doc := &yaml.Node{Kind: yaml.MappingNode, Content: []*yaml.Node{
		key("name"), scalar(name),
		key("model"), {Kind: yaml.ScalarNode, Style: yaml.LiteralStyle, Value: strings.TrimSpace(text)},
		key("tests"), tests,
	}}
	header := append(append([]string{}, title...), "",
		"fga model test passes on this file while the escalation is open:",
		"  fga model test --tests "+path.Join(dir, file))
	doc.HeadComment = strings.Join(header, "\n")
	content, err := zanzibar.ProofYAML(doc)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrProof, err)
	}
	return []zanzibar.ProofFile{{Path: file, Content: content}}, nil
}

// modelText writes the model back in the DSL, through its JSON. The transformer from the
// DSL leaves a direct assignment without the message inside it
// (transformer/dsltojson.go:310 at language v0.3.2), and the one back to the DSL reads
// such an assignment as missing (jsontodsl.go:207 there) and refuses the relation. Read
// back from JSON, the assignment has its message.
func (s *Schema) modelText() (string, error) {
	encoded, err := protojson.Marshal(s.model)
	if err != nil {
		return "", err
	}
	text, err := transformer.TransformJSONStringToDSL(string(encoded))
	if err != nil {
		return "", err
	}
	return *text, nil
}

// proofTest is one state of a proof as a test of a store file.
func (s *Schema) proofTest(state zanzibar.ProofState, name string) (*yaml.Node, error) {
	tuples := &yaml.Node{Kind: yaml.SequenceNode}
	for _, r := range state.Relationships {
		if err := s.Admit(r); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrProof, err)
		}
		tuple := &yaml.Node{Kind: yaml.MappingNode, Content: []*yaml.Node{
			key("user"), scalar(r.Subject.String()),
			key("relation"), scalar(r.Relation),
			key("object"), scalar(r.Resource.String()),
		}}
		if r.Caveat != nil {
			condition := &yaml.Node{Kind: yaml.MappingNode, Content: []*yaml.Node{key("name"), scalar(r.Caveat.Name)}}
			if len(r.Caveat.Context) > 0 {
				context, err := value(r.Caveat.Context)
				if err != nil {
					return nil, fmt.Errorf("%w: %s: %w", ErrProof, r, err)
				}
				condition.Content = append(condition.Content, key("context"), context)
			}
			tuple.Content = append(tuple.Content, key("condition"), condition)
		}
		tuples.Content = append(tuples.Content, tuple)
	}

	checks := &yaml.Node{Kind: yaml.SequenceNode}
	for _, c := range state.Checks {
		check, err := proofCheck(c)
		if err != nil {
			return nil, err
		}
		checks.Content = append(checks.Content, check)
	}

	test := &yaml.Node{Kind: yaml.MappingNode, Content: []*yaml.Node{
		key("name"), scalar(name),
	}}
	if len(state.Made) > 0 {
		test.Content = append(test.Content, key("description"), scalar(strings.Join(state.Made, "; ")))
	}
	if len(tuples.Content) > 0 {
		test.Content = append(test.Content, key("tuples"), tuples)
	}
	test.Content = append(test.Content, key("check"), checks)
	return test, nil
}

// proofCheck is one check of a proof as a check of a store file, under a comment that
// says what it shows. A check that waits on a condition is asked under the context that
// decides it.
func proofCheck(c zanzibar.ProofCheck) (*yaml.Node, error) {
	asked := c.Assertion
	if asked.Level == zanzibar.Conditional {
		if c.Decided == nil {
			return nil, fmt.Errorf("%w: %s waits on a condition, which OpenFGA answers with an error, and no check of the store supplies a context that decides it", ErrProof, asked)
		}
		asked = *c.Decided
	}
	check := &yaml.Node{Kind: yaml.MappingNode, HeadComment: c.Why, Content: []*yaml.Node{
		key("user"), scalar(asked.Subject.String()),
		key("object"), scalar(asked.Resource.String()),
	}}
	if asked.Context != nil {
		context, err := value(asked.Context)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %w", ErrProof, asked, err)
		}
		check.Content = append(check.Content, key("context"), context)
	}
	expected := "false"
	if asked.Level == zanzibar.Yes {
		expected = "true"
	}
	check.Content = append(check.Content, key("assertions"), &yaml.Node{Kind: yaml.MappingNode, Content: []*yaml.Node{
		key(asked.Name), {Kind: yaml.ScalarNode, Tag: "!!bool", Value: expected},
	}})
	return check, nil
}

// value is a context written as YAML, its keys in order so the same proof writes the
// same bytes.
func value(context map[string]any) (*yaml.Node, error) {
	out := &yaml.Node{Kind: yaml.MappingNode}
	keys := make([]string, 0, len(context))
	for k := range context {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		var v yaml.Node
		if err := v.Encode(context[k]); err != nil {
			return nil, err
		}
		out.Content = append(out.Content, key(k), &v)
	}
	return out, nil
}

// key is a key of a YAML mapping.
func key(name string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Value: name}
}

// scalar is a string value, quoted where YAML would read it as something else.
func scalar(text string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: text}
}
