package spicedb

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/authzed/spicedb/pkg/caveats"
	caveattypes "github.com/authzed/spicedb/pkg/caveats/types"
	core "github.com/authzed/spicedb/pkg/proto/core/v1"
	"github.com/authzed/spicedb/pkg/schemadsl/generator"
	"github.com/authzed/spicedb/pkg/tuple"
	yaml "go.yaml.in/yaml/v3"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/saluc28/petard/internal/zanzibar"
)

// ErrProof is returned for a proof SpiceDB cannot be asked to run: a relationship it
// would refuse, or a schema its generator cannot write back whole.
var ErrProof = errors.New("spicedb: no proof")

// ProofFiles writes a proof as validation files zed validate reads, one for each state of
// the proof, in a directory of its own named name. Each holds the schema written back by
// SpiceDB's own generator, the relationships of the state, and the checks of the state as
// assertions: zed validate passes on all of them while the escalation is open. dir is the
// directory the files are written under, as the user named it, for the command each file
// says to run; title is the lines each file starts with.
//
// SpiceDB answers a check that waits on a caveat with no context as caveated, which an
// assertion states directly (assertCaveated), so a proof asks every check with no
// context.
func (s *Schema) ProofFiles(dir, name string, title []string, p *zanzibar.Proof) ([]zanzibar.ProofFile, error) {
	text, whole, err := generator.GenerateSchema(context.Background(), s.definitions)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrProof, err)
	}
	if !whole {
		return nil, fmt.Errorf("%w: SpiceDB's generator cannot write the schema back whole", ErrProof)
	}
	text = trimComments(text)

	paths := make([]string, len(p.States))
	run := make([]string, len(p.States))
	for i, state := range p.States {
		paths[i] = path.Join(name, fmt.Sprintf("%d-%s.yaml", i+1, stateName(state, i == len(p.States)-1)))
		run[i] = path.Join(dir, paths[i])
	}

	for _, state := range p.States {
		for _, c := range state.Checks {
			if loop := s.Model.LoopFrom(state.Relationships, c.Resource); loop != "" {
				return nil, fmt.Errorf("%w: a check of %s can follow the relationships round a loop through %s, which SpiceDB follows to its depth limit and fails the check on wherever it waits for every result, as on the base of an exclusion (internal/graph/check.go:1106 and :1198 at v1.57.0)", ErrProof, c.Resource, loop)
			}
		}
	}

	files := make([]zanzibar.ProofFile, 0, len(p.States))
	for i, state := range p.States {
		lines := make([]string, 0, len(state.Relationships))
		for _, r := range state.Relationships {
			if err := s.Admit(r); err != nil {
				return nil, err
			}
			line, err := relationshipText(r)
			if err != nil {
				return nil, fmt.Errorf("%w: %s: %w", ErrProof, r, err)
			}
			lines = append(lines, line)
		}

		header := append(append([]string{}, title...), "", fmt.Sprintf("State %d of %d, %s.", i+1, len(p.States), p.Where(i)))
		for _, made := range state.Made {
			header = append(header, "  "+made)
		}
		header = append(header, "", "zed validate passes on every file of this proof while the escalation is open:",
			"  zed validate "+strings.Join(run, " "))

		doc := &yaml.Node{Kind: yaml.MappingNode, Content: []*yaml.Node{
			key("schema"), literal(text),
			key("relationships"), literal(strings.Join(lines, "\n")),
			key("assertions"), assertions(state.Checks),
		}}
		doc.HeadComment = strings.Join(header, "\n")
		content, err := zanzibar.ProofYAML(doc)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrProof, err)
		}
		files = append(files, zanzibar.ProofFile{Path: paths[i], Content: content})
	}
	return files, nil
}

// Admit says whether SpiceDB would store a relationship of this schema, asking what it
// asks of a write (internal/relationships/validation.go:145-269 at v1.57.0): identifiers
// it can store, a relation of the resource that is not a permission, a subject of a form
// the relation allows with the same caveat and the same presence of an expiration, and a
// caveat context whose values have the types of the caveat's parameters.
func (s *Schema) Admit(r zanzibar.Relationship) error {
	if err := tuple.ValidateResourceID(r.Resource.ID); err != nil {
		return fmt.Errorf("%w: %s: %w", ErrProof, r, err)
	}
	if err := tuple.ValidateSubjectID(r.Subject.ID); err != nil {
		return fmt.Errorf("%w: %s: %w", ErrProof, r, err)
	}
	t := s.Model.Type(r.Resource.Type)
	if t == nil {
		return fmt.Errorf("%w: %s: type %s is not defined", ErrProof, r, r.Resource.Type)
	}
	relation := t.Relation(r.Relation)
	if relation == nil {
		return fmt.Errorf("%w: %s: %s#%s is not a relation", ErrProof, r, r.Resource.Type, r.Relation)
	}
	subject := s.Model.Type(r.Subject.Type)
	if subject == nil || (r.Subject.Relation != "" && !subject.Declares(r.Subject.Relation)) {
		return fmt.Errorf("%w: %s: the subject is not defined", ErrProof, r)
	}

	caveat := ""
	if r.Caveat != nil {
		caveat = r.Caveat.Name
	}
	wildcard := r.Subject.ID == zanzibar.WildcardID
	allowed := false
	for _, a := range relation.Allowed {
		if a.Type == r.Subject.Type && a.Relation == r.Subject.Relation && a.Wildcard == wildcard &&
			a.Caveat == caveat && a.Expiration == (r.Expires != nil) {
			allowed = true
			break
		}
	}
	if !allowed {
		return fmt.Errorf("%w: %s: %s#%s does not allow this subject%s", ErrProof, r, r.Resource.Type, r.Relation, formText(caveat, r.Expires != nil))
	}

	if caveat != "" && len(r.Caveat.Context) > 0 {
		if _, err := caveats.ConvertContextToParameters(caveattypes.Default.TypeSet, r.Caveat.Context, s.refs[caveat], caveats.ErrorForUnknownParameters); err != nil {
			return fmt.Errorf("%w: %s: %w", ErrProof, r, err)
		}
	}

	// The pattern a subject identifier is held to binds only its start
	// (pkg/tuple/parsing.go:21 and :47 at v1.57.0), so one the parser of a
	// validation file refuses can pass it. Reading the relationship back is the
	// question the file asks.
	text, err := relationshipText(r)
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrProof, r, err)
	}
	if _, err := tuple.Parse(text); err != nil {
		return fmt.Errorf("%w: %s: a validation file cannot hold it: %w", ErrProof, r, err)
	}
	return nil
}

// trimComments takes the spaces off the end of the comment lines of a schema. The
// generator writes an empty line of a comment as "// ", and YAML cannot keep a block
// of text as it is when a line of it ends in a space, so the schema would be written
// as one quoted line. A comment is all a line that starts with // holds, so the schema
// is the same.
func trimComments(text string) string {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			lines[i] = strings.TrimRight(line, " \t")
		}
	}
	return strings.Join(lines, "\n")
}

// formText says what a relationship carries besides its subject, for an error that it
// is not a form the relation allows.
func formText(caveat string, expires bool) string {
	switch {
	case caveat != "" && expires:
		return " with caveat " + caveat + " and an expiration"
	case caveat != "":
		return " with caveat " + caveat
	case expires:
		return " with an expiration"
	}
	return " without a caveat"
}

// relationshipText writes a relationship in the notation of a validation file, with
// its caveat and expiration, the way SpiceDB writes one.
func relationshipText(r zanzibar.Relationship) (string, error) {
	subjectRelation := r.Subject.Relation
	if subjectRelation == "" {
		subjectRelation = ellipsis
	}
	rel := tuple.Relationship{
		RelationshipReference: tuple.RelationshipReference{
			Resource: tuple.ObjectAndRelation{ObjectType: r.Resource.Type, ObjectID: r.Resource.ID, Relation: r.Relation},
			Subject:  tuple.ObjectAndRelation{ObjectType: r.Subject.Type, ObjectID: r.Subject.ID, Relation: subjectRelation},
		},
	}
	if r.Expires != nil {
		// The parser reads an expiration in UTC alone, written with Z
		// (pkg/tuple/parsing.go:42 at v1.57.0).
		utc := r.Expires.UTC()
		rel.OptionalExpiration = &utc
	}
	if r.Caveat != nil {
		rel.OptionalCaveat = &core.ContextualizedCaveat{CaveatName: r.Caveat.Name}
		if len(r.Caveat.Context) > 0 {
			context, err := structpb.NewStruct(r.Caveat.Context)
			if err != nil {
				return "", err
			}
			rel.OptionalCaveat.Context = context
		}
	}
	return tuple.String(rel)
}

// assertions are the checks of a state as the assertions block of a validation file,
// each under a comment that says what it shows.
func assertions(checks []zanzibar.ProofCheck) *yaml.Node {
	byLevel := map[zanzibar.Level]*yaml.Node{}
	for _, c := range checks {
		list := byLevel[c.Level]
		if list == nil {
			list = &yaml.Node{Kind: yaml.SequenceNode}
			byLevel[c.Level] = list
		}
		item := &yaml.Node{Kind: yaml.ScalarNode, Value: c.String(), HeadComment: c.Why}
		list.Content = append(list.Content, item)
	}
	out := &yaml.Node{Kind: yaml.MappingNode}
	for _, name := range []struct {
		name  string
		level zanzibar.Level
	}{{"assertTrue", zanzibar.Yes}, {"assertCaveated", zanzibar.Conditional}, {"assertFalse", zanzibar.No}} {
		if list := byLevel[name.level]; list != nil {
			out.Content = append(out.Content, key(name.name), list)
		}
	}
	return out
}

// stateName names the file of a state.
func stateName(state zanzibar.ProofState, last bool) string {
	switch {
	case state.Writes == 0:
		return "before"
	case last:
		return "after"
	}
	return fmt.Sprintf("after-write-%d", state.Writes)
}

// key is a key of a YAML mapping.
func key(name string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Value: name}
}

// literal is a block of text written as it is.
func literal(text string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Style: yaml.LiteralStyle, Value: text}
}
