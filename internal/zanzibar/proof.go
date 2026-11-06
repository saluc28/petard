package zanzibar

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	yaml "go.yaml.in/yaml/v3"
)

// Proof is an escalation the way the product itself can be asked to show it, with its
// own checker and without petard: the store at each point of the witness where something
// is asked, and what petard expects the product to answer there. The first state is the
// one the witness starts from, where the coalition does not hold the permission it
// raises, and the last comes after the last write, where it does. Before each write the
// write model puts behind a permission, the coalition holds that permission, which is
// what the application checks before it lets the write through. A file of the product
// built from a proof passes while the escalation is open.
//
// What a proof cannot show is that the application checks what the write model says it
// checks: that is declared, not read from the product.
type Proof struct {
	States []ProofState
}

// ProofState is the store after some of the writes of a witness, and what a proof asks
// of it.
type ProofState struct {
	// Writes is how many writes of the witness the state comes after, 0 for the state
	// the witness starts from.
	Writes int

	// Made words the writes made since the state before, one line each, the way a
	// report words a witness.
	Made []string

	Relationships []Relationship
	Checks        []ProofCheck
}

// Where says where in the witness the state at index i of the proof is: before the
// writes, after one or some of them, or after them all.
func (p *Proof) Where(i int) string {
	state := p.States[i]
	switch {
	case state.Writes == 0:
		return "before the writes"
	case i == len(p.States)-1:
		return "after the writes"
	case len(state.Made) == 1:
		return fmt.Sprintf("after write %d", state.Writes)
	}
	return fmt.Sprintf("after writes %d to %d", state.Writes-len(state.Made)+1, state.Writes)
}

// ProofCheck is one check of a proof: the assertion, with the level petard expects of
// it when the check brings no context, and what it shows.
type ProofCheck struct {
	Assertion

	// Decided is the same check under a context one of the sample's own checks
	// supplies, with the level petard expects there, for a check that without a
	// context waits on a condition. A product that answers a check it cannot decide
	// with an error, as OpenFGA does, is asked it this way. It is nil for a check
	// decided without a context, and for one no context of the sample decides the
	// way the proof needs.
	Decided *Assertion

	// Why says what the check shows, in a sentence a file of the product can carry
	// as a comment.
	Why string
}

// ProofFile is one file of a proof as the test runner of a product reads it, at a path
// relative to the directory the proofs are written to.
type ProofFile struct {
	Path    string
	Content []byte
}

// ProofYAML writes a file of a proof, a YAML document, indented by two spaces as the
// files of both products are usually written.
func ProofYAML(doc *yaml.Node) ([]byte, error) {
	var b bytes.Buffer
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// errNoReplay is the failure of a proof whose replay does not give what the search
// found.
var errNoReplay = errors.New("the writes do not give the same answers once applied as the product applies them")

// proofOf replays a witness over the state it starts from, applying each write the way
// the product does, and asks at each step what the escalation rests on.
//
// The product keeps one tuple to a resource, relation and subject, so a write of a
// tuple that is already there in another form replaces it, where the search keeps
// both. When that changes an answer, the replay no longer gives the levels the search
// found, and there is no proof. A check the product fails on a loop has none either:
// SpiceDB answers it with an error at its depth limit, which no assertion states.
func proofOf(s Sample, esc Escalation) (*Proof, error) {
	if len(esc.coalition) == 0 {
		return nil, errNoReplay
	}
	r := replay{sample: s, now: Options{Now: s.Now}.now(), contexts: contextsOf(s.Assertions)}
	store := productState{}
	for _, t := range esc.start {
		if t.Expires == nil || t.Expires.After(r.now) {
			store.put(t)
		}
	}
	coalition := slices.Clone(esc.coalition)

	var proof Proof
	state := ProofState{Relationships: store.list()}
	checker := r.checker(state.Relationships)
	before, err := r.ask(checker, Assertion{Resource: esc.Object, Name: esc.Permission, Subject: Subject{Object: coalition[0]}}, No)
	if err != nil {
		return nil, err
	}
	if before.Level != esc.Before {
		return nil, errNoReplay
	}
	before.Why = "Before the writes, " + holdsText(before.Assertion) + "."
	state.Checks = append(state.Checks, before)

	var made []string
	for i, step := range esc.Writes {
		gates, err := r.gates(checker, step, coalition)
		if err != nil {
			return nil, err
		}
		state.Checks = append(state.Checks, gates...)
		if len(state.Checks) > 0 {
			proof.States = append(proof.States, state)
			made = nil
		}

		switch {
		case step.Relationship.Relation == "":
		case step.Delete:
			store.drop(step.Relationship)
		default:
			store.put(step.Relationship)
		}
		if step.Creation != nil && !containsObject(coalition, step.Created) {
			coalition = append(coalition, step.Created)
		}
		made = append(made, stepText(step))
		state = ProofState{Writes: i + 1, Made: made, Relationships: store.list()}
		checker = r.checker(state.Relationships)
	}

	after, err := r.held(checker, esc.Object, esc.Permission, coalition, Object{})
	if err != nil {
		return nil, err
	}
	if after.Level != esc.After {
		return nil, errNoReplay
	}
	after.Why = "After the writes, " + holdsText(after.Assertion) + "."
	state.Checks = append(state.Checks, after)
	proof.States = append(proof.States, state)
	return &proof, nil
}

// replay is what a proof asks its checks with.
type replay struct {
	sample   Sample
	now      time.Time
	contexts []map[string]any
}

func (r replay) checker(state []Relationship) *Checker {
	return NewChecker(r.sample.Model, state, r.sample.Caveats, r.now)
}

// gates are the checks the write model says the application makes before it lets a
// step through, asked in the state before the step: the permission a rule's writer
// holds on the resource, the permission a rule's subject holds there, and for a
// creation the permission held on each object it is made in. A gate anyone passes asks
// nothing.
func (r replay) gates(checker *Checker, step WriteStep, coalition []Object) ([]ProofCheck, error) {
	var out []ProofCheck
	switch {
	case step.Rule != nil:
		rule := step.Rule
		verb := "write"
		if step.Delete {
			verb = "delete"
		}
		if rule.Gate.Holds != "" {
			c, err := r.held(checker, step.Relationship.Resource, rule.Gate.Holds, coalition, step.Writer.Object)
			if err != nil {
				return nil, err
			}
			if c.Level < Conditional {
				return nil, errNoReplay
			}
			c.Why = fmt.Sprintf("The write model lets %s on %s %s %s%s, and %s holds it.",
				gatePhrase(rule.Gate), step.Relationship.Resource, verb, step.Relationship, declaredAt(rule.Position), c.Subject)
			out = append(out, c)
		}
		subject := step.Relationship.Subject
		if rule.Subject.Holds != "" && subject.ID != WildcardID {
			c, err := r.ask(checker, Assertion{Resource: step.Relationship.Resource, Name: rule.Subject.Holds, Subject: subject}, Yes)
			if err != nil {
				return nil, err
			}
			if c.Level < Conditional {
				return nil, errNoReplay
			}
			c.Why = fmt.Sprintf("The rule lets the %s name %s, which holds %s on %s.", verb, subject, rule.Subject.Holds, step.Relationship.Resource)
			out = append(out, c)
		}
	case step.Creation != nil:
		for _, on := range step.Creation.On {
			in, ok := step.On[on.Type]
			if on.Gate.Holds == "" || !ok {
				continue
			}
			c, err := r.held(checker, in, on.Gate.Holds, coalition, step.Writer.Object)
			if err != nil {
				return nil, err
			}
			if c.Level < Conditional {
				return nil, errNoReplay
			}
			c.Why = fmt.Sprintf("The write model lets %s on %s create %s in it%s, and %s holds it.",
				gatePhrase(on.Gate), in, step.Created, declaredAt(step.Creation.Position), c.Subject)
			out = append(out, c)
		}
	}
	return out, nil
}

// held asks the members of the coalition for a permission on a resource and keeps the
// first that holds it at the highest level any of them does, the writer first when it
// is one of them, since that is who the search found making the write.
func (r replay) held(checker *Checker, resource Object, permission string, coalition []Object, writer Object) (ProofCheck, error) {
	members := coalition
	if containsObject(coalition, writer) {
		members = append([]Object{writer}, slices.DeleteFunc(slices.Clone(coalition), func(o Object) bool { return o == writer })...)
	}
	var best ProofCheck
	for i, member := range members {
		c, err := r.ask(checker, Assertion{Resource: resource, Name: permission, Subject: Subject{Object: member}}, Yes)
		if err != nil {
			return ProofCheck{}, err
		}
		if i == 0 || c.Level > best.Level {
			best = c
		}
		if best.Level == Yes {
			break
		}
	}
	return best, nil
}

// ask answers a check with no context, and, when it waits on a condition, looks among
// the contexts of the sample for one under which it is the level a proof needs, want.
func (r replay) ask(checker *Checker, a Assertion, want Level) (ProofCheck, error) {
	result, err := checker.Check(a.Resource, a.Name, a.Subject, nil)
	if err != nil {
		return ProofCheck{}, err
	}
	if result.Cycle && result.Level != Yes {
		return ProofCheck{}, fmt.Errorf("checking %s goes round a loop in the relationships, on which SpiceDB fails at its depth limit rather than answering", a)
	}
	a.Level = result.Level
	c := ProofCheck{Assertion: a}
	if result.Level != Conditional {
		return c, nil
	}
	for _, context := range r.contexts {
		under, err := checker.Check(a.Resource, a.Name, a.Subject, context)
		if err != nil {
			return ProofCheck{}, err
		}
		if under.Level == want && !under.Cycle {
			decided := a
			decided.Context = context
			decided.Level = want
			c.Decided = &decided
			break
		}
	}
	return c, nil
}

// contextsOf are the contexts the checks of a sample supply, each once, in the order
// the checks come.
func contextsOf(assertions []Assertion) []map[string]any {
	var out []map[string]any
	seen := map[string]bool{}
	for _, a := range assertions {
		if a.Context == nil {
			continue
		}
		key, err := json.Marshal(a.Context)
		if err != nil || seen[string(key)] {
			continue
		}
		seen[string(key)] = true
		out = append(out, a.Context)
	}
	return out
}

// holdsText words a check as what its subject holds, at the level it has.
func holdsText(a Assertion) string {
	held := fmt.Sprintf("%s on %s", a.Name, a.Resource)
	switch a.Level {
	case Yes:
		return fmt.Sprintf("%s holds %s", a.Subject, held)
	case Conditional:
		return fmt.Sprintf("%s holds %s only under a condition", a.Subject, held)
	}
	return fmt.Sprintf("%s does not hold %s", a.Subject, held)
}

// declaredAt is where a rule was declared, as a parenthesis after what it allows, or
// nothing when the source did not say.
func declaredAt(p Position) string {
	if p.File == "" {
		return ""
	}
	return " (" + p.String() + ")"
}

// productState is a store as the product keeps it: one tuple to a resource, relation
// and subject, so a write of a tuple already there in another form replaces it, and a
// delete takes it whatever it carries.
type productState struct {
	order []Relationship
}

func (p *productState) put(r Relationship) {
	if i := p.index(r); i >= 0 {
		p.order[i] = r
		return
	}
	p.order = append(p.order, r)
}

func (p *productState) drop(r Relationship) {
	if i := p.index(r); i >= 0 {
		p.order = slices.Delete(p.order, i, i+1)
	}
}

func (p *productState) index(r Relationship) int {
	identity := tupleIdentity(r)
	return slices.IndexFunc(p.order, func(t Relationship) bool { return tupleIdentity(t) == identity })
}

func (p *productState) list() []Relationship { return slices.Clone(p.order) }
