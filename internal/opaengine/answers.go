package opaengine

import (
	"fmt"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
)

// This file is about a decision that answers with a value: default verdict :=
// "scan", then "blocked", "allowed" or "clean" as the rules decide. Such a rule
// is defined for every request, the ones it refuses included, and which of its
// answers lets a request through is in what the enforcement point does with the
// value. The policy does not say, so it is declared with the decision, as
// data.app.verdict=allowed, and three things follow from it: what is asked of
// OPA, which rules of the decision are on which side, and what a report prints.

// declaredAnswers is what the declarations of one decision say about its
// answers, kept while they are read so that two of them that cannot both be
// meant are refused.
type declaredAnswers struct {
	terms []*ast.Term

	// grants and denies say on which side the decision was declared, with an
	// answer or without one.
	grants, denies bool
}

// sideDeclared is one declaration of a decision from outside: the side, and the
// answer it names when it names one.
type sideDeclared struct {
	denies bool
	answer *ast.Term
}

// declare takes one declaration of the decision.
func (d *declaredAnswers) declare(side sideDeclared) {
	if side.denies {
		d.denies = true
	} else {
		d.grants = true
	}
	if side.answer == nil {
		return
	}
	for _, known := range d.terms {
		if known.Equal(side.answer) {
			return
		}
	}
	d.terms = append(d.terms, side.answer)
}

// bothSides reports whether the decision names an answer and is declared on
// both sides. A decision with no answer declared on both sides is one that
// denies, as it always was.
func (d *declaredAnswers) bothSides() bool {
	return len(d.terms) > 0 && d.grants && d.denies
}

// answeredEntrypoint splits a declared entrypoint into the path of the decision
// and the answer it is on its side for, when the declaration names one:
// data.app.verdict=allowed, or app/result/decision=allow.
//
// The answer is read as Rego when it is a value written out, true, 1 or "allow"
// in its quotes, and as a string otherwise, which is what a bare word on a
// command line means.
func answeredEntrypoint(declared string) (string, *ast.Term, error) {
	path, written, answered := strings.Cut(declared, "=")
	if !answered {
		return declared, nil, nil
	}
	if path == "" || written == "" {
		return "", nil, fmt.Errorf("%w: %s", ErrBadEntrypoint, declared)
	}
	if term, err := ast.ParseTerm(written); err == nil && isWrittenOut(term) {
		return path, term, nil
	}
	return path, ast.StringTerm(written), nil
}

// isWrittenOut reports whether a term is a value written out, with no variable
// and no reference in it.
func isWrittenOut(term *ast.Term) bool {
	if !term.IsGround() {
		return false
	}
	written := true
	ast.WalkRefs(term, func(ast.Ref) bool {
		written = false
		return true
	})
	return written
}

// answerTexts writes answers as Rego, in the order they were declared.
func answerTexts(answers []*ast.Term) []string {
	texts := make([]string, 0, len(answers))
	for _, answer := range answers {
		texts = append(texts, answer.String())
	}
	return texts
}

// Answers returns the answers a decision is declared to be on its side for, as
// Rego, and nothing for a decision that is on its side whenever it holds.
func (b *Bundle) Answers(decision string) []string {
	return answerTexts(b.answersFor(decision))
}

// answersFor is Answers as terms. It reads the declared entrypoints, and keeps
// what it read for as long as they stay the same: a question asked of a
// decision is asked many times over, and the entrypoints are set once.
func (b *Bundle) answersFor(decision string) []*ast.Term {
	key := strings.Join(b.Entrypoints, "\x00") + "\x01" + strings.Join(b.DenyEntrypoints, "\x00")
	if !strings.Contains(key, "=") {
		// No entrypoint names an answer, which is every bundle but a few.
		return nil
	}

	b.answersMu.Lock()
	defer b.answersMu.Unlock()
	if b.answers == nil || b.answersKey != key {
		b.answers, b.answersKey = map[string][]*ast.Term{}, key
		// Entrypoints that do not hold together are refused where the decisions
		// are read, and a decision nobody could read has no answer to ask for.
		roots, err := entrypointRules(b)
		if err == nil {
			for _, root := range roots {
				b.answers[root.name] = root.answers
			}
		}
	}
	return b.answers[decision]
}

// queriesFor writes the queries that ask whether a decision is on its side. A
// decision that is whenever it holds is asked the one query of query. One
// declared with answers is asked once for each, what it returns unified with
// the answer.
//
// The unification is also what keeps partial evaluation readable. Asked whole,
// a decision with a default comes back as a rule generated for every answer,
// the refusals among them. Asked for one answer the default drops out, and what
// is left are the conditions of the rules that give that answer, inlined.
func (b *Bundle) queriesFor(decision string) []string {
	query := b.query(decision)
	answers := b.answersFor(decision)
	if len(answers) == 0 {
		return []string{query}
	}
	queries := make([]string, 0, len(answers))
	for _, answer := range answers {
		queries = append(queries, query+" = "+answer.String())
	}
	return queries
}

// maxAnswerDepth bounds how far answerOf follows a value through the rules and
// functions that build it.
const maxAnswerDepth = 4

// answerOf returns what a rule answers with at a field of its value, when the
// policy writes it out, and reports whether it does.
//
// The value is followed through an object written in the head or bound in the
// body, and through a function or a rule of the policy when every definition of
// it answers the same there: result := deny_result(reason) answers "deny" at
// decision when deny_result builds {"decision": "deny", ...} and nothing else.
// A value the policy computes is not an answer it writes, and the rule is then
// taken to be on the side its decision is.
func answerOf(compiler *ast.Compiler, rule *ast.Rule, field ast.Ref) (*ast.Term, bool) {
	if rule.Head == nil || rule.Head.Value == nil {
		return nil, false
	}
	return valueAt(compiler, rule.Head.Value, rule.Body, field, 0)
}

// valueAt follows a term of a rule down a field to a value written out.
func valueAt(compiler *ast.Compiler, value *ast.Term, body ast.Body, field ast.Ref, depth int) (*ast.Term, bool) {
	if depth > maxAnswerDepth {
		return nil, false
	}

	switch at := value.Value.(type) {
	case ast.Var:
		for _, expr := range body {
			if bound, found := boundTo(expr, at); found {
				return valueAt(compiler, bound, body, field, depth+1)
			}
			if called, found := returnedBy(expr, at); found {
				return definedAt(compiler, called, field, depth+1)
			}
		}
		return nil, false

	case ast.Ref:
		// A rule of the policy named as the value: what it answers is the answer.
		return definedAt(compiler, at, field, depth+1)

	case ast.Object:
		if len(field) == 0 {
			break
		}
		next := at.Get(field[0])
		if next == nil {
			return nil, false
		}
		return valueAt(compiler, next, body, field[1:], depth)
	}

	if len(field) > 0 || !isWrittenOut(value) {
		return nil, false
	}
	return value, true
}

// boundTo returns the term an equality binds a variable to, when the expression
// is one that does.
func boundTo(expr *ast.Expr, v ast.Var) (*ast.Term, bool) {
	if !expr.IsEquality() || expr.Negated {
		return nil, false
	}
	operands := expr.Operands()
	for _, pair := range [][2]*ast.Term{{operands[0], operands[1]}, {operands[1], operands[0]}} {
		if bound, isVar := varOf(pair[0]); isVar && bound == v {
			if other, alsoVar := varOf(pair[1]); alsoVar && other == v {
				continue
			}
			return pair[1], true
		}
	}
	return nil, false
}

// returnedBy returns the function a call hands a variable its result from, when
// the expression is such a call: the compiler writes f(x) used as a value as a
// call with one more operand, the variable the result goes to.
func returnedBy(expr *ast.Expr, v ast.Var) (ast.Ref, bool) {
	if !expr.IsCall() || expr.Negated {
		return nil, false
	}
	operands := expr.Operands()
	if len(operands) == 0 {
		return nil, false
	}
	if result, isVar := varOf(operands[len(operands)-1]); !isVar || result != v {
		return nil, false
	}
	return expr.Operator(), true
}

// definedAt returns what a rule or a function of the policy answers at a field,
// when every definition of it answers the same value written out.
func definedAt(compiler *ast.Compiler, ref ast.Ref, field ast.Ref, depth int) (*ast.Term, bool) {
	if !ref.HasPrefix(ast.DefaultRootRef) || !ref.IsGround() {
		// A builtin, a part of the request, or a document picked by a variable.
		return nil, false
	}
	rules := compiler.GetRulesExact(ref)
	if len(rules) == 0 {
		return nil, false
	}
	var answer *ast.Term
	for _, rule := range rules {
		if rule.Head == nil || rule.Head.Value == nil || rule.Head.Key != nil {
			return nil, false
		}
		for leg := rule; leg != nil; leg = leg.Else {
			value, found := valueAt(compiler, leg.Head.Value, leg.Body, field, depth)
			if !found || (answer != nil && !answer.Equal(value)) {
				return nil, false
			}
			answer = value
		}
	}
	return answer, answer != nil
}

// onItsSide reports whether a rule of a decision declared with answers gives
// one of them, and whether the policy writes what it gives at all.
func onItsSide(compiler *ast.Compiler, root decisionRoot, rule *ast.Rule) (onSide, written bool) {
	answer, found := answerOf(compiler, rule, root.field)
	if !found {
		return false, false
	}
	for _, declared := range root.answers {
		if declared.Equal(answer) {
			return true, true
		}
	}
	return false, true
}
