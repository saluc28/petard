package openfga

import (
	"strings"

	"github.com/antlr4-go/antlr/v4"
	parser "github.com/openfga/language/pkg/go/gen"

	"github.com/saluc28/petard/internal/zanzibar"
)

// dslPositions finds where a model written in the DSL declares its types,
// relations and conditions. The compiled form keeps none of it, and a finding that
// names a relation has to say where to look. What a model means is read from the
// compiled form alone; this reads the parse tree for the lines and nothing else.
//
// The keys are a type's name, type#relation, and "condition name". The text has
// already compiled by the time this runs, so a declaration it cannot find only
// leaves that position without a line.
func dslPositions(file, text string) map[string]zanzibar.Position {
	lexer := parser.NewOpenFGALexer(antlr.NewInputStream(withoutComments(text)))
	lexer.RemoveErrorListeners()
	fga := parser.NewOpenFGAParser(antlr.NewCommonTokenStream(lexer, antlr.TokenDefaultChannel))
	fga.RemoveErrorListeners()

	l := &positionListener{file: file, at: map[string]zanzibar.Position{}}
	antlr.ParseTreeWalkerDefault.Walk(l, fga.Main())
	return l.at
}

// withoutComments blanks what the language package blanks before it parses
// (pkg/go/transformer/dsltojson.go:515-533 at language v0.3.2), keeping every line
// where it is so that a token's line is the line of the file.
func withoutComments(text string) string {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		trimmed := strings.TrimLeft(line, " ")
		if trimmed == "" || trimmed[0] == '#' {
			lines[i] = ""
			continue
		}
		lines[i] = strings.TrimRight(strings.Split(line, " #")[0], " ")
	}
	return strings.TrimRight(strings.Join(lines, "\n"), "\n")
}

type positionListener struct {
	parser.BaseOpenFGAParserListener

	file     string
	at       map[string]zanzibar.Position
	typeName string
}

func (l *positionListener) position(token antlr.Token) zanzibar.Position {
	return zanzibar.Position{File: l.file, Line: token.GetLine(), Column: token.GetColumn() + 1}
}

// EnterTypeDef records a type and remembers it for the relations inside it.
func (l *positionListener) EnterTypeDef(ctx *parser.TypeDefContext) {
	if ctx.GetTypeName() == nil {
		return
	}
	l.typeName = ctx.GetTypeName().GetText()
	l.at[l.typeName] = l.position(ctx.GetTypeName().GetStart())
}

// EnterRelationDeclaration records a relation of the type being read.
func (l *positionListener) EnterRelationDeclaration(ctx *parser.RelationDeclarationContext) {
	if ctx.RelationName() == nil {
		return
	}
	l.at[l.typeName+"#"+ctx.RelationName().GetText()] = l.position(ctx.RelationName().GetStart())
}

// EnterCondition records a condition.
func (l *positionListener) EnterCondition(ctx *parser.ConditionContext) {
	if ctx.ConditionName() == nil {
		return
	}
	l.at["condition "+ctx.ConditionName().GetText()] = l.position(ctx.ConditionName().GetStart())
}
