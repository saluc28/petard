// Package render holds the shape of what the commands print: how wide a line
// is, how prose out of the registry becomes terminal lines, and how a report
// decides whether to use color.
//
// It is here rather than in each command because the rules are the same
// everywhere and the first place the output lands is a CI log: one width, plain
// ASCII, and color only when somebody is actually watching.
package render

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
)

// Width is the widest line the commands print.
//
// A hundred columns fits a terminal split in two on a laptop, and a log viewer
// that wraps at eighty leaves the overflow readable rather than shredded. Paths
// and references are the exception: breaking one makes it uncopyable, so a word
// longer than the line is left whole and allowed to run over.
const Width = 100

// Wrap turns a paragraph of prose into lines that fit, each already carrying
// the indent.
//
// Blank lines in the source separate paragraphs and are kept as such, which is
// what the folded scalars of the registry produce: a run of newlines where the
// author left a gap, and single spaces everywhere else.
func Wrap(text, indent string) []string {
	var lines []string
	for i, paragraph := range strings.Split(strings.TrimSpace(text), "\n") {
		paragraph = strings.TrimSpace(paragraph)
		if paragraph == "" {
			// A gap the author left, kept as a gap, unless it is leading.
			if len(lines) > 0 && i > 0 {
				lines = append(lines, "")
			}
			continue
		}
		lines = append(lines, wrapParagraph(paragraph, indent)...)
	}
	return lines
}

func wrapParagraph(paragraph, indent string) []string {
	var lines []string
	line := indent

	for _, word := range strings.Fields(paragraph) {
		switch {
		case line == indent:
			line += word
		case len(line)+1+len(word) <= Width:
			line += " " + word
		default:
			lines = append(lines, line)
			line = indent + word
		}
	}
	if line != indent {
		lines = append(lines, line)
	}
	return lines
}

// Print writes a paragraph wrapped and indented.
func Print(out io.Writer, text, indent string) {
	for _, line := range Wrap(text, indent) {
		fmt.Fprintln(out, line)
	}
}

// Plain takes the markdown emphasis out of registry prose.
//
// The files are read on GitHub as well as here, and there the asterisks are
// what makes the load-bearing word of a sentence stand out. In a terminal they
// are noise, and the sentence reads the same without them.
func Plain(text string) string {
	return strings.ReplaceAll(text, "**", "")
}

// Terminal says whether a writer is a terminal somebody is looking at.
//
// A command writes to whatever it was handed, which in a test is a buffer and
// in a pipeline a file, and neither wants escape sequences. Only a character
// device does.
func Terminal(w io.Writer) bool {
	file, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// Style says whether the report may use escape sequences.
//
// The rule is the one the ecosystem settled on: not a terminal, TERM=dumb or
// NO_COLOR set means plain text (fatih/color color.go:18-23 at v1.18.0, which
// is what regal uses). On Windows there is one more condition, because the
// classic console only interprets these sequences when something turned that
// on, and a terminal that does not is a report full of bracket codes. The
// terminals that do announce themselves in the environment.
type Style struct{ escapes bool }

// StyleFor decides once, for a writer. The flag is the last word: somebody who
// passes -no-color has a reason, and no detection beats being told.
func StyleFor(w io.Writer, noColor bool) Style {
	return styleFor(Terminal(w), noColor)
}

func styleFor(terminal, noColor bool) Style {
	if noColor || !terminal || os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return Style{}
	}
	if runtime.GOOS == "windows" && os.Getenv("WT_SESSION") == "" &&
		os.Getenv("TERM") == "" && os.Getenv("ANSICON") == "" {
		return Style{}
	}
	return Style{escapes: true}
}

// Bold is for the few words that carry the structure of a report: the headings,
// and the two names of an escalation. There is no other color in the output,
// because a color scale would be a severity scale, and severity is not
// something this tool computes yet.
func (s Style) Bold(text string) string {
	if !s.escapes {
		return text
	}
	return "\x1b[1m" + text + "\x1b[0m"
}
