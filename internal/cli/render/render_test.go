package render

import (
	"slices"
	"strings"
	"testing"
)

func TestWrapKeepsTheWidthAndTheIndent(t *testing.T) {
	text := strings.Repeat("word ", 60)

	lines := Wrap(text, "    ")
	if len(lines) < 3 {
		t.Fatalf("lines = %d, want the text broken up", len(lines))
	}
	for _, line := range lines {
		if len(line) > Width {
			t.Errorf("line of %d columns: %q", len(line), line)
		}
		if !strings.HasPrefix(line, "    ") {
			t.Errorf("line without the indent: %q", line)
		}
	}
}

// A path or a link is one word, and half of one is useless. Running over the
// width is the smaller harm, so it is the one this takes.
func TestAWordLongerThanTheLineStaysWhole(t *testing.T) {
	long := "https://example.invalid/" + strings.Repeat("a", Width)

	lines := Wrap("see "+long+" for it", "  ")
	if !slices.Contains(lines, "  "+long) {
		t.Errorf("the long word was broken up: %q", lines)
	}
}

// The registry writes its prose in folded scalars, where a blank line the
// author left arrives as a newline and everything else as spaces. The gaps are
// paragraphs and are worth keeping.
func TestABlankLineStaysAParagraphBreak(t *testing.T) {
	lines := Wrap("first thing\n\nsecond thing", "")

	if !slices.Equal(lines, []string{"first thing", "", "second thing"}) {
		t.Errorf("lines = %q", lines)
	}
}

func TestWrapDropsLeadingAndTrailingSpace(t *testing.T) {
	if lines := Wrap("\n  one line  \n\n", ""); !slices.Equal(lines, []string{"one line"}) {
		t.Errorf("lines = %q", lines)
	}
}

func TestPlainTakesOutTheEmphasis(t *testing.T) {
	if got := Plain("the **whole** path, not the `prefix`"); got != "the whole path, not the `prefix`" {
		t.Errorf("Plain() = %q", got)
	}
}

// Escape sequences are for a person looking at a terminal. Everywhere else they
// are four characters of noise in front of every heading, and the place a
// report most often ends up is a log file.
func TestNothingIsColoredOutsideATerminal(t *testing.T) {
	// A terminal that says it understands them, so that the cases below are
	// about the rule under test and not about this machine.
	t.Setenv("TERM", "xterm-256color")

	for _, test := range []struct {
		name     string
		terminal bool
		noColor  bool
		env      map[string]string
		want     bool
	}{
		{name: "a terminal", terminal: true, want: true},
		{name: "a pipe or a file", terminal: false},
		{name: "asked not to", terminal: true, noColor: true},
		{name: "NO_COLOR is set", terminal: true, env: map[string]string{"NO_COLOR": "1"}},
		{name: "a dumb terminal", terminal: true, env: map[string]string{"TERM": "dumb"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			for name, value := range test.env {
				t.Setenv(name, value)
			}
			if got := styleFor(test.terminal, test.noColor).Bold("x") != "x"; got != test.want {
				t.Errorf("colored = %v, want %v", got, test.want)
			}
		})
	}
}

// A buffer is what every test and every pipeline hands the commands, and it has
// to come back clean without anybody asking.
func TestStyleForABufferIsPlain(t *testing.T) {
	if got := StyleFor(&strings.Builder{}, false).Bold("heading"); got != "heading" {
		t.Errorf("Bold() = %q", got)
	}
}
