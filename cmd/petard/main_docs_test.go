package main

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// outputMarker is how a doc says that the block below is what a command
// prints: an HTML comment on the line before the fence, which a page renders
// as nothing.
//
//	<!-- output of: petard analyze fixtures/vulnerable-spicedb -->
//
// The command is split on spaces, so an argument cannot hold one, and it runs
// from the root of the repository.
var outputMarker = regexp.MustCompile(`^<!-- output of: (petard .+) -->$`)

// readOnly are the commands a doc may show the output of. A block in a doc is
// not a way to make the suite call a server or write a file, so a command that
// can do either, or an argument that names a URL or asks for a file to be
// written, is refused rather than run.
var readOnly = struct{ commands, writing []string }{
	commands: []string{"analyze", "demo", "explain", "patterns", "version"},
	writing:  []string{"-tests", "-questions", "-extract"},
}

// checkReadOnly says why a command of a doc may not run, or nil when it may.
func checkReadOnly(args []string) error {
	if len(args) == 0 || !slices.Contains(readOnly.commands, args[0]) {
		return fmt.Errorf("only %s may be shown", strings.Join(readOnly.commands, ", "))
	}
	for _, arg := range args[1:] {
		flag, _, _ := strings.Cut(strings.Replace(arg, "--", "-", 1), "=")
		if slices.Contains(readOnly.writing, flag) || strings.Contains(arg, "://") {
			return fmt.Errorf("%s writes a file or reaches a server", arg)
		}
	}
	return nil
}

// outputBlock is a block a doc marks as the output of a command.
type outputBlock struct {
	doc     string
	line    int
	command string
	lines   []string
}

// A block of output in the docs is a claim about the binary, and it drifts the
// moment the output changes and nobody reruns the command. Each marked block
// has to be lines the command prints, one after the other: all of what it
// prints, or the part a doc wants to show.
func TestTheDocsShowWhatTheCommandsPrint(t *testing.T) {
	root := filepath.Join("..", "..")

	// Every Markdown file of the repository, outside the directories whose
	// name starts with a dot.
	var blocks []outputBlock
	err := filepath.WalkDir(root, func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name != root && strings.HasPrefix(d.Name(), ".") {
				return fs.SkipDir
			}
			return nil
		}
		if filepath.Ext(name) != ".md" {
			return nil
		}
		found, err := outputBlocks(root, name)
		blocks = append(blocks, found...)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) == 0 {
		t.Fatal("no doc marks a block as the output of a command")
	}

	t.Chdir(root)
	printed := map[string][]string{}
	for _, b := range blocks {
		out, ok := printed[b.command]
		if !ok {
			args := strings.Fields(b.command)[1:]
			if err := checkReadOnly(args); err != nil {
				t.Errorf("%s:%d: %s is not run: %v", b.doc, b.line, b.command, err)
				continue
			}
			var stdout, stderr bytes.Buffer
			run(args, &stdout, &stderr)
			out = trimmedLines(stdout.String())
			if len(out) == 0 {
				t.Errorf("%s printed nothing (stderr: %s)", b.command, stderr.String())
			}
			printed[b.command] = out
		}
		if !holdsRun(out, b.lines) {
			t.Errorf("%s:%d shows what %s does not print; it prints:\n%s",
				b.doc, b.line, b.command, strings.Join(out, "\n"))
		}
	}
}

// outputBlocks reads the marked blocks of one doc. A marker with no fence under
// it is an error rather than a block left unchecked.
func outputBlocks(root, doc string) ([]outputBlock, error) {
	raw, err := os.ReadFile(doc)
	if err != nil {
		return nil, err
	}
	name, err := filepath.Rel(root, doc)
	if err != nil {
		return nil, err
	}
	name = filepath.ToSlash(name)
	lines := trimmedLines(strings.ReplaceAll(string(raw), "\r\n", "\n"))
	fence := func(line string) bool { return strings.HasPrefix(line, "```") }

	var blocks []outputBlock
	for i := 0; i < len(lines); i++ {
		m := outputMarker.FindStringSubmatch(lines[i])
		if m == nil {
			continue
		}
		open := i + 1
		if open >= len(lines) || !fence(lines[open]) {
			return nil, fmt.Errorf("%s:%d: the output marker has no fenced block under it", name, i+1)
		}
		end := slices.IndexFunc(lines[open+1:], fence)
		if end < 0 {
			return nil, fmt.Errorf("%s:%d: the block under the output marker is never closed", name, i+1)
		}
		end += open + 1
		blocks = append(blocks, outputBlock{doc: name, line: i + 1, command: m[1], lines: lines[open+1 : end]})
		i = end
	}
	return blocks, nil
}

// trimmedLines are the lines of a text, without the spaces a table pads
// them with at the end, which a doc does not keep.
func trimmedLines(out string) []string {
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	for i, line := range lines {
		lines[i] = strings.TrimRight(line, " ")
	}
	return lines
}

// holdsRun says whether want is a run of consecutive lines of out.
func holdsRun(out, want []string) bool {
	if len(want) == 0 {
		return false
	}
	for i := 0; i+len(want) <= len(out); i++ {
		if slices.Equal(out[i:i+len(want)], want) {
			return true
		}
	}
	return false
}

func TestCheckReadOnly(t *testing.T) {
	tests := []struct {
		name string
		args []string
		ok   bool
	}{
		{name: "the demo", args: []string{"demo"}, ok: true},
		{name: "a fixture", args: []string{"analyze", "fixtures/vulnerable-spicedb"}, ok: true},
		{name: "a pattern", args: []string{"explain", "PTD-ZAN-001"}, ok: true},
		{name: "no command", args: nil},
		{name: "an export", args: []string{"export", "-out", "graph.json", "policy"}},
		{name: "a server", args: []string{"analyze", "http://localhost:8181"}},
		{name: "tests written", args: []string{"analyze", "-tests", "escalations_test.rego", "policy"}},
		{name: "questions written", args: []string{"analyze", "-questions=write-model.yaml", "policy"}},
		{name: "fixtures written", args: []string{"demo", "--extract", "."}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := checkReadOnly(tt.args); (err == nil) != tt.ok {
				t.Errorf("checkReadOnly(%q) = %v, want ok %v", tt.args, err, tt.ok)
			}
		})
	}
}
