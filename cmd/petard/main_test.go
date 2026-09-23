package main

import (
	"bytes"
	"strings"
	"testing"
)

// The dispatch is the whole of this command, and a subcommand that silently
// does nothing is worse than one that is missing: the run looks like it worked.
func TestEverySubcommandIsReachable(t *testing.T) {
	for _, name := range []string{"analyze", "explain", "export", "measure"} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			// No paths, so each one prints its own usage and refuses.
			if code := run([]string{name}, &stdout, &stderr); code != 2 {
				t.Errorf("exit code = %d, want 2 (stdout: %s, stderr: %s)",
					code, stdout.String(), stderr.String())
			}
			if want := "usage: petard " + name; !strings.Contains(stderr.String(), want) {
				t.Errorf("the usage does not say %q:\n%s", want, stderr.String())
			}
		})
	}
}

// patterns takes no argument at all, so it is the one subcommand that has
// something to say when run with none.
func TestPatternsListsWithoutArguments(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"patterns"}, &stdout, &stderr); code != 0 {
		t.Errorf("exit code = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "PTD-OPA-001") {
		t.Errorf("the list is empty:\n%s", stdout.String())
	}
}

func TestUnknownCommandSaysSoAndLists(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"analyse"}, &stdout, &stderr); code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
	out := stderr.String()
	if !strings.Contains(out, `unknown command "analyse"`) || !strings.Contains(out, "analyze ") {
		t.Errorf("a typo should name itself and list the commands:\n%s", out)
	}
}

func TestNoArgumentsPrintsTheUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(nil, &stdout, &stderr); code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "usage: petard <command>") {
		t.Errorf("the usage is missing:\n%s", stderr.String())
	}
}

// The first thing a bug report needs is which build it came from, so the line
// says something whether or not the linker stamped it.
func TestVersionSaysWhichBuild(t *testing.T) {
	for _, name := range []string{"version", "--version"} {
		var stdout, stderr bytes.Buffer
		if code := run([]string{name}, &stdout, &stderr); code != 0 {
			t.Errorf("%s: exit code = %d, want 0 (stderr: %s)", name, code, stderr.String())
		}
		out := stdout.String()
		if first, _, _ := strings.Cut(out, "\n"); !strings.HasPrefix(first, "petard ") || len(first) < 10 {
			t.Errorf("%s printed %q", name, first)
		}
		// Which OPA is linked in decides what an analysis says, and the answer
		// to "why does this bundle report differently now" starts here.
		if !strings.Contains(out, "\nopa v") {
			t.Errorf("%s does not say which OPA is compiled in:\n%s", name, out)
		}
	}
}

// Asking for the flags of one command through help is a question, not a
// mistake: the answer belongs on stdout and the run is a success.
func TestHelpForOneCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"help", "analyze"}, &stdout, &stderr); code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	if stderr.Len() != 0 {
		t.Errorf("help wrote to stderr: %s", stderr.String())
	}
	for _, want := range []string{"usage: petard analyze", "-fail-on", "-write-model"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("the flags do not mention %q:\n%s", want, stdout.String())
		}
	}

	stdout.Reset()
	if code := run([]string{"help", "analyse"}, &stdout, &stderr); code != 2 {
		t.Errorf("a typo after help: exit code = %d, want 2", code)
	}
}

func TestHelpGoesToStdout(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"help"}, &stdout, &stderr); code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	if stderr.Len() != 0 {
		t.Errorf("help wrote to stderr: %s", stderr.String())
	}
	for _, command := range []string{"analyze", "explain", "patterns", "export", "measure", "demo", "version"} {
		if !strings.Contains(stdout.String(), command) {
			t.Errorf("the usage does not list %s:\n%s", command, stdout.String())
		}
	}
}
