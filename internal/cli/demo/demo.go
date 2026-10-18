// Package demo runs the analysis over the fixtures built into the binary.
package demo

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/saluc28/petard/fixtures"
	"github.com/saluc28/petard/internal/cli/analyze"
	"github.com/saluc28/petard/internal/cli/render"
)

const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2
)

// fixture is one fixture the demo can analyze, named after the product it is
// written for, since that is what somebody who uses one of them reaches for.
type fixture struct {
	name string // as the command line names it
	what string // as the closing line names it
	dir  string // the directory it unpacks into

	// flags and paths are what petard analyze is handed to read the fixture
	// unpacked at root: what it declares, if anything, then what to analyze.
	// They are kept apart because every flag has to come before the first
	// path.
	flags, paths func(root string) []string
}

// demoFixtures are the fixtures the demo has, in the order it runs and lists
// them.
var demoFixtures = []fixture{
	{
		name: "opa",
		what: "the policy",
		dir:  fixtures.BundleDir,
		// What the bundle declares next to its policy, and the requests it
		// says its decisions grant.
		flags: func(root string) []string {
			return []string{
				"-pep", filepath.Join(root, "pep.yaml"),
				"-write-model", filepath.Join(root, "write-model.yaml"),
				"-data", filepath.Join(root, "data"),
				"-granted", filepath.Join(root, "inputs", "granted-download.json"),
				"-granted", filepath.Join(root, "inputs", "granted-mint.json"),
			}
		},
		paths: func(root string) []string { return []string{filepath.Join(root, "policy-v1")} },
	},
	{
		name:  "spicedb",
		what:  "the SpiceDB schema",
		dir:   fixtures.SpiceDBDir,
		paths: func(root string) []string { return []string{root} },
	},
}

// Run unpacks the fixtures and analyzes them, or writes them where the caller
// asked and stops there. A name picks one fixture; without one, the demo takes
// them all in one run, the way petard analyze reads a repository that holds
// both.
//
// It takes no path of its own: the point is to answer "what does this thing
// do" for somebody holding a binary and nothing else.
func Run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("petard demo", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprintf(stderr, "usage: petard demo [-v] [-extract <dir>] [%s]\n\n"+
			"Analyzes the fixtures built into this binary, written by hand with defects in them:\n"+
			"opa, a Rego policy, and spicedb, a SpiceDB schema. A name picks one of them.\n\n",
			strings.Join(names(), " | "))
		flags.PrintDefaults()
	}
	extract := flags.String("extract", "", "write the fixtures here instead of analyzing them")
	verbose := flags.Bool("v", false, "print the evidence too, as petard analyze -v does")

	// The name can come before the flags or after them.
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	var name string
	if flags.NArg() > 0 {
		name = flags.Arg(0)
		if err := flags.Parse(flags.Args()[1:]); err != nil {
			return exitUsage
		}
	}
	if flags.NArg() > 0 {
		fmt.Fprintf(stderr, "petard demo: %q is one argument too many; the demo takes one name at most\n", flags.Arg(0))
		return exitUsage
	}
	chosen, ok := choose(name)
	if !ok {
		fmt.Fprintf(stderr, "petard demo: %q names no fixture of the demo, which has %s; "+
			"run petard analyze to analyze a policy or a schema of your own\n",
			name, strings.Join(names(), " and "))
		return exitUsage
	}

	if *extract != "" {
		if err := fixtures.Unpack(*extract, dirs(chosen)...); err != nil {
			var exists *fixtures.ExistsError
			if errors.As(err, &exists) {
				fmt.Fprintf(stderr, "petard demo: %s is already there, and the demo does not write over it; "+
					"remove it or give -extract another directory\n", exists.Path)
			} else {
				fmt.Fprintf(stderr, "petard demo: %v\n", err)
			}
			return exitFailure
		}
		fmt.Fprintf(stdout, "%s written to %s\n", strings.Join(dirs(chosen), " and "), *extract)
		fmt.Fprintf(stdout, "analyze %s with: petard analyze %s\n",
			pronoun(chosen), strings.Join(arguments(*extract, chosen), " "))
		return exitOK
	}

	dir, err := os.MkdirTemp("", "petard-demo-")
	if err != nil {
		fmt.Fprintf(stderr, "petard demo: %v\n", err)
		return exitFailure
	}
	defer func() { _ = os.RemoveAll(dir) }()

	if err := fixtures.Unpack(dir, dirs(chosen)...); err != nil {
		fmt.Fprintf(stderr, "petard demo: %v\n", err)
		return exitFailure
	}

	// The analysis names every file it read by the path it was handed, and
	// lines the names up in columns. Handed from inside the temporary
	// directory, the paths are the ones a checkout has: the directory's random
	// name never reaches the report, so it cannot widen a column on one run
	// and not on the next. go -C moves the same way before it runs anything
	// (src/cmd/go/main.go:408 at go1.27.1).
	leave, err := enter(dir)
	if err != nil {
		fmt.Fprintf(stderr, "petard demo: %v\n", err)
		return exitFailure
	}
	// Deferred after the removal, so it runs before it: Windows will not
	// remove the directory a process is working in.
	defer leave()

	// A demonstration is not a gate: the fixtures are built to be full of
	// findings, and exiting 3 over the ones they were written to have would
	// say something about the fixtures rather than about the tool.
	analysis := []string{"-fail-on", "none"}
	if *verbose {
		analysis = append(analysis, "-v")
	}
	analysis = append(analysis, arguments(".", chosen)...)

	if code := analyze.Run(analysis, stdout, stderr); code != exitOK {
		return code
	}

	extractCommand := "petard demo -extract <dir>"
	if name != "" {
		extractCommand += " " + name
	}
	fmt.Fprintln(stdout)
	// The command on a line of its own, so that wrapping never splits it.
	render.Print(stdout, fmt.Sprintf("That was %s of the demo, written by hand with defects in %s.\n"+
		"Run %s to get the files, edit them, and analyze them again.",
		strings.Join(collect(chosen, func(f fixture) string { return f.what }), " and "), pronoun(chosen), extractCommand), "")
	return exitOK
}

// choose is the fixture a name picks, or all of them for no name.
func choose(name string) ([]fixture, bool) {
	if name == "" {
		return demoFixtures, true
	}
	for _, f := range demoFixtures {
		if f.name == name {
			return []fixture{f}, true
		}
	}
	return nil, false
}

// names are the names the demo takes, in the order it lists them.
func names() []string { return collect(demoFixtures, func(f fixture) string { return f.name }) }

// dirs are the directories the fixtures chosen unpack into.
func dirs(chosen []fixture) []string { return collect(chosen, func(f fixture) string { return f.dir }) }

func collect(chosen []fixture, of func(fixture) string) []string {
	out := make([]string, 0, len(chosen))
	for _, f := range chosen {
		out = append(out, of(f))
	}
	return out
}

func pronoun(chosen []fixture) string {
	if len(chosen) == 1 {
		return "it"
	}
	return "them"
}

// arguments hand petard analyze the fixtures chosen, unpacked under dir. The
// demo runs with them and prints them for a run of one's own, so the two say
// the same thing.
func arguments(dir string, chosen []fixture) []string {
	var flags, paths []string
	for _, f := range chosen {
		root := filepath.Join(dir, f.dir)
		if f.flags != nil {
			flags = append(flags, f.flags(root)...)
		}
		paths = append(paths, f.paths(root)...)
	}
	return append(flags, paths...)
}

// enter makes dir the working directory and returns what goes back to the one
// before it.
func enter(dir string) (func(), error) {
	previous, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	if err := os.Chdir(dir); err != nil {
		return nil, err
	}
	return func() { _ = os.Chdir(previous) }, nil
}
