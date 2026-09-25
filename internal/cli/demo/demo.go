// Package demo runs the analysis over the bundle built into the binary.
package demo

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/saluc28/petard/fixtures"
	"github.com/saluc28/petard/internal/cli/analyze"
)

const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2
)

// Run unpacks the bundle and analyzes it, or writes it where the caller asked
// and stops there.
//
// It takes no policy path of its own: the point is to answer "what does this
// thing do" for somebody holding a binary and nothing else.
func Run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("petard demo", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprint(stderr, "usage: petard demo [-v] [-extract <dir>]\n\n"+
			"Analyzes the vulnerable bundle built into this binary.\n\n")
		flags.PrintDefaults()
	}
	extract := flags.String("extract", "", "write the bundle here instead of analyzing it")
	verbose := flags.Bool("v", false, "print the evidence too, as petard analyze -v does")

	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if flags.NArg() > 0 {
		fmt.Fprintf(stderr, "petard demo: %q is not an argument this command takes; "+
			"run petard analyze to analyze a policy of your own\n", flags.Arg(0))
		return exitUsage
	}

	if *extract != "" {
		root, err := fixtures.Unpack(*extract)
		if err != nil {
			fmt.Fprintf(stderr, "petard demo: %v\n", err)
			return exitFailure
		}
		fmt.Fprintf(stdout, "bundle written to %s\n", root)
		fmt.Fprintf(stdout, "analyze it with: petard analyze %s\n", strings.Join(bundleArguments(root), " "))
		return exitOK
	}

	dir, err := os.MkdirTemp("", "petard-demo-")
	if err != nil {
		fmt.Fprintf(stderr, "petard demo: %v\n", err)
		return exitFailure
	}
	defer func() { _ = os.RemoveAll(dir) }()

	if _, err := fixtures.Unpack(dir); err != nil {
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

	// A demonstration is not a gate: the bundle is built to be full of
	// findings, and exiting 3 over the ones it was written to have would say
	// something about the fixture rather than about the tool.
	analysis := []string{"-fail-on", "none"}
	if *verbose {
		analysis = append(analysis, "-v")
	}
	analysis = append(analysis, bundleArguments(fixtures.BundleDir)...)

	if code := analyze.Run(analysis, stdout, stderr); code != exitOK {
		return code
	}

	fmt.Fprint(stdout, "\nThat was the bundle built into this binary, written by hand with the "+
		"escalations in it.\nRun petard demo -extract <dir> to get the files, edit them, and "+
		"analyze them again.\n")
	return exitOK
}

// bundleArguments hand petard analyze the bundle unpacked at root: what the
// bundle declares next to its policy, then the policy. The demo runs with them
// and prints them for a run of one's own, so the two say the same thing.
func bundleArguments(root string) []string {
	return []string{
		"-pep", filepath.Join(root, "pep.yaml"),
		"-write-model", filepath.Join(root, "write-model.yaml"),
		"-data", filepath.Join(root, "data"),
		filepath.Join(root, "policy-v1"),
	}
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
