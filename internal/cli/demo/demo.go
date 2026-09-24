// Package demo runs the analysis over the bundle built into the binary.
package demo

import (
	"bytes"
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
		fmt.Fprintf(stdout, "analyze it with: petard analyze -pep %s -write-model %s -data %s %s\n",
			filepath.Join(root, "pep.yaml"),
			filepath.Join(root, "write-model.yaml"),
			filepath.Join(root, "data"),
			filepath.Join(root, "policy-v1"))
		return exitOK
	}

	dir, err := os.MkdirTemp("", "petard-demo-")
	if err != nil {
		fmt.Fprintf(stderr, "petard demo: %v\n", err)
		return exitFailure
	}
	defer func() { _ = os.RemoveAll(dir) }()

	root, err := fixtures.Unpack(dir)
	if err != nil {
		fmt.Fprintf(stderr, "petard demo: %v\n", err)
		return exitFailure
	}

	// A demonstration is not a gate: the bundle is built to be full of
	// findings, and exiting 3 over the ones it was written to have would say
	// something about the fixture rather than about the tool.
	analysis := []string{
		"-fail-on", "none",
		"-pep", filepath.Join(root, "pep.yaml"),
		"-write-model", filepath.Join(root, "write-model.yaml"),
		"-data", filepath.Join(root, "data"),
	}
	if *verbose {
		analysis = append(analysis, "-v")
	}
	analysis = append(analysis, filepath.Join(root, "policy-v1"))

	// The analysis names every file it read, and here those names are a
	// temporary directory nobody asked about. The report is held and the
	// prefix taken off it, so it reads like a run against a checkout.
	var report, problems bytes.Buffer
	code := analyze.Run(analysis, &report, &problems)

	fmt.Fprint(stdout, shorten(report.String(), root))
	fmt.Fprint(stderr, shorten(problems.String(), root))
	if code != exitOK {
		return code
	}

	fmt.Fprint(stdout, "\nThat was the bundle built into this binary, written by hand with the "+
		"escalations in it.\nRun petard demo -extract <dir> to get the files, edit them, and "+
		"analyze them again.\n")
	return exitOK
}

// shorten replaces the directory the bundle was unpacked into with the name it
// carries inside the binary.
//
// Both spellings are taken off: the analysis reports paths with forward
// slashes, and the directory arrives from the operating system with whatever
// separator it uses.
func shorten(report, root string) string {
	for _, spelling := range []string{filepath.ToSlash(root), root} {
		report = strings.ReplaceAll(report, spelling, fixtures.BundleDir)
	}
	return report
}
