// Command petard reads Rego policies, works out what their decisions depend
// on, applies the taxonomy of escalation patterns to what it finds, and sends
// the result to BloodHound as a structured OpenGraph.
//
// It is one binary with subcommands, the way opa and regal are, because a
// person who downloads a file should not have to know which of three it is.
package main

import (
	"fmt"
	"io"
	"os"
	"path"
	"runtime/debug"
	"slices"
	"strings"

	"github.com/saluc28/petard/internal/cli/analyze"
	"github.com/saluc28/petard/internal/cli/demo"
	"github.com/saluc28/petard/internal/cli/export"
	"github.com/saluc28/petard/internal/cli/measure"
)

// version, commit and date are set by the linker on a release build. A binary
// built any other way says so, since the first thing a bug report needs is
// which build it came from.
var (
	version = ""
	commit  = ""
	date    = ""
)

const (
	exitOK      = 0
	exitUsage   = 2
	programName = "petard"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return exitUsage
	}

	switch args[0] {
	case "analyze":
		return analyze.Run(args[1:], stdout, stderr)
	case "export":
		return export.Run(args[1:], stdout, stderr)
	case "measure":
		return measure.Run(args[1:], stdout, stderr)
	case "demo":
		return demo.Run(args[1:], stdout, stderr)
	case "version", "-version", "--version":
		for _, line := range buildLines() {
			fmt.Fprintln(stdout, line)
		}
		return exitOK
	case "help", "-h", "-help", "--help":
		usage(stdout)
		return exitOK
	default:
		fmt.Fprintf(stderr, "%s: unknown command %q\n\n", programName, args[0])
		usage(stderr)
		return exitUsage
	}
}

func usage(out io.Writer) {
	fmt.Fprint(out, `usage: petard <command> [flags] <path>...

Commands:
  analyze   read a policy bundle and report what its decisions depend on
  export    send the same analysis to BloodHound as an OpenGraph payload
  measure   run the engine over a body of Rego written by somebody else
  demo      analyze the vulnerable bundle built into this binary
  version   print the version, the commit and the build date

Run "petard <command> -h" for the flags of that command.
`)
}

// reported are the dependencies whose version changes what an analysis says.
//
// OPA is the parser and the evaluator, so the answer to "why does this bundle
// report differently than it did last month" is usually which one is linked in.
// bhgraph decides what BloodHound is asked to accept. They are compiled in, not
// called, so nobody can swap them without a new binary, and a report is only
// reproducible next to the versions that produced it.
var reported = []string{
	"github.com/open-policy-agent/opa",
	"github.com/saluc28/bhgraph",
}

// buildLines describe the binary: what it is, and what it carries.
func buildLines() []string {
	lines := []string{buildLine()}

	info, ok := debug.ReadBuildInfo()
	if !ok {
		return lines
	}
	for _, dep := range info.Deps {
		if !slices.Contains(reported, dep.Path) {
			continue
		}
		if dep.Replace != nil {
			lines = append(lines, fmt.Sprintf("%s %s, replaced by %s %s",
				path.Base(dep.Path), dep.Version, dep.Replace.Path, dep.Replace.Version))
			continue
		}
		lines = append(lines, path.Base(dep.Path)+" "+dep.Version)
	}
	return lines
}

// buildLine describes the binary in one line.
//
// A release build is stamped by the linker. A build from source has no stamp,
// and the module version Go records is read instead, so that "devel" or a
// pseudo-version is reported rather than nothing at all.
func buildLine() string {
	line := programName + " " + versionOrModule()

	var stamp []string
	if commit != "" {
		stamp = append(stamp, "commit "+commit)
	}
	if date != "" {
		stamp = append(stamp, "built "+date)
	}
	if len(stamp) > 0 {
		line += " (" + strings.Join(stamp, ", ") + ")"
	}
	return line
}

func versionOrModule() string {
	if version != "" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		return info.Main.Version
	}
	return "unknown version"
}
