// Package explain prints one pattern of the registry for a person to read.
//
// A report names a pattern by its id and its title, which is enough to know
// something was found and not enough to argue with it. The file behind that id
// says what the engine looked for, what has to be true for the finding to be a
// defect, and which conditions it fires on for nothing. This command puts that
// in the terminal, so that the answer to "why am I being told this" does not
// require the repository.
//
// The prose belongs to whoever writes the registry. Nothing here interprets it:
// the fields are read and printed, in the order a reader needs them.
package explain

import (
	"flag"
	"fmt"
	"io"
	"io/fs"
	"strconv"
	"strings"

	yaml "go.yaml.in/yaml/v3"

	"github.com/saluc28/petard/internal/cli/render"
	"github.com/saluc28/petard/internal/taxonomy"
	registry "github.com/saluc28/petard/taxonomy-registry"
)

const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2
)

// entry is a pattern file as a reader needs it.
//
// It is deliberately not taxonomy.Pattern. That type is what the engine needs,
// and it leaves this prose out so that no computation can start depending on a
// paragraph somebody rewords. Here the paragraphs are the point and nothing
// reads them but the printer below.
type entry struct {
	ID     string `yaml:"id"`
	Name   string `yaml:"name"`
	Title  string `yaml:"title"`
	Engine string `yaml:"engine"`
	Status string `yaml:"status"`

	Category struct {
		ID      string `yaml:"id"`
		Title   string `yaml:"title"`
		Summary string `yaml:"summary"`
	} `yaml:"category"`

	Summary string `yaml:"summary"`

	Preconditions []struct {
		Capability string `yaml:"capability"`
		Note       string `yaml:"note"`
	} `yaml:"preconditions"`

	Detection struct {
		Signals []struct {
			Check     string `yaml:"check"`
			Rationale string `yaml:"rationale"`
		} `yaml:"signals"`
		Confidence         string `yaml:"confidence"`
		ConfidenceNote     string `yaml:"confidence_note"`
		RequiresWriteModel bool   `yaml:"requires_write_model"`
	} `yaml:"detection"`

	FalsePositives []struct {
		Condition     string `yaml:"condition"`
		Discriminator string `yaml:"discriminator"`
		Measurement   string `yaml:"measurement"`
		Case          *struct {
			Reports bool `yaml:"reports"`
		} `yaml:"case"`
	} `yaml:"false_positives"`
}

// Run prints the pattern the argument names.
func Run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("petard explain", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprint(stderr, "usage: petard explain <id or name>\n\n"+
			"Prints what a pattern looks for, and what it will not report.\n\n")
		flags.PrintDefaults()
	}
	registryPath := flags.String("registry", "", registry.FlagUsage)

	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	switch flags.NArg() {
	case 1:
	case 0:
		flags.Usage()
		return exitUsage
	default:
		fmt.Fprintln(stderr, "petard explain: one pattern at a time")
		return exitUsage
	}

	source := registry.Source(*registryPath)
	all, err := taxonomy.LoadRegistry(source)
	if err != nil {
		fmt.Fprintf(stderr, "petard explain: %v\n", err)
		return exitFailure
	}

	wanted := flags.Arg(0)
	pattern, found := find(all, wanted)
	if !found {
		fmt.Fprintf(stderr, "petard explain: no pattern is called %s; run petard patterns for the list\n", wanted)
		return exitUsage
	}

	content, err := fs.ReadFile(source, pattern.File)
	if err != nil {
		fmt.Fprintf(stderr, "petard explain: %v\n", err)
		return exitFailure
	}
	var full entry
	if err := yaml.Unmarshal(content, &full); err != nil {
		fmt.Fprintf(stderr, "petard explain: parsing %s: %v\n", pattern.File, err)
		return exitFailure
	}

	printEntry(stdout, full, pattern.File)
	return exitOK
}

// find takes an id or the name, in any case. Both are printed in every report,
// and asking somebody to remember which of the two the command wants is asking
// them to look it up first.
func find(all []taxonomy.Pattern, wanted string) (taxonomy.Pattern, bool) {
	for _, pattern := range all {
		if strings.EqualFold(pattern.ID, wanted) || strings.EqualFold(pattern.Name, wanted) {
			return pattern, true
		}
	}
	return taxonomy.Pattern{}, false
}

func printEntry(out io.Writer, e entry, file string) {
	fmt.Fprintf(out, "%s  %s\n", e.ID, e.Name)
	render.Print(out, render.Plain(e.Title), "")

	fmt.Fprintf(out, "\n  Category  %s, %s\n", e.Category.ID, e.Category.Title)
	fmt.Fprintf(out, "  Engine    %s\n", e.Engine)
	fmt.Fprintf(out, "  Status    %s\n", e.Status)

	section(out, "What it is")
	render.Print(out, render.Plain(e.Summary), "  ")

	if len(e.Preconditions) > 0 {
		section(out, "What has to be true for it to be a defect")
		render.Print(out, "All of them. One that does not hold is the pattern closed.", "  ")
		for _, precondition := range e.Preconditions {
			fmt.Fprintln(out)
			bullet(out, render.Plain(precondition.Capability))
			if precondition.Note != "" {
				render.Print(out, render.Plain(precondition.Note), "    ")
			}
		}
	}

	if len(e.Detection.Signals) > 0 {
		section(out, "What it looks for")
		for i, signal := range e.Detection.Signals {
			if i > 0 {
				fmt.Fprintln(out)
			}
			numbered(out, i+1, render.Plain(signal.Check))
		}
		if e.Detection.RequiresWriteModel {
			fmt.Fprintln(out)
			render.Print(out, "It needs a write model. Without one every match stays a candidate, "+
				"because the last signal is about who can write, and that is not in the policy.", "  ")
		}
		if e.Detection.Confidence != "" {
			fmt.Fprintf(out, "\n  Confidence %s by default, and per finding after that.\n", e.Detection.Confidence)
			render.Print(out, render.Plain(e.Detection.ConfidenceNote), "  ")
		}
	}

	if len(e.FalsePositives) > 0 {
		section(out, "Where it fires with nothing behind it")
		render.Print(out, "Declared by whoever wrote the pattern, and reported anyway when it happens.", "  ")
		for _, fp := range e.FalsePositives {
			fmt.Fprintln(out)
			bullet(out, render.Plain(fp.Condition))
			if fp.Discriminator != "" {
				render.Print(out, "Told apart by: "+render.Plain(fp.Discriminator), "    ")
			}
			render.Print(out, settled(fp.Measurement, fp.Case != nil && fp.Case.Reports), "    ")
		}
	}

	section(out, "Written down in")
	fmt.Fprintf(out, "  %s\n", registry.Path(file))
	fmt.Fprintf(out, "  %s%s\n", registry.URL, file)
}

// settled says how a declared false positive was settled, which is what
// separates a pattern somebody verified from one somebody asserted.
func settled(measurement string, reports bool) string {
	switch {
	case measurement == taxonomy.MeasurementCase && reports:
		return "The registry carries a policy that realizes this, and the engine still reports it."
	case measurement == taxonomy.MeasurementCase:
		return "The registry carries a policy that realizes this, and the engine tells it apart."
	case measurement == taxonomy.MeasurementOutOfBand:
		return "Neither the policy nor the data holds what would tell the two apart. A person has to."
	default:
		return "How this one is settled is not written down yet."
	}
}

func section(out io.Writer, title string) {
	fmt.Fprintf(out, "\n%s\n", title)
}

func bullet(out io.Writer, text string) {
	item(out, "-", text)
}

func numbered(out io.Writer, n int, text string) {
	item(out, strconv.Itoa(n)+".", text)
}

// item prints one entry of a list: the marker, then the text wrapped so that
// what runs on lines up under what the marker introduced rather than under the
// marker itself.
func item(out io.Writer, marker, text string) {
	indent := strings.Repeat(" ", len("  ")+len(marker)+len(" "))

	lines := render.Wrap(text, indent)
	if len(lines) == 0 {
		return
	}
	fmt.Fprintf(out, "  %s %s\n", marker, strings.TrimSpace(lines[0]))
	for _, line := range lines[1:] {
		fmt.Fprintln(out, line)
	}
}
