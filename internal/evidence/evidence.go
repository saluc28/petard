// Package evidence holds a write model to the source of the application it describes. A
// rule can cite the lines of that source that make its write, and Check says whether each
// line is still there; Sites lists the places in the source that call a write of SpiceDB
// or OpenFGA, so a reviewer can see which of them no rule cites.
//
// Neither says that a cited line does what the rule declares, or that the application
// checks the gate a rule names: that is for a person to read.
package evidence

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	yaml "go.yaml.in/yaml/v3"
)

// ErrCitation is returned for a citation that is not written as path:line.
var ErrCitation = errors.New("evidence: invalid citation")

// Citation is a line of the application's source a rule of a write model rests on, at a
// path relative to the root the source is read from, with a slash between directories.
// Text is what the line has to hold, so that a line the code has moved away from shows
// up; it is empty when the rule cites the line alone.
type Citation struct {
	Path string
	Line int
	Text string
}

// String writes the citation as path:line.
func (c Citation) String() string {
	return c.Path + ":" + strconv.Itoa(c.Line)
}

// UnmarshalYAML reads a citation written as path:line, or as a mapping with at, the
// path:line, and text, what the line holds.
func (c *Citation) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		return c.parse(node.Value, node.Line)
	case yaml.MappingNode:
		var m struct {
			At   string `yaml:"at"`
			Text string `yaml:"text"`
		}
		for i := 0; i+1 < len(node.Content); i += 2 {
			if key := node.Content[i].Value; key != "at" && key != "text" {
				return fmt.Errorf("%w: line %d: unknown key %q, a citation holds at and text", ErrCitation, node.Content[i].Line, key)
			}
		}
		if err := node.Decode(&m); err != nil {
			return err
		}
		if err := c.parse(m.At, node.Line); err != nil {
			return err
		}
		c.Text = m.Text
		return nil
	}
	return fmt.Errorf("%w: line %d: a citation is path:line, or {at: path:line, text: ...}", ErrCitation, node.Line)
}

// parse reads path:line. The path is relative and stays inside the root: a citation names
// a line of the application, not a file anywhere on the machine.
func (c *Citation) parse(text string, line int) error {
	at := strings.LastIndex(text, ":")
	if at <= 0 {
		return fmt.Errorf("%w: line %d: %q is not path:line", ErrCitation, line, text)
	}
	n, err := strconv.Atoi(text[at+1:])
	if err != nil || n < 1 {
		return fmt.Errorf("%w: line %d: %q does not end in a line number", ErrCitation, line, text)
	}
	p := path.Clean(strings.ReplaceAll(text[:at], "\\", "/"))
	if !fs.ValidPath(p) {
		return fmt.Errorf("%w: line %d: %q is not a path inside the source", ErrCitation, line, text)
	}
	c.Path, c.Line = p, n
	return nil
}

// Check says whether a cited line is still in the source: the file is there, it has the
// line, and the line holds the text the citation gives. The error says which of these
// failed, in words a report prints after the citation.
func Check(source fs.FS, c Citation) error {
	f, err := source.Open(c.Path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return errors.New("the file is not there")
		}
		return err
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), maxLine)
	for n := 1; scanner.Scan(); n++ {
		if n < c.Line {
			continue
		}
		if c.Text != "" && !strings.Contains(scanner.Text(), c.Text) {
			return fmt.Errorf("the line does not hold %q", c.Text)
		}
		return nil
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return fmt.Errorf("the file has fewer than %d lines", c.Line)
}

// maxLine is the longest line a citation or a site can be read on. A longer one is
// minified or generated, not something a rule cites.
const maxLine = 1 << 20

// Site is a line of the application's source that calls a write of a product.
type Site struct {
	Path string
	Line int

	// Call is the name the line calls, as the source spells it, and Product the
	// product it writes to.
	Call    string
	Product string
}

// String writes the site as path:line.
func (s Site) String() string {
	return s.Path + ":" + strconv.Itoa(s.Line)
}

// writeNames are the calls that write tuples, by their name with case and underscores
// taken out, so one entry stands for the spelling of every SDK.
//
// SpiceDB names the calls in its API, and each SDK keeps the name in its own case:
// WriteRelationships, DeleteRelationships and ImportBulkRelationships
// (authzed/api/v1/permission_service_grpc.pb.go:47, :52 and :85 in authzed-go v1.11.0,
// src/authzed/api/v1/permission_service_pb2_grpc.py:24, :29 and :59 in authzed-py
// v1.25.0, src/authzedapi/authzed/api/v1/permission_service.grpc-client.ts:50, :62 and
// :124 in authzed-node v1.7.0), and BulkImportRelationships before it
// (experimental_service_grpc.pb.go:43 in authzed-go v1.11.0).
//
// OpenFGA names its call Write (openfga/v1/openfga_service.proto:142 in openfga/api at
// f153694bfc20), which says nothing outside the call, so a site is found by what its SDKs
// name distinctly: the request a write takes, ClientWriteRequest, and the calls that
// write or delete tuples (client/client.go:1506, :1920 and :1984 in go-sdk v0.8.3,
// client.ts:220, :611 and :633 in js-sdk v0.9.7, openfga_sdk/client/models/write_request.py:6
// and openfga_sdk/client/client.py:613 and :630 in python-sdk v0.10.5).
var writeNames = map[string]string{
	"writerelationships":      "SpiceDB",
	"deleterelationships":     "SpiceDB",
	"importbulkrelationships": "SpiceDB",
	"bulkimportrelationships": "SpiceDB",
	"clientwriterequest":      "OpenFGA",
	"writetuples":             "OpenFGA",
	"deletetuples":            "OpenFGA",
}

// writePaths are the HTTP paths a write is posted to, for a source that calls the API
// without an SDK: those of SpiceDB's gateway (permission_service.pb.gw.go:507, :524 and
// :626 in authzed-go v1.11.0) and OpenFGA's (openfga_service.proto:144 in openfga/api at
// f153694bfc20).
var writePaths = []struct {
	pattern *regexp.Regexp
	product string
}{
	{regexp.MustCompile(`/v1/relationships/(write|delete|importbulk)\b`), "SpiceDB"},
	{regexp.MustCompile(`/stores/[^/\s"'` + "`" + `]+/write\b`), "OpenFGA"},
}

var identifier = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*`)

// sourceExtensions are the files Sites reads.
var sourceExtensions = []string{
	".go", ".py", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".java", ".kt", ".scala",
	".cs", ".rb", ".php", ".rs", ".ex", ".exs",
}

// skippedDirs are the directories Sites does not walk: other people's code, what a build
// leaves, and the history of the repository.
var skippedDirs = []string{".git", "node_modules", "vendor", "third_party", "dist", "build", "target", ".venv", "venv", "__pycache__"}

// Sites finds the lines of the source that call a write of SpiceDB or OpenFGA, by name,
// in the order the files and lines come. Tests are left out by the names the languages
// give them, since what they write goes to a store of their own.
//
// It finds a call by its name, so a line that only mentions one, in a comment, counts,
// and a call made through a wrapper of another name does not. It is where a review
// starts, not proof that there is no other place.
func Sites(source fs.FS) ([]Site, error) {
	var out []Site
	err := fs.WalkDir(source, ".", func(p string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if p != "." && slices.Contains(skippedDirs, entry.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		if !slices.Contains(sourceExtensions, path.Ext(p)) || isTest(entry.Name()) {
			return nil
		}
		found, err := sitesIn(source, p)
		out = append(out, found...)
		return err
	})
	return out, err
}

// sitesIn are the sites of one file.
func sitesIn(source fs.FS, p string) ([]Site, error) {
	f, err := source.Open(p)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var out []Site
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), maxLine)
	for n := 1; scanner.Scan(); n++ {
		line := scanner.Text()
		if site, ok := siteOn(line); ok {
			site.Path, site.Line = p, n
			out = append(out, site)
		}
	}
	if err := scanner.Err(); err != nil {
		// A line past maxLine is generated or minified, and the rest of the file
		// is read no further.
		if errors.Is(err, bufio.ErrTooLong) {
			return out, nil
		}
		return nil, err
	}
	return out, nil
}

// siteOn is the first write a line calls, by name or by path.
func siteOn(line string) (Site, bool) {
	for _, name := range identifier.FindAllString(line, -1) {
		if product, ok := writeNames[strings.ToLower(strings.ReplaceAll(name, "_", ""))]; ok {
			return Site{Call: name, Product: product}, true
		}
	}
	for _, w := range writePaths {
		if m := w.pattern.FindString(line); m != "" {
			return Site{Call: m, Product: w.product}, true
		}
	}
	return Site{}, false
}

// isTest says whether a file is a test by the name its language gives one: name_test.go,
// test_name.py or name_test.py, name.test.ts or name.spec.ts, NameTest.java or
// NameTests.cs.
func isTest(name string) bool {
	base := strings.TrimSuffix(name, path.Ext(name))
	switch {
	case strings.HasSuffix(base, "_test"), strings.HasPrefix(base, "test_"):
		return true
	case strings.HasSuffix(base, ".test"), strings.HasSuffix(base, ".spec"):
		return true
	case strings.HasSuffix(base, "Test"), strings.HasSuffix(base, "Tests"):
		return true
	}
	return false
}
