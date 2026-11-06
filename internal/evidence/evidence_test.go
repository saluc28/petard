package evidence

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	yaml "go.yaml.in/yaml/v3"
)

// A citation is path:line, or a mapping that adds the text the line holds. A path that
// leaves the source, or a line that is not a number from 1, is refused.
func TestCitationReadsBothForms(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		expected Citation
		err      bool
	}{
		{name: "path and line", yaml: "api/share.go:88", expected: Citation{Path: "api/share.go", Line: 88}},
		{name: "with the text the line holds", yaml: "{at: api/share.go:88, text: WriteRelationships}", expected: Citation{Path: "api/share.go", Line: 88, Text: "WriteRelationships"}},
		{name: "a windows path", yaml: `'api\share.go:88'`, expected: Citation{Path: "api/share.go", Line: 88}},
		{name: "no line", yaml: "api/share.go", err: true},
		{name: "line zero", yaml: "api/share.go:0", err: true},
		{name: "outside the source", yaml: "../app/share.go:3", err: true},
		{name: "an absolute path", yaml: "/etc/passwd:1", err: true},
		{name: "an unknown key", yaml: "{at: api/share.go:88, line: 3}", err: true},
		{name: "a list", yaml: "[api/share.go, 88]", err: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got Citation
			err := yaml.Unmarshal([]byte(tt.yaml), &got)
			switch {
			case tt.err && !errors.Is(err, ErrCitation):
				t.Errorf("Unmarshal(%s) = %+v, %v, want %v", tt.yaml, got, err, ErrCitation)
			case !tt.err && (err != nil || got != tt.expected):
				t.Errorf("Unmarshal(%s) = %+v, %v, want %+v", tt.yaml, got, err, tt.expected)
			}
		})
	}
}

// A cited line holds while its file is there, has the line, and the line holds the text
// the citation gives; each failure says which.
func TestCheck(t *testing.T) {
	source := fstest.MapFS{
		"api/share.go": {Data: []byte("package api\n\nfunc share() {\n\tclient.WriteRelationships(ctx, req)\n}\n")},
	}
	tests := []struct {
		name     string
		citation Citation
		expected string
	}{
		{name: "the line", citation: Citation{Path: "api/share.go", Line: 4}},
		{name: "the line and its text", citation: Citation{Path: "api/share.go", Line: 4, Text: "WriteRelationships"}},
		{name: "the code moved", citation: Citation{Path: "api/share.go", Line: 3, Text: "WriteRelationships"}, expected: `the line does not hold "WriteRelationships"`},
		{name: "past the end", citation: Citation{Path: "api/share.go", Line: 40}, expected: "the file has fewer than 40 lines"},
		{name: "no such file", citation: Citation{Path: "api/gone.go", Line: 1}, expected: "the file is not there"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Check(source, tt.citation)
			switch {
			case tt.expected == "" && err != nil:
				t.Errorf("Check(%s) = %v, want nil", tt.citation, err)
			case tt.expected != "" && (err == nil || err.Error() != tt.expected):
				t.Errorf("Check(%s) = %v, want %q", tt.citation, err, tt.expected)
			}
		})
	}
}

// The calls that write are found in the spelling of each SDK and by the HTTP path, once
// a line; a request type, a call of another name, a test, and code under vendor or
// node_modules are not.
func TestSites(t *testing.T) {
	source := fstest.MapFS{
		"api/share.go":            {Data: []byte("func share() {\n\treq := &v1.WriteRelationshipsRequest{}\n\tclient.WriteRelationships(ctx, req)\n}\n")},
		"api/ban.py":              {Data: []byte("def unban():\n    client.delete_relationships(request)\n")},
		"jobs/sync.ts":            {Data: []byte("await client.importBulkRelationships(meta);\n")},
		"web/members.ts":          {Data: []byte("const body: ClientWriteRequest = {writes: []};\nawait fga.write(body);\nawait fga.writeTuples(tuples);\n")},
		"web/raw.js":              {Data: []byte("fetch(`${url}/stores/${store}/write`, {method: 'POST'})\nfetch(base + '/v1/relationships/write')\n")},
		"api/logs.go":             {Data: []byte("w.Write(p)\nbuf.WriteString(s)\n")},
		"api/share_test.go":       {Data: []byte("client.WriteRelationships(ctx, req)\n")},
		"web/members.spec.ts":     {Data: []byte("await fga.writeTuples(tuples);\n")},
		"vendor/sdk/client.go":    {Data: []byte("func (c *Client) WriteRelationships() {}\n")},
		"node_modules/x/index.js": {Data: []byte("writeTuples()\n")},
		"README.md":               {Data: []byte("call WriteRelationships\n")},
	}
	sites, err := Sites(source)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, s := range sites {
		got = append(got, s.String()+" "+s.Call+" "+s.Product)
	}
	expected := []string{
		"api/ban.py:2 delete_relationships SpiceDB",
		"api/share.go:3 WriteRelationships SpiceDB",
		"jobs/sync.ts:1 importBulkRelationships SpiceDB",
		"web/members.ts:1 ClientWriteRequest OpenFGA",
		"web/members.ts:3 writeTuples OpenFGA",
		"web/raw.js:1 /stores/${store}/write OpenFGA",
		"web/raw.js:2 /v1/relationships/write SpiceDB",
	}
	if !slices.Equal(got, expected) {
		t.Errorf("Sites:\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(expected, "\n"))
	}
}

// A line past the longest Sites reads is a bundle or generated code: the file is read up to
// it, and the search goes on with the next file instead of failing.
func TestSitesStopAtALineTooLongToRead(t *testing.T) {
	bundle := "writeTuples(a)\n" + strings.Repeat("x", maxLine+1) + "\nwriteTuples(b)\n"
	source := fstest.MapFS{
		"web/bundle.js":  {Data: []byte(bundle)},
		"web/members.ts": {Data: []byte("await fga.deleteTuples(tuples);\n")},
	}
	sites, err := Sites(source)
	if err != nil {
		t.Fatalf("Sites: %v", err)
	}
	var got []string
	for _, site := range sites {
		got = append(got, site.String())
	}
	if want := []string{"web/bundle.js:1", "web/members.ts:1"}; !slices.Equal(got, want) {
		t.Errorf("Sites = %v, want %v", got, want)
	}
}
