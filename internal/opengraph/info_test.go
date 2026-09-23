package opengraph

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"text/template"

	"github.com/saluc28/bhgraph"

	"github.com/saluc28/petard/internal/opaengine"
	"github.com/saluc28/petard/internal/taxonomy"
	"github.com/saluc28/petard/internal/writemodel"
	registry "github.com/saluc28/petard/taxonomy-registry"
)

// The Entity Panel names every pattern by its title and links its file, so the
// notes here and the registry have to agree, one pattern for one pattern.
func TestPatternNotesFollowTheRegistry(t *testing.T) {
	patterns, err := taxonomy.LoadRegistry(registry.OPA)
	if err != nil {
		t.Fatalf("LoadRegistry() error = %v", err)
	}
	if len(patterns) != len(patternNotes) {
		t.Fatalf("the registry holds %d patterns, the notes %d", len(patterns), len(patternNotes))
	}
	for i, pattern := range patterns {
		note := patternNotes[i]
		if note.id != pattern.ID || note.name != pattern.Name || note.title != pattern.Title {
			t.Errorf("note %d = %s %s %q, the registry says %s %s %q",
				i, note.id, note.name, note.title, pattern.ID, pattern.Name, pattern.Title)
		}
	}
}

// Every kind says what it means, in a section of the same key and position.
func TestEveryKindSaysWhatItMeans(t *testing.T) {
	schema := Schema()
	for _, kind := range schema.NodeKinds {
		if kind.Info["meaning"].Position != 1 {
			t.Errorf("%s has no section saying what it means", kind.Name)
		}
	}
	for _, kind := range schema.RelationshipKinds {
		if kind.Info["meaning"].Position != 1 {
			t.Errorf("%s has no section saying what it means", kind.Name)
		}
	}
}

// What BloodHound hands a template, as server/graphdb/internal/services/template.go
// declares it at v9.7.0.
type (
	kindContext struct {
		KindID *int32
		Name   string
	}
	nodeContext struct {
		NodeID     int64
		Kinds      []kindContext
		Properties map[string]any
	}
	relationshipContext struct {
		RelationshipID int64
		Source         nodeContext
		Target         nodeContext
		Kind           kindContext
		Properties     map[string]any
	}
)

// fixturePayload is the graph of the fixture as BloodHound holds it: the
// payload, through JSON, so that a list is a []any and a number a float64.
func fixturePayload(t *testing.T) (nodes map[string]nodeContext, edges []relationshipContext) {
	t.Helper()

	fixture := filepath.Join("..", "..", "fixtures", "vulnerable-bundle")
	bundle, err := opaengine.Load([]string{filepath.Join(fixture, "policy-v1")}, opaengine.ParseModeAuto)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	reads, err := opaengine.Reads(bundle, opaengine.Limits{})
	if err != nil {
		t.Fatalf("Reads() error = %v", err)
	}
	a := taxonomy.Analysis{Bundle: bundle, Reads: reads, Shape: opaengine.RecognizeShape(reads)}
	if a.Model, err = writemodel.Load(filepath.Join(fixture, "write-model.yaml")); err != nil {
		t.Fatalf("writemodel.Load() error = %v", err)
	}
	if a.Data, err = opaengine.LoadData([]string{filepath.Join(fixture, "data")}); err != nil {
		t.Fatalf("LoadData() error = %v", err)
	}
	findings, err := taxonomy.Run(t.Context(), a)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	g, _, err := taxonomy.Assemble(t.Context(), a, findings)
	if err != nil {
		t.Fatalf("Assemble() error = %v", err)
	}

	encoded, err := json.Marshal(Payload(g))
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Graph struct {
			Nodes []struct {
				ID         string         `json:"id"`
				Kinds      []string       `json:"kinds"`
				Properties map[string]any `json:"properties"`
			} `json:"nodes"`
			Edges []struct {
				Kind       string                 `json:"kind"`
				Start      struct{ Value string } `json:"start"`
				End        struct{ Value string } `json:"end"`
				Properties map[string]any         `json:"properties"`
			} `json:"edges"`
		} `json:"graph"`
	}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}

	nodes = map[string]nodeContext{}
	for _, node := range decoded.Graph.Nodes {
		context := nodeContext{Properties: node.Properties}
		for _, kind := range node.Kinds {
			context.Kinds = append(context.Kinds, kindContext{Name: kind})
		}
		// Ingest upper-cases objectid and name unless the use_raw_object_id
		// feature flag is on, and it ships disabled and not user updatable
		// (cmd/api/src/services/graphify/ingestnodes.go and the migration
		// 20260710120000_v9_add_use_raw_object_id_flag_bed_8954.sql at v9.7.1).
		// A panel rendered against the payload would read a name the analyst
		// never sees.
		if name, isString := context.Properties["name"].(string); isString {
			context.Properties["name"] = strings.ToUpper(name)
		}
		nodes[strings.ToUpper(node.ID)] = context
	}
	for _, edge := range decoded.Graph.Edges {
		edges = append(edges, relationshipContext{
			Source:     nodes[strings.ToUpper(edge.Start.Value)],
			Target:     nodes[strings.ToUpper(edge.End.Value)],
			Kind:       kindContext{Name: edge.Kind},
			Properties: edge.Properties,
		})
	}
	return nodes, edges
}

// render evaluates every section of a panel against one entity, the way the
// server does, and returns them joined.
func render(t *testing.T, sections map[string]string, context any) string {
	t.Helper()

	var panels []string
	for key, content := range sections {
		parsed, err := template.New("kind-info-markdown").Parse(content)
		if err != nil {
			t.Fatalf("section %s does not parse: %v", key, err)
		}
		var rendered bytes.Buffer
		if err := parsed.Execute(&rendered, context); err != nil {
			t.Fatalf("section %s does not render: %v", key, err)
		}
		// BloodHound shows a section that renders to nothing as its heading
		// with a blank under it, which reads as a panel that failed rather
		// than as an entity nothing was found on.
		if strings.TrimSpace(rendered.String()) == "" {
			t.Errorf("section %s renders empty", key)
		}
		panels = append(panels, rendered.String())
	}
	// The panel shows the sections apart, and a test that ran them together
	// would read a sentence that BloodHound never shows.
	return strings.Join(panels, "\n\n")
}

// Every panel renders for every entity of the fixture, which holds every kind
// and every pattern, without an error and without a missing value printed as
// such. BloodHound shows the raw template when rendering fails, so a template
// that breaks on one entity breaks in front of the analyst.
func TestPanelsRenderForEveryEntityOfTheFixture(t *testing.T) {
	schema := Schema()
	nodeSections, edgeSections := map[string]map[string]string{}, map[string]map[string]string{}
	for _, kind := range schema.NodeKinds {
		nodeSections[kind.Name] = contents(kind.Info)
	}
	for _, kind := range schema.RelationshipKinds {
		edgeSections[kind.Name] = contents(kind.Info)
	}

	nodes, edges := fixturePayload(t)
	rendered := map[string]string{}
	check := func(what, text string) {
		if strings.Contains(text, "<no value>") || strings.Contains(text, "{{") {
			t.Errorf("%s renders a missing value or a template:\n%s", what, text)
		}
		rendered[what] = text
	}
	for id, node := range nodes {
		check(id, render(t, nodeSections[node.Kinds[0].Name], node))
	}
	for _, edge := range edges {
		what := edge.Kind.Name + " " + edge.Source.Properties["name"].(string) + " -> " + edge.Target.Properties["name"].(string)
		check(what, render(t, edgeSections[edge.Kind.Name], edge))
	}

	says := func(what, expected string) {
		t.Helper()
		if text, found := rendered[what]; !found || !strings.Contains(text, expected) {
			t.Errorf("%s does not say %q:\n%s", what, expected, text)
		}
	}
	says("PTD_CanEscalateTo CAROL -> ALICE", "**CAROL** can take the position **ALICE** holds")
	says("PTD_Reads DATA.QUILL.TENANT_POLICY.DENIED_MFA -> DATA.TENANTS[_].POLICY.REQUIRE_MFA",
		"**Absent for** dolm, out of 2 documents tried.")
	says("DATA.QUILL.REVIEW.ALLOW_UNGUARDED", "`input.reviews`")
	says("MALLORY", "No pattern reports on this principal.")
	says("PTD_CanEscalateTo MALLORY -> DAVE",
		"the names of the fields look like a subject or an action, which is a guess")
	for what, text := range rendered {
		if strings.HasPrefix(what, "PTD_CanEscalateTo CAROL") && !strings.Contains(text, "PTD-OPA-006") {
			t.Errorf("%s does not name the pattern that drew it:\n%s", what, text)
		}
	}
}

func contents(info map[string]bhgraph.KindInfo) map[string]string {
	out := make(map[string]string, len(info))
	for key, section := range info {
		out[key] = section.Markdown.Content
	}
	return out
}
