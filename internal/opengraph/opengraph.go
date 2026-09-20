// Package opengraph adapts Petard's internal model to what BloodHound ingests.
//
// The payload format, the extension definition schema and the signed client all
// live in bhgraph, which is a separate module because they are useful to any
// collector and have nothing to do with Rego. What lives here is the adapter:
// which of our kinds is drawn how, and how an internal edge becomes an edge of
// the payload.
//
// The names and the traversability are not restated here. They come from
// internal/graph, because they end up in ingested data and in saved Cypher
// queries, and a schema that disagreed with the model would produce a graph
// nobody could query.
package opengraph

import (
	"encoding/json"
	"fmt"
	"maps"

	"github.com/saluc28/bhgraph"

	"github.com/saluc28/petard/internal/graph"
)

// Version is the version of the schema Petard installs, which changes whenever
// a kind or a property does. BloodHound keys an extension by its name, so this
// is what tells one installation from the next.
const Version = "v0.2.1"

// namespace is what the extension declares, and it is PTD and not PTD_.
//
// BloodHound appends the underscore itself: it accepts a kind only if the name
// starts with the namespace followed by "_" (cmd/api/src/model/graphschema.go:508
// at v9.7.0). Declaring PTD_ therefore makes the server look for PTD__Principal
// and refuse the whole schema with a 400 that names the first kind. The kind
// names do not change either way: they are PTD_Principal and friends, and it is
// only the declared namespace that leaves the underscore out.
const namespace = "PTD"

// display is how a node kind is drawn, which is the only thing about a kind
// that the model has no opinion on.
//
// Icons are Font Awesome free solid names, which is what BloodHound renders.
// Declaring them here makes the custom-nodes endpoint unnecessary.
//
// Every kind is declared a display kind, the way MSSQLHound declares all seven
// of its own. The server registers an icon only for a display kind
// (upsertCustomIcons in cmd/api/src/database/upsert_schema_extension.go at
// v9.7.1), and the UI draws a question mark for a kind it finds no icon for
// (GetIconInfo in packages/javascript/bh-shared-ui/src/utils/icons.ts). A node
// here carries one kind, so there is nothing for a display kind to disambiguate
// and nothing to gain by leaving one out.
type display struct {
	displayName string
	description string
	icon        string
	color       string
}

// displays are keyed by kind, and a kind missing from this table is a schema
// that cannot describe its own graph. The test next door walks graph.NodeKinds
// so that adding a kind and forgetting to draw it fails here rather than in
// somebody's browser.
var displays = map[graph.NodeKind]display{
	graph.NodeKindPrincipal: {
		displayName: "Principal",
		description: "Anything that can hold privilege: a user, a role, a service account, or an external system that decides on their behalf.",
		icon:        "user",
		color:       "#4d7ea8",
	},
	graph.NodeKindAction: {
		displayName: "Action",
		description: "An operation a principal may be allowed to perform, as the policy names it.",
		icon:        "bolt",
		color:       "#e0a458",
	},
	graph.NodeKindResource: {
		displayName: "Resource",
		description: "What an action is performed on, named by the document a decision turned out to allow.",
		icon:        "file",
		color:       "#6a994e",
	},
	graph.NodeKindAttribute: {
		displayName: "Attribute",
		description: "A field a decision depends on, whether it was read from data or believed from an external answer. It is what an escalation aims at.",
		icon:        "tag",
		color:       "#9b5de5",
	},
	graph.NodeKindRule: {
		displayName: "Rule",
		description: "A rule of the analyzed policy. Whether the PEP asks for it directly is the is_decision property.",
		icon:        "gavel",
		color:       "#bc4749",
	},
}

// descriptions say what an edge means, in the terms an analyst reading the UI
// has rather than the terms the analysis has.
var descriptions = map[graph.EdgeKind]string{
	graph.EdgeKindCanPerform:    "The principal can get this out of a decision, given the data as it stands. The condition property is what still has to hold.",
	graph.EdgeKindReads:         "The rule depends on this attribute. A dependency, not a capability, which is why it is not traversable.",
	graph.EdgeKindWrittenBy:     "The attribute can be written by this principal. It describes the system around OPA and is declared rather than derived from any policy.",
	graph.EdgeKindCanEscalateTo: "The principal can reach the position the other one holds, by writing something they are allowed to write. The only edge that means privilege escalation.",
	graph.EdgeKindTaintedBy:     "The value comes from this external source rather than from the policy. A dependency, not a capability.",
}

// Schema returns the extension definition schema Petard installs.
//
// Environments are left empty on purpose. The environment of a Petard graph
// would be the analyzed bundle, and the model has no node for a bundle: adding
// one to fill a field that only does anything in BloodHound Enterprise would
// mean an eleventh kind on a list the model declares closed. The field is
// legal empty, and what it would buy in Community Edition is nothing.
func Schema() bhgraph.Extension {
	extension := bhgraph.Extension{
		Schema: bhgraph.SchemaMeta{
			Name:        "petard",
			DisplayName: "Petard",
			Version:     Version,
			Namespace:   namespace,
		},
		RelationshipFindings: []any{},
		Environments:         []bhgraph.Environment{},
	}

	for _, kind := range graph.NodeKinds() {
		drawn := displays[kind]
		extension.NodeKinds = append(extension.NodeKinds, bhgraph.NodeKind{
			Name:          string(kind),
			DisplayName:   drawn.displayName,
			Description:   drawn.description,
			IsDisplayKind: true,
			Icon:          drawn.icon,
			Color:         drawn.color,
			Info:          nodeInfo(kind),
		})
	}

	for _, kind := range graph.EdgeKinds() {
		extension.RelationshipKinds = append(extension.RelationshipKinds, bhgraph.RelationshipKind{
			Name:          string(kind),
			Description:   descriptions[kind],
			IsTraversable: kind.IsTraversable(),
			Info:          edgeInfo(kind),
		})
	}
	return extension
}

// Payload turns the internal graph into the one that gets uploaded.
//
// The provenance of an edge is merged into its properties here and not before.
// Inside Petard, where a claim comes from is a field of its own so that nothing
// can overwrite it by accident; on the wire everything is a property, and this
// is the one place that knows both shapes.
func Payload(g *graph.Graph) bhgraph.Graph {
	var payload bhgraph.Graph

	for _, node := range g.Nodes() {
		payload.AddNode(bhgraph.Node{
			ID:         node.ID,
			Kinds:      []string{string(node.Kind)},
			Properties: maps.Clone(node.Properties),
		})
	}

	for _, edge := range g.Edges() {
		properties := edge.Source.Properties()
		maps.Copy(properties, edge.Properties)
		payload.AddEdge(bhgraph.Edge{
			Kind:       string(edge.Kind),
			Start:      bhgraph.NodeRef(edge.From),
			End:        bhgraph.NodeRef(edge.To),
			Properties: properties,
		})
	}
	return payload
}

// Validate checks a payload against the schema Petard installs, and against the
// structure BloodHound expects.
//
// It is worth doing before anything is sent because an ingest job answers
// asynchronously and poorly: an edge pointing at a node nobody emitted is
// accepted and then quietly produces nothing.
func Validate(payload bhgraph.Graph) error {
	schema := Schema()
	if err := schema.Validate(); err != nil {
		return fmt.Errorf("opengraph: the schema does not hold together: %w", err)
	}
	if err := payload.ValidateAgainst(schema); err != nil {
		return fmt.Errorf("opengraph: the payload does not match the schema: %w", err)
	}
	return nil
}

// SchemaFile is where the installed schema is kept in the repository.
//
// It is committed rather than only generated because it is the contract with
// data that has already been ingested: a reviewer has to be able to see a kind
// name change in a diff, not discover it after the fact in a graph that no
// longer matches its queries. The test beside this file regenerates it and
// fails when the two disagree.
const SchemaFile = "petard.json"

// MarshalSchema renders the schema the way it is committed: indented, and with
// a trailing newline, so that a diff of two versions is a diff of what changed.
func MarshalSchema() ([]byte, error) {
	encoded, err := json.MarshalIndent(Schema(), "", "  ")
	if err != nil {
		return nil, fmt.Errorf("opengraph: writing the schema: %w", err)
	}
	return append(encoded, '\n'), nil
}
