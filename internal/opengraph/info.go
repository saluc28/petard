package opengraph

import (
	"fmt"
	"strings"

	"github.com/saluc28/bhgraph"

	"github.com/saluc28/petard/internal/graph"
	registry "github.com/saluc28/petard/taxonomy-registry"
)

// This file holds what BloodHound shows in the Entity Panel for each kind: what
// a node or an edge of that kind means, and what Petard found about the one
// selected. The second half is a Go template BloodHound evaluates against the
// selected entity, with .Properties for a node and .Source, .Target and
// .Properties for a relationship (server/graphdb/internal/services/template.go
// at v9.7.0). It uses the functions text/template has built in and nothing
// else, so that a test can render it the way the server does.

// registryURL is where the file of each pattern is read on GitHub.
const registryURL = registry.URL

// patternNote is what the panel says about one pattern: its title in the
// registry, the name that makes its file, and what closes it, which is what the
// counter case of the fixture shows, where there is one to show.
type patternNote struct {
	id, name, title, closes string
}

// patternNotes are the patterns of the registry, in order. A test holds them to
// the registry, so that a pattern added there and forgotten here fails.
var patternNotes = []patternNote{
	{
		id: "PTD-OPA-001", name: "attribute-self-write",
		title:  "The subject writes an attribute the policy reads to decide about them",
		closes: "A field the subject cannot write, assigned by a role through an administration API, is the counter case.",
	},
	{
		id: "PTD-OPA-002", name: "deny-undefined-on-missing-data",
		title:  "A deny rule is silent for part of the data, so the check does not apply there",
		closes: "A default that denies on the rule that reads, or a second rule of the decision that denies when the path is missing, closes it.",
	},
	{
		id: "PTD-OPA-003", name: "transitive-grant-via-ownership",
		title:  "A position in a hierarchy grants everything below it, and nothing says so",
		closes: "A position is a target rather than a defect: what matters is who can take it.",
	},
	{
		id: "PTD-OPA-004", name: "decision-tainted-by-external-source",
		title:  "A decision depends on an external source, so whoever controls it decides",
		closes: "Whoever controls the endpoint, or can steer where the call goes, decides in the policy's place.",
	},
	{
		id: "PTD-OPA-005", name: "fail-open-on-source-unavailable",
		title:  "A check that needs an external source stops applying when it does not answer",
		closes: "Consuming the error closes it, by denying when the source does not answer.",
	},
	{
		id: "PTD-OPA-006", name: "write-allowed-by-another-decision",
		title:  "One decision lets a principal write the data another decision grants on",
		closes: "The decision that allows the write refusing the value the other one grants on closes it.",
	},
	{
		id: "PTD-OPA-007", name: "every-over-empty-domain",
		title:  "A check written with every stops applying when its domain is empty",
		closes: "Requiring at least one element before the every closes it.",
	},
	{
		id: "PTD-OPA-008", name: "global-document-decides-for-anybody",
		title:  "A document every request shares decides for anybody who asks",
		closes: "Reading the document next to the requester's own record closes it: somebody with no record gets nothing.",
	},
	{
		id: "PTD-OPA-009", name: "self-asserted-exemption",
		title:  "A request lifts a check on itself by saying it is exempt",
		closes: "Taking the exemption from a part of the request the enforcement point sets, as it sets a second factor, closes it.",
	},
	{
		id: "PTD-OPA-010", name: "grant-on-uncontrolled-name",
		title:  "A decision grants on a name somebody else picks",
		closes: "Granting on the id the issuer assigns, which nobody picks and nothing else is ever given, closes it.",
	},
}

// patternLines renders, for a list of pattern ids held under key, one line per
// pattern with its title, a link to its file and what closes it.
func patternLines(key, heading string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "{{ with .Properties.%s }}\n**%s**\n{{ range . }}", key, heading)
	for _, note := range patternNotes {
		fmt.Fprintf(&b, `{{ if eq . "%s" }}
- [%s](%s%s-%s.yaml): %s. %s{{ end }}`, note.id, note.id, registryURL, note.id, note.name, note.title, note.closes)
	}
	b.WriteString("{{ end }}\n{{ end }}")
	return b.String()
}

// confidenceLine says what the level an edge carries means.
//
// The scale is the one internal/opaengine recognizes a request on, and a panel
// that prints the letter and stops leaves the reader to guess whether D is good
// news. The wording follows the levels themselves, so that an edge measured
// from a declaration reads differently from one measured from a guess about
// field names.
func confidenceLine() string {
	levels := []struct{ level, means string }{
		{"A", "the request is declared rather than recognized, by an annotation in the policy or by " +
			"whoever deploys it"},
		{"B", "the request has the shape the AuthZEN Authorization API standardizes"},
		{"C", "a convention of a specific domain recognized it, such as a Kubernetes admission review"},
		{"D", "the names of the fields look like a subject or an action, which is a guess and says so"},
		{"E", "nothing recognized the request, so only the syntactic level of the analysis holds"},
	}

	var b strings.Builder
	b.WriteString("{{ with .Properties.confidence }}**The request was recognized at level {{ . }}** of A to E")
	for _, level := range levels {
		fmt.Fprintf(&b, `{{ if eq . "%s" }}: %s{{ end }}`, level.level, level.means)
	}
	b.WriteString(".{{ end }}")
	return b.String()
}

// patternsFound is the part of a panel that names the patterns reporting on the
// selected entity, findings first.
func patternsFound() string {
	return patternLines(graph.PropPatterns, "Found by") + "\n" +
		patternLines(graph.PropCandidatePatterns, "Candidate of, until a write model settles it")
}

// section is one Entity Panel section.
func section(title string, position int, content ...string) bhgraph.KindInfo {
	return bhgraph.KindInfo{
		Title:    title,
		Position: position,
		Markdown: bhgraph.KindInfoMarkdown{Content: strings.Join(content, "\n\n")},
	}
}

// meaning is the section every kind has: what an entity of that kind stands for.
func meaning(content ...string) map[string]bhgraph.KindInfo {
	return map[string]bhgraph.KindInfo{"meaning": section("What it means", 1, content...)}
}

// withDetails adds the section about the selected entity.
func withDetails(info map[string]bhgraph.KindInfo, content ...string) map[string]bhgraph.KindInfo {
	info["details"] = section("What Petard found", 2, content...)
	return info
}

// nodeInfo is the Entity Panel of each node kind.
func nodeInfo(kind graph.NodeKind) map[string]bhgraph.KindInfo {
	switch kind {
	case graph.NodeKindPrincipal:
		return withDetails(meaning(
			"Anything that can hold privilege in the system around the policy: a user or a team the "+
				"data names, somebody the write model says can write a document, or an external system "+
				"whose answers a decision believes.",
			"`PTD_CanPerform` says what the principal can get out of a decision given the data as it "+
				"stands, and `PTD_CanEscalateTo` whose position it can take by writing something it is "+
				"allowed to write.",
		),
			patternsFound(),
			"{{ with .Properties.positions }}**Positions worth taking**\n{{ range . }}\n- {{ . }}{{ end }}\n{{ end }}",
			// Most principals of a graph carry no mark at all, and a section
			// that renders to nothing leaves a heading with a blank under it.
			"{{ if and (not .Properties.patterns) (not .Properties.candidate_patterns) "+
				"(not .Properties.positions) }}No pattern reports on this principal. What it can "+
				"get out of the decisions is on its `PTD_CanPerform` edges, and whose position it "+
				"can take on `PTD_CanEscalateTo`.{{ end }}",
		)
	case graph.NodeKindAction:
		return meaning("An operation the policy names, such as read or merge. A capability points " +
			"here when the condition that grants it fixes the action and names no resource.")
	case graph.NodeKindResource:
		return meaning("A document a decision can grant, named by the value the residual condition " +
			"fixes for it. Capabilities point here.")
	case graph.NodeKindAttribute:
		return meaning(
			"A field a decision depends on: a document under `data`, which the rules that read it "+
				"point to with `PTD_Reads`, or a value an external source answered with, joined to that "+
				"source by `PTD_TaintedBy`.",
			"Whoever the write model says can write it is at the end of `PTD_WrittenBy`, and that is "+
				"where an escalation aims.",
		)
	case graph.NodeKindRule:
		return withDetails(meaning(
			"A rule of the analyzed policy. Its `PTD_Reads` edges are what it depends on, and "+
				"`is_decision` says whether the enforcement point asks for it directly.",
		),
			"{{ if .Properties.is_decision }}The enforcement point asks for this rule directly.{{ else }}"+
				"A decision reaches this rule through the rules that call it.{{ end }}",
			patternsFound(),
			"{{ with .Properties.empty_domains }}**Collections that pass when empty**\n{{ range . }}\n- `{{ . }}`{{ end }}\n{{ end }}",
		)
	default:
		return nil
	}
}

// edgeInfo is the Entity Panel of each relationship kind.
func edgeInfo(kind graph.EdgeKind) map[string]bhgraph.KindInfo {
	switch kind {
	case graph.EdgeKindCanPerform:
		return withDetails(meaning(
			"The principal can get this out of the decision, given the data as it stands. It is a "+
				"measurement: the same policy against other documents gives other edges.",
		),
			"{{ with .Properties.decision }}**Decision** `{{ . }}`{{ end }}",
			"{{ with .Properties.condition }}**What still has to hold**, as partial evaluation left it:\n\n```\n{{ . }}\n```{{ end }}",
			"{{ with .Properties.action }}**Action** {{ . }}{{ end }}",
			confidenceLine(),
		)
	case graph.EdgeKindReads:
		return withDetails(meaning(
			"The rule depends on this attribute. A dependency, not a capability, which is why "+
				"pathfinding does not walk it: what a finding says about a read is on the edge instead.",
		),
			"{{ with .Properties.ref }}Read as `{{ . }}`{{ end }}{{ with .Properties.source_file }} at `{{ . }}:{{ $.Properties.source_line }}`{{ end }}.",
			"{{ with .Properties.provenance }}The document is chosen by `{{ . }}`.{{ end }}",
			patternsFound(),
			"{{ with .Properties.uncovered_keys }}**Absent for** {{ . }}, out of {{ $.Properties.keys_checked }} documents tried.{{ end }}",
			"{{ with .Properties.mitigation }}**When the source does not answer**, {{ . }}.{{ end }}",
		)
	case graph.EdgeKindWrittenBy:
		return withDetails(meaning(
			"The attribute can be written by this principal. It describes the system around OPA and is "+
				"declared in the write model rather than derived from any policy.",
		),
			"{{ with .Properties.via }}Written through `{{ . }}`{{ end }}{{ with .Properties.via_write_path }}, declared as `{{ . }}`{{ end }}.",
			"{{ with .Properties.write_confidence }}The write model says it was {{ . }}.{{ end }}",
		)
	case graph.EdgeKindCanEscalateTo:
		return withDetails(meaning(
			"The principal can reach the position the other one holds, by writing something it is "+
				"allowed to write. The only edge that means privilege escalation.",
		),
			"**{{ .Source.Properties.name }}** can take the position **{{ .Target.Properties.name }}** holds"+
				"{{ with .Properties.decision }} in `{{ . }}`{{ end }}"+
				"{{ with .Properties.via_write_path }}, by writing `{{ . }}`{{ end }}"+
				"{{ with .Properties.via }} through `{{ . }}`{{ end }}.",
			"{{ with .Properties.value }}The value written is `{{ . }}`{{ with $.Properties.authorized_by }}, which `{{ . }}` allows{{ end }}.{{ end }}",
			"{{ with .Properties.relation }}Through `{{ . }}`: {{ $.Properties.reach_transitive }} ways in with it, {{ $.Properties.reach_direct }} without it.{{ end }}",
			confidenceLine(),
			patternsFound(),
		)
	case graph.EdgeKindTaintedBy:
		return withDetails(meaning(
			"The value comes from this external source rather than from the policy. A dependency, not "+
				"a capability: whoever answers decides what the value is.",
		),
			"{{ with .Properties.provenance_origin }}Answered to a call to `{{ . }}`{{ end }}{{ with .Properties.source_file }} at `{{ . }}:{{ $.Properties.source_line }}`{{ end }}.",
		)
	default:
		return nil
	}
}
