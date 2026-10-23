package opengraph

import (
	"fmt"
	"strings"

	"github.com/saluc28/bhgraph"

	"github.com/saluc28/petard/internal/graph"
	"github.com/saluc28/petard/internal/pattern"
	registry "github.com/saluc28/petard/taxonomy-registry"
)

// This file holds what BloodHound shows in the Entity Panel for each kind: what
// a node or an edge of that kind means, and what Petard found about the one
// selected. The second half is a Go template BloodHound evaluates against the
// selected entity, with .Properties for a node and .Source, .Target and
// .Properties for a relationship (server/graphdb/internal/services/template.go
// at v9.7.1). It uses the functions text/template has built in and nothing
// else, so that a test can render it the way the server does.

// patternNotes are every pattern's panel metadata, loaded from the registry so
// that a pattern added there appears in the panel without being copied here.
//
// It panics on a registry that does not parse, the way registry.mustSub does:
// the files are embedded and fixed at build time, so a failure is a build bug
// rather than a runtime condition.
var patternNotes = mustNotes()

func mustNotes() []pattern.Note {
	notes, err := pattern.Notes()
	if err != nil {
		panic(err)
	}
	return notes
}

// patternLines renders, for a list of pattern ids held under key, one line per
// pattern with its title, a link to its file and what closes it.
func patternLines(key, heading string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "{{ with .Properties.%s }}\n**%s**\n{{ range . }}", key, heading)
	for _, note := range patternNotes {
		url := registry.URL(note.Engine, note.ID+"-"+note.Name+".yaml")
		fmt.Fprintf(&b, `{{ if eq . "%s" }}
- [%s](%s): %s. %s{{ end }}`, note.ID, note.ID, url, note.Title, note.Closes)
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
			"A field a decision depends on, and what an escalation aims at: the question worth asking "+
				"about it is who can write it, and whoever the write model says can is at the end of "+
				"`PTD_WrittenBy`.",
			"In an OPA graph it is a document under `data`, which the rules that read it reach by "+
				"`PTD_Reads`, or a value an external source answered, joined to that source by "+
				"`PTD_TaintedBy`. In a Zanzibar graph it is a relation on an object, named "+
				"`object#relation`.",
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
			"The principal can reach a position it was not given, by writing something it is allowed "+
				"to write. Against a policy the position is another principal's and the edge ends "+
				"there; against a Zanzibar model it is a permission on an object, and the edge ends at "+
				"the object. The only edge that means privilege escalation.",
		),
			"{{ with .Properties.permission }}**{{ $.Source.Properties.name }}** raises **{{ . }}** on "+
				"**{{ $.Target.Properties.name }}**.{{ else }}"+
				"**{{ .Source.Properties.name }}** can take the position **{{ .Target.Properties.name }}** holds"+
				"{{ with .Properties.decision }} in `{{ . }}`{{ end }}"+
				"{{ with .Properties.via_write_path }}, by writing `{{ . }}`{{ end }}"+
				"{{ with .Properties.via }} through `{{ . }}`{{ end }}.{{ end }}",
			"{{ with .Properties.value }}The value written is `{{ . }}`{{ with $.Properties.authorized_by }}, which `{{ . }}` allows{{ end }}.{{ end }}",
			"{{ with .Properties.relation }}Through `{{ . }}`: {{ $.Properties.reach_transitive }} ways in with it, {{ $.Properties.reach_direct }} without it.{{ end }}",
			"{{ with .Properties.witness_request }}**Proven by** the request `{{ . }}`, which `{{ $.Properties.decision }}` "+
				"refuses today and grants once `{{ $.Properties.witness_document }}` holds `{{ $.Properties.witness_value }}`.{{ end }}",
			"{{ with .Properties.witness_write_request }}`{{ $.Properties.authorized_by }}` allows the write on `{{ . }}`.{{ end }}",
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
