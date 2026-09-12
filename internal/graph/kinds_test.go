package graph

import "testing"

// The two tests below read as if they restated the constants, and that is the
// point. The kind strings are a contract with data that has already been
// ingested and with saved Cypher queries: a rename is not a refactor, it is a
// migration. Spelling them out a second time makes the cost visible in a
// failing test instead of in a graph nobody can query any more.

func TestNodeKindValues(t *testing.T) {
	values := map[NodeKind]string{
		NodeKindPrincipal: "PTD_Principal",
		NodeKindAction:    "PTD_Action",
		NodeKindResource:  "PTD_Resource",
		NodeKindAttribute: "PTD_Attribute",
		NodeKindRule:      "PTD_Rule",
	}
	for kind, expected := range values {
		if string(kind) != expected {
			t.Errorf("node kind = %q, want %q", kind, expected)
		}
	}
	if len(values) != 5 {
		t.Errorf("declared node kinds = %d, want 5: a new kind needs its own decision, not a silent addition", len(values))
	}
}

func TestNodeKindIsValid(t *testing.T) {
	tests := []struct {
		name     string
		kind     NodeKind
		expected bool
	}{
		{name: "principal", kind: NodeKindPrincipal, expected: true},
		{name: "action", kind: NodeKindAction, expected: true},
		{name: "resource", kind: NodeKindResource, expected: true},
		{name: "attribute", kind: NodeKindAttribute, expected: true},
		{name: "rule", kind: NodeKindRule, expected: true},
		{name: "zero value", kind: "", expected: false},
		{name: "unprefixed", kind: "Principal", expected: false},
		{name: "made up", kind: "PTD_Group", expected: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.kind.IsValid(); got != tt.expected {
				t.Errorf("NodeKind(%q).IsValid() = %t, want %t", tt.kind, got, tt.expected)
			}
		})
	}
}

func TestEdgeKindValues(t *testing.T) {
	values := map[EdgeKind]string{
		EdgeKindCanPerform:    "PTD_CanPerform",
		EdgeKindReads:         "PTD_Reads",
		EdgeKindWrittenBy:     "PTD_WrittenBy",
		EdgeKindCanEscalateTo: "PTD_CanEscalateTo",
		EdgeKindTaintedBy:     "PTD_TaintedBy",
	}
	for kind, expected := range values {
		if string(kind) != expected {
			t.Errorf("edge kind = %q, want %q", kind, expected)
		}
	}
	if len(values) != 5 {
		t.Errorf("declared edge kinds = %d, want 5: a new kind needs its own decision, not a silent addition", len(values))
	}
}

func TestEdgeKindIsValid(t *testing.T) {
	tests := []struct {
		name     string
		kind     EdgeKind
		expected bool
	}{
		{name: "can perform", kind: EdgeKindCanPerform, expected: true},
		{name: "reads", kind: EdgeKindReads, expected: true},
		{name: "written by", kind: EdgeKindWrittenBy, expected: true},
		{name: "can escalate to", kind: EdgeKindCanEscalateTo, expected: true},
		{name: "tainted by", kind: EdgeKindTaintedBy, expected: true},
		{name: "zero value", kind: "", expected: false},
		{name: "node kind used as edge kind", kind: "PTD_Principal", expected: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.kind.IsValid(); got != tt.expected {
				t.Errorf("EdgeKind(%q).IsValid() = %t, want %t", tt.kind, got, tt.expected)
			}
		})
	}
}

// TestEdgeKindIsTraversable holds the traversability column of the data model.
// Getting a value wrong here does not break a build: it invents paths in the
// BloodHound UI, or hides real ones, which is the kind of defect that reaches
// a report.
func TestEdgeKindIsTraversable(t *testing.T) {
	tests := []struct {
		name     string
		kind     EdgeKind
		expected bool
	}{
		{name: "can perform is a capability", kind: EdgeKindCanPerform, expected: true},
		{name: "written by is a capability", kind: EdgeKindWrittenBy, expected: true},
		{name: "can escalate to is a capability", kind: EdgeKindCanEscalateTo, expected: true},
		{name: "reads is a dependency", kind: EdgeKindReads, expected: false},
		{name: "tainted by is a dependency", kind: EdgeKindTaintedBy, expected: false},
		{name: "unknown kind", kind: "PTD_Whatever", expected: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.kind.IsTraversable(); got != tt.expected {
				t.Errorf("EdgeKind(%q).IsTraversable() = %t, want %t", tt.kind, got, tt.expected)
			}
		})
	}
}

func TestPropertyKeys(t *testing.T) {
	keys := map[string]string{
		PropSourceFile:       "source_file",
		PropSourceLine:       "source_line",
		PropSourceRule:       "source_rule",
		PropName:             "name",
		PropIsDecision:       "is_decision",
		PropRef:              "ref",
		PropProvenance:       "provenance",
		PropProvenanceTerm:   "provenance_term",
		PropProvenanceOrigin: "provenance_origin",
		PropUnderNegation:    "under_negation",
	}
	for got, expected := range keys {
		if got != expected {
			t.Errorf("property key = %q, want %q", got, expected)
		}
	}
}
