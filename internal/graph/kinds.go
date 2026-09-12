package graph

import "slices"

// NodeKind is the type of a node, spelled the way BloodHound will read it.
//
// The PTD_ prefix is the namespace convention SpecterOps collectors follow.
// These strings travel further than the analysis does: they land in ingested
// data and in saved Cypher queries, so renaming one means re-ingesting every
// graph and rewriting every query that mentions it.
type NodeKind string

const (
	// NodeKindPrincipal is anything that can hold privilege: a user, a role, a
	// service account, or an external system that decides on their behalf.
	NodeKindPrincipal NodeKind = "PTD_Principal"

	// NodeKindAction is an operation a principal may be allowed to perform.
	NodeKindAction NodeKind = "PTD_Action"

	// NodeKindResource is what an action is performed on.
	NodeKindResource NodeKind = "PTD_Resource"

	// NodeKindAttribute is a field of data or input that a decision depends on.
	// It gets a node of its own because it is what an escalation aims at: the
	// interesting question about an attribute is who can write it.
	NodeKindAttribute NodeKind = "PTD_Attribute"

	// NodeKindRule is a rule of the analyzed policy.
	//
	// The data model calls for it without naming it: Reads goes from a rule to
	// an attribute, and there was no kind to hang the near end on. Whether a
	// rule is a decision the PEP asks for is a property of the node, not a
	// kind of its own: it is the same object either way, and a policy where
	// today's helper becomes tomorrow's entrypoint should not change shape in
	// the graph.
	NodeKindRule NodeKind = "PTD_Rule"
)

// NodeKinds returns every node kind the model declares, in the order the design
// lists them.
//
// It exists so that the exporter can walk the kinds instead of repeating them:
// a schema that declares four of five kinds produces nodes BloodHound cannot
// classify, and the mistake would only show in the UI.
func NodeKinds() []NodeKind {
	return []NodeKind{
		NodeKindPrincipal,
		NodeKindAction,
		NodeKindResource,
		NodeKindAttribute,
		NodeKindRule,
	}
}

// IsValid reports whether k is one of the declared node kinds.
//
// The zero value is not valid. A kind that reached the export empty would
// produce a node BloodHound cannot classify, and it would look like data
// rather than like the mistake it is.
func (k NodeKind) IsValid() bool {
	return slices.Contains(NodeKinds(), k)
}

// EdgeKind is the type of an edge. The same warning as NodeKind applies: these
// strings are a contract with data that has already been ingested.
type EdgeKind string

const (
	// EdgeKindCanPerform links a principal to what it may do. Its properties
	// carry the residual condition left by partial evaluation, which is what
	// turns "may do" into "may do, under this condition".
	EdgeKindCanPerform EdgeKind = "PTD_CanPerform"

	// EdgeKindReads links a rule or a principal to an attribute a decision
	// depends on. It is a dependency, not a capability.
	EdgeKindReads EdgeKind = "PTD_Reads"

	// EdgeKindWrittenBy links an attribute to whoever can write it. It is the
	// one edge no policy analysis can derive: it describes the system around
	// OPA and is declared by hand or by a connector.
	EdgeKindWrittenBy EdgeKind = "PTD_WrittenBy"

	// EdgeKindCanEscalateTo links a principal to a position it can reach that
	// it was not given. It is the only edge that represents real privilege
	// escalation, and it exists only where a write path meets a decision.
	EdgeKindCanEscalateTo EdgeKind = "PTD_CanEscalateTo"

	// EdgeKindTaintedBy links an attribute to the external origin its value
	// comes from, an http.send response for instance.
	EdgeKindTaintedBy EdgeKind = "PTD_TaintedBy"
)

// EdgeKinds returns every edge kind the model declares.
func EdgeKinds() []EdgeKind {
	return []EdgeKind{
		EdgeKindCanPerform,
		EdgeKindReads,
		EdgeKindWrittenBy,
		EdgeKindCanEscalateTo,
		EdgeKindTaintedBy,
	}
}

// IsValid reports whether k is one of the declared edge kinds. As for
// NodeKind, the zero value is not.
func (k EdgeKind) IsValid() bool {
	return slices.Contains(EdgeKinds(), k)
}

// IsTraversable reports whether BloodHound's pathfinding may walk this edge.
// It is the value that ends up in is_traversable in the extension schema, and
// it is kept here so that the schema and the model cannot drift apart.
//
// The choice is semantic, not cosmetic. Pathfinding walks whatever it is told
// it may walk, so marking an edge traversable when it does not represent a
// capability invents paths in the UI that nobody can take.
func (k EdgeKind) IsTraversable() bool {
	switch k {
	case EdgeKindCanPerform, EdgeKindWrittenBy, EdgeKindCanEscalateTo:
		return true
	default:
		// Reads and TaintedBy are dependency relations, not capabilities, and
		// an unknown kind is not traversable either.
		return false
	}
}

// Property keys. They are fixed here, once, because they are part of the
// ingested payload: adding one later means re-ingesting every graph already
// uploaded.
const (
	// Provenance of an edge derived from Rego: where to look in the sources.
	PropSourceFile = "source_file"
	PropSourceLine = "source_line"
	PropSourceRule = "source_rule"

	// PropName is what the node is called, and PropIsDecision marks the rules
	// the PEP asks for.
	PropName       = "name"
	PropIsDecision = "is_decision"

	// PropRef is a read as it stands in the rule, keeping the index:
	// data.users[input.user].profile.department.
	PropRef = "ref"

	// PropProvenance says who chooses the document a read lands on;
	// PropProvenanceTerm names it where the rule itself cannot, because the
	// index is a parameter and the answer is at the call site; and
	// PropProvenanceOrigin names the external source, when there is one.
	PropProvenance       = "provenance"
	PropProvenanceTerm   = "provenance_term"
	PropProvenanceOrigin = "provenance_origin"

	// PropUnderNegation marks a read that happens inside a negation: a value
	// read to deny is not a value read to grant.
	PropUnderNegation = "under_negation"

	// PropConfidence is the level the shape of the request was recognized at,
	// on the A to E scale of the design, and it travels on everything whose
	// claim rests on that recognition. Section 6.8 makes it non negotiable: an
	// edge derived from a guess about field names must not be indistinguishable
	// from one derived from a declaration.
	PropConfidence = "confidence"

	// PropDecision is the decision an edge was measured against. A capability
	// and an escalation are both answers to "out of which decision", and the
	// same principal can have very different ones out of two.
	PropDecision = "decision"

	// PropCondition is what still has to hold for a capability to apply, as the
	// residual condition partial evaluation left, written as Rego so that it can
	// be pasted back into a query.
	PropCondition = "condition"

	// PropAction is the action a capability is qualified by, kept as a property
	// where the edge already points at the resource. An edge can only have one
	// far end, and between the two the resource is the one worth walking to.
	PropAction = "action"

	// PropVia is how something is done to the world outside OPA: the endpoint,
	// the form or the job through which a write happens. A finding without the
	// how is not something anybody can act on.
	PropVia = "via"

	// PropViaWritePath is the entry of the write model that turned a candidate
	// into a finding, so that a claim about escalation names the declaration it
	// rests on rather than asking to be trusted.
	PropViaWritePath = "via_write_path"

	// PropWriteConfidence is whether a write path was asserted by a person or
	// discovered by a connector.
	//
	// It is a different scale from PropConfidence and the two must not be read
	// together: that one grades how well the tool recognized the request, this
	// one grades where the claim about the world around OPA came from.
	PropWriteConfidence = "write_confidence"

	// PropUncoveredKeys are the documents of a collection where a path a check
	// depends on is absent, and PropKeysChecked how many were tried. Together
	// they are the difference between a check that does not apply here and one
	// that does not apply anywhere.
	PropUncoveredKeys = "uncovered_keys"
	PropKeysChecked   = "keys_checked"

	// PropEnforcingSide says how the side that applies a check was established.
	// The claim rests on it, and when it stops being a declaration the
	// confidence has to follow.
	PropEnforcingSide = "enforcing_side"

	// PropReachTransitive and PropReachDirect are how much a decision grants a
	// principal with a relation in place and with it cut, and PropRelation is
	// what was cut. The pair is a measurement rather than a structure, and
	// neither number means anything without the other.
	PropReachTransitive = "reach_transitive"
	PropReachDirect     = "reach_direct"
	PropRelation        = "relation"
)
