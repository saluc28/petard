# Quill, the main decision about documents.
# Holds: PTD-OPA-001 (case and counter case), PTD-OPA-003 (case and counter
# case), and the closed chain 001 -> 003.
package quill.authz

# METADATA
# scope: document
# title: Document access decision
# description: |
#   The entrypoint Quill's PEP consumes. It is the decision every rule the
#   patterns report has to lead back to, through compiler.Graph.
# entrypoint: true
default allow := false

# ---------------------------------------------------------------------------
# The healthy route: the owner reads their own document.
# No pattern may report it. It is the background noise of a real policy.
allow if input.user == data.documents[input.doc].owner

# ---------------------------------------------------------------------------
# PTD-OPA-001 CASE, attribute self-write.
# Grants read to whoever says they sit in the security department.
# The subject writes profile.department: see write-model.yaml.
allow if {
	input.action == "read"
	data.users[input.user].profile.department == "security"
}

# PTD-OPA-001 COUNTER CASE, same record, a field the subject does NOT write.
# roles[] is written by an administrator alone. Signal 2 fires (the reference
# is indexed by the subject) and signal 4 does not: no finding.
allow if {
	input.action == "read"
	"admin" in data.users[input.user].roles
}

# ---------------------------------------------------------------------------
# PTD-OPA-003 CASE, transitive grant through the project hierarchy.
# Whoever holds a position in an ancestor of the document's project reads the
# document.
allow if {
	input.action == "read"
	doc := data.documents[input.doc]
	some anc in ancestors_of(doc.project)
	is_member(input.user, anc)
}

# explicit membership
is_member(user, proj) if user in data.projects[proj].members

# THE 001 -> 003 CHAIN.
# Membership is derived from a profile field, and the subject writes that field.
# This is where the two patterns stop being two observations and become a path.
is_member(user, proj) if data.users[user].profile.department == data.projects[proj].department

# The hierarchy as an adjacency list: child -> [parent].
#
# ⚠️ Every project needs an entry, the root included, and the root gets [].
# Checked on 2026-08-03 with opa 1.19.0: graph.reachable puts a node in the
# result ONLY if that node is a key of the graph object. Written the way that
# comes naturally, `p := data.projects[child].parent`, which skips the nodes
# with no parent, the root never shows up among the ancestors and the hierarchy
# climbs one level short of where it should, without raising anything.
parent_of[child] := parents if {
	some child, project in data.projects
	parents := [p | p := project.parent]
}

# Transitive closure through the builtin: Rego does not allow recursion between
# rules.
ancestors_of(proj) := graph.reachable(parent_of, {proj})
