# The Rego v0 variant of policy-v1/authz.rego: same semantics, pre-1.0 syntax.
# The v1 parser has to REJECT it and the v0 parser has to accept it, which is
# what gives dual parsing a test from the first day.
package quill.authz

import future.keywords.in

# METADATA
# scope: document
# title: Document access decision
# entrypoint: true
default allow = false

allow {
	input.user == data.documents[input.doc].owner
}

# PTD-OPA-001 CASE
allow {
	input.action == "read"
	data.users[input.user].profile.department == "security"
}

# PTD-OPA-001 COUNTER CASE, roles[] is not written by the subject
allow {
	input.action == "read"
	"admin" in data.users[input.user].roles
}

# PTD-OPA-003 CASE
allow {
	input.action == "read"
	doc := data.documents[input.doc]
	some anc in ancestors_of(doc.project)
	is_member(input.user, anc)
}

is_member(user, proj) {
	user in data.projects[proj].members
}

# THE 001 -> 003 CHAIN
is_member(user, proj) {
	data.users[user].profile.department == data.projects[proj].department
}

# ⚠️ every project needs an entry, the root included, and it gets []:
# graph.reachable only includes nodes that are keys of the graph object.
# See policy-v1/authz.rego.
parent_of[child] = parents {
	some child, project in data.projects
	parents := [p | p := project.parent]
}

ancestors_of(proj) = graph.reachable(parent_of, {proj})
