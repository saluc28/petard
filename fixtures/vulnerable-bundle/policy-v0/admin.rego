# The Rego v0 variant of policy-v1/admin.rego.
package quill.admin

import future.keywords.in

# METADATA
# scope: document
# title: Role assignment decision
# entrypoint: true
default allow = false

allow {
	input.action == "assign_role"
	"admin" in data.users[input.user].roles
}

# PTD-OPA-006 CASE, first half
allow {
	input.action == "assign_role"
	"support" in data.users[input.user].roles
	input.role in {"viewer", "editor"}
}
