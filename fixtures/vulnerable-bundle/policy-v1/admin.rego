# Quill, the decision behind the administration API.
# Holds: PTD-OPA-006, the half of the case that allows a write.
package quill.admin

# METADATA
# scope: document
# title: Role assignment decision
# description: |
#   The entrypoint the PEP of PUT /api/v1/users/{id}/roles consumes. It decides
#   who may write data.users[_].roles, the field the publishing decision reads.
# entrypoint: true
default allow := false

# Administrators assign any role.
allow if {
	input.action == "assign_role"
	"admin" in data.users[input.user].roles
}

# PTD-OPA-006 CASE, first half. Support staff handle the role requests people
# make most often: viewer and editor, for anybody, themselves included. On its
# own this grants the assignment of two roles and nothing else.
allow if {
	input.action == "assign_role"
	"support" in data.users[input.user].roles
	input.role in {"viewer", "editor"}
}
