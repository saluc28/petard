# Quill, the decision about publishing documents.
# Holds: PTD-OPA-006, the half of the case that grants, and its counter case.
package quill.publish

# METADATA
# scope: document
# title: Publishing decision
# entrypoint: true
default allow := false

# PTD-OPA-006 CASE, second half. Editors publish, which is what the role is
# for. On its own this is the healthy case.
allow if {
	input.action == "publish"
	"editor" in data.users[input.user].roles
}

# PTD-OPA-006 COUNTER CASE. Withdrawing a document takes an administrator, and
# the role assignment decision does not let support assign admin: the write it
# allows does not reach this branch.
allow if {
	input.action == "withdraw"
	"admin" in data.users[input.user].roles
}
