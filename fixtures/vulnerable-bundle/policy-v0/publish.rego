# The Rego v0 variant of policy-v1/publish.rego.
package quill.publish

import future.keywords.in

# METADATA
# scope: document
# title: Publishing decision
# entrypoint: true
default allow = false

# PTD-OPA-006 CASE, second half
allow {
	input.action == "publish"
	"editor" in data.users[input.user].roles
}

# PTD-OPA-006 COUNTER CASE, admin is not a role support can assign
allow {
	input.action == "withdraw"
	"admin" in data.users[input.user].roles
}
