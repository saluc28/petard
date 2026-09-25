# The Rego v0 variant of policy-v1/platform.rego.
package quill.platform

import future.keywords.in

# METADATA
# scope: document
# title: Reading room decision
# entrypoint: true
default allow_reading_room = false

# PTD-OPA-008 CASE, a document every request shares
allow_reading_room {
	input.action == "read"
	data.settings.reading_room.open == true
}

# METADATA
# scope: document
# title: Administration console decision
# entrypoint: true
default allow_console = false

# PTD-OPA-008 COUNTER CASE, the same kind of setting read next to the record
allow_console {
	"admin" in data.users[input.user].roles
	data.settings.console.enabled == true
}

# METADATA
# scope: document
# title: Audit log decision
# entrypoint: true
default allow_audit_log = false

# PTD-OPA-010 CASE, the group by the name somebody picked
allow_audit_log {
	input.action == "read_audit_log"
	"security" in input.groups
}

# PTD-OPA-010 COUNTER CASE, the group by the id the directory assigned
allow_audit_log {
	input.action == "read_audit_log"
	"grp-5821" in input.group_ids
}
