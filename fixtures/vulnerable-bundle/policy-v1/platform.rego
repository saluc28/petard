# Quill, decisions about the platform as a whole.
# Holds: PTD-OPA-008 (case and counter case), PTD-OPA-010 (case and counter
# case).
package quill.platform

# METADATA
# scope: document
# title: Reading room decision
# entrypoint: true
default allow_reading_room := false

# PTD-OPA-008 CASE. The reading room is open to whoever asks while the platform
# says it is. One document every request shares decides for everybody at once,
# requesters the data has never heard of included.
allow_reading_room if {
	input.action == "read"
	data.settings.reading_room.open == true
}

# METADATA
# scope: document
# title: Administration console decision
# entrypoint: true
default allow_console := false

# PTD-OPA-008 COUNTER CASE. Just as global a setting, but read next to the
# requester's own record: somebody with no record gets nothing whatever it says,
# so it switches the console for the administrators and not for anybody.
allow_console if {
	"admin" in data.users[input.user].roles
	data.settings.console.enabled == true
}

# METADATA
# scope: document
# title: Audit log decision
# entrypoint: true
default allow_audit_log := false

# PTD-OPA-010 CASE. The audit log is open to the group called security. The
# single sign-on puts the names of the user's groups in the request, and any
# account of Quill can create a group and name it: the single sign-on hands the
# new name over like any other.
allow_audit_log if {
	input.action == "read_audit_log"
	"security" in input.groups
}

# PTD-OPA-010 COUNTER CASE. The same group, by the id the directory assigned it,
# which nobody picks and nothing else is ever given.
allow_audit_log if {
	input.action == "read_audit_log"
	"grp-5821" in input.group_ids
}
