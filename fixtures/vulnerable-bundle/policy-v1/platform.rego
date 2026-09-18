# Quill, decisions about the platform as a whole.
# Holds: PTD-OPA-008 (case and counter case).
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
