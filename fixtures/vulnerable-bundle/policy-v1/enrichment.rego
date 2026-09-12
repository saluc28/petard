# Quill, decision enrichment from an external source.
# Holds: PTD-OPA-004 (case and counter case).
#
# The hosts named here sit under the .invalid TLD, reserved by RFC 2606, so
# they never resolve. The fixture is reproducible without a network and without
# mocks. For PTD-OPA-004 the runtime outcome is irrelevant anyway: the finding
# is static.
package quill.enrichment

# METADATA
# scope: document
# title: Decision enriched from an external source
# entrypoint: true
default allow := false

# PTD-OPA-004 CASE, the decision depends on the CONTENT of an external source.
# Whoever controls idp.petard-fixture.invalid decides in place of the policy.
allow if {
	input.action == "read"
	enrichment := http.send({
		"method": "GET",
		"url": "https://idp.petard-fixture.invalid/attrs",
		"raise_error": false,
	})
	enrichment.body.clearance == "high"
}

# PTD-OPA-004 COUNTER CASE, same builtin, a result that reaches NO decision:
# this is a telemetry document, not a branch of allow.
# Signal 1 fires (there is an http.send) and signal 2 does not: no taint
# towards a decision, no finding. It is the counter case that tells the taint
# apart from the mere presence of the builtin.
audit_trace := trace_id if {
	response := http.send({
		"method": "GET",
		"url": "https://telemetry.petard-fixture.invalid/trace",
		"raise_error": false,
	})
	trace_id := response.body.trace_id
}
