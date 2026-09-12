# The Rego v0 variant of policy-v1/enrichment.rego.
package quill.enrichment

# METADATA
# scope: document
# title: Decision enriched from an external source
# entrypoint: true
default allow = false

# PTD-OPA-004 CASE, the decision depends on the CONTENT of an external source
allow {
	input.action == "read"
	enrichment := http.send({
		"method": "GET",
		"url": "https://idp.petard-fixture.invalid/attrs",
		"raise_error": false,
	})
	enrichment.body.clearance == "high"
}

# PTD-OPA-004 COUNTER CASE, a result that reaches no decision
audit_trace = trace_id {
	response := http.send({
		"method": "GET",
		"url": "https://telemetry.petard-fixture.invalid/trace",
		"raise_error": false,
	})
	trace_id := response.body.trace_id
}
