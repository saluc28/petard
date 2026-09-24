# The Rego v0 variant of policy-v1/tenant_policy.rego.
package quill.tenant_policy

# METADATA
# scope: document
# title: Tenant level decision
# entrypoint: true
default allow = false

allow {
	input.action == "read"
	not denied_mfa
	not denied_suspended
}

# PTD-OPA-002 CASE, fail-open on a missing key
denied_mfa {
	data.tenants[input.tenant].policy.require_mfa == true
	not input.mfa
}

# PTD-OPA-002 COUNTER CASE, status is there for every tenant
denied_suspended {
	data.tenants[input.tenant].status == "suspended"
}

# METADATA
# scope: document
# title: Tenant export decision
# entrypoint: true
default allow_export = false

allow_export {
	input.action == "export"
	not export_needs_mfa
}

# PTD-OPA-009 CASE (input.scheduled, set by the caller) and COUNTER CASE
# (input.mfa, set by the gateway from the session)
export_needs_mfa {
	not input.mfa
	not input.scheduled
}
