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
