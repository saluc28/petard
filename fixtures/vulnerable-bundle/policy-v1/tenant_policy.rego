# Quill, tenant level checks.
# Holds: PTD-OPA-002 (case and counter case).
package quill.tenant_policy

# METADATA
# scope: document
# title: Tenant level decision
# description: |
#   The PEP consumes this rule. Enforcement lives on the deny side, and saying
#   so is what makes signal 1 of PTD-OPA-002 explicit instead of heuristic, and
#   what lifts the pattern's confidence from B towards A.
# entrypoint: true
default allow := false

# Two sided architecture: the PEP consumes allow, enforcement lives on the deny
# side.
allow if {
	input.action == "read"
	not denied_mfa
	not denied_suspended
}

# PTD-OPA-002 CASE, fail-open on a key the data does not have.
# berq declares policy.require_mfa; dolm has no policy key at all.
# For dolm the body is undefined, the rule produces nothing, and the check does
# not apply. Same policy, smaller domain of application.
denied_mfa if {
	data.tenants[input.tenant].policy.require_mfa == true
	not input.mfa
}

# PTD-OPA-002 COUNTER CASE, the status field is there for EVERY tenant.
# No uncovered key: the engine must not report it.
denied_suspended if {
	data.tenants[input.tenant].status == "suspended"
}
