# The Rego v0 variant of policy-v1/delegation.rego.
package quill.delegation

import future.keywords.every
import future.keywords.in

# METADATA
# scope: document
# title: Mint a delegated credential
# entrypoint: true
default allow_mint = false

# PTD-OPA-013 CASE, a requested authority bounded by the agent's own role but
# not by the delegating edge
allow_mint {
	input.action == "mint"
	count(input.requested_scopes) > 0
	every scope in input.requested_scopes {
		scope in input.role_scopes
	}
}

# METADATA
# scope: document
# title: Mint a delegated credential, narrowed to the edge
# entrypoint: true
default allow_mint_narrowed = false

# PTD-OPA-013 COUNTER CASE, bounded by the delegating edge as well
allow_mint_narrowed {
	input.action == "mint"
	count(input.requested_scopes) > 0
	every scope in input.requested_scopes {
		scope in input.delegation_edge.scopes
	}
	every scope in input.requested_scopes {
		scope in input.role_scopes
	}
}
