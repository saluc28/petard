# Quill, the decision that mints a credential for a delegated agent.
# Holds: PTD-OPA-013 (case and counter case).
package quill.delegation

# METADATA
# scope: document
# title: Mint a delegated credential
# entrypoint: true
default allow_mint := false

# PTD-OPA-013 CASE. The agent asks for scopes, and the decision bounds them by
# the agent's own role grant, but never by the scopes the delegating user's edge
# carries. An agent whose role is broad mints scopes the delegator never held.
# The count guards the every, so an empty request is not vacuously granted.
allow_mint if {
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
default allow_mint_narrowed := false

# PTD-OPA-013 COUNTER CASE. The same mint, bounded by the delegating edge as
# well: every requested scope must sit inside the edge the delegator carries, so
# a scope the delegator never held is refused.
allow_mint_narrowed if {
	input.action == "mint"
	count(input.requested_scopes) > 0
	every scope in input.requested_scopes {
		scope in input.delegation_edge.scopes
	}
	every scope in input.requested_scopes {
		scope in input.role_scopes
	}
}
