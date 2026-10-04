# The Rego v0 variant of policy-v1/mesh.rego.
package quill.mesh

# METADATA
# scope: document
# title: Internal sync decision
# entrypoint: true
default allow_sync = false

# PTD-OPA-011 CASE, a grant on an identity somebody can assume
allow_sync {
	input.action == "sync"
	input.caller.spiffe == "spiffe://quill.internal/ns/platform/sa/sync"
}

# PTD-OPA-011 COUNTER CASE, an identity the mesh pins to a verified credential
allow_sync {
	input.action == "sync"
	input.caller.attested == "agent:indexer"
}
