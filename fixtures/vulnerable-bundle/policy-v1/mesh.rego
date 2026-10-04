# Quill, decisions in front of the service mesh.
# Holds: PTD-OPA-011 (case and counter case).
package quill.mesh

# METADATA
# scope: document
# title: Internal sync decision
# entrypoint: true
default allow_sync := false

# PTD-OPA-011 CASE. The internal sync is authorized by the workload identity of
# the caller, the service account the mesh proves from its mTLS certificate.
# Whoever can deploy a workload under that service account becomes it, and who
# can deploy into the namespace is a fact the policy cannot see.
allow_sync if {
	input.action == "sync"
	input.caller.spiffe == "spiffe://quill.internal/ns/platform/sa/sync"
}

# PTD-OPA-011 COUNTER CASE. The same shape on an identity the mesh pins to a
# verified credential, which nobody can assume without holding the credential.
allow_sync if {
	input.action == "sync"
	input.caller.attested == "agent:indexer"
}
