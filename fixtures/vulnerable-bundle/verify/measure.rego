# NOT part of the policy bundle: this is the fixture's measuring instrument.
# It produces the numbers EXPECTED.md declares, so that anybody can regenerate
# them instead of taking them on trust.
# Load it explicitly in addition to policy-v1/, never in its place.
#
# Everything is exposed as a rule without arguments: on Windows, PowerShell
# quoting breaks opa eval queries passed as an argument, so the strings live
# here.
package quill.verify

import data.quill.authz

# documents a user reaches TRANSITIVELY (membership in an ancestor)
reachable_by(user) := {doc_id |
	d := data.documents[doc_id]
	some anc in authz.ancestors_of(d.project)
	authz.is_member(user, anc)
}

# documents reached DIRECTLY (membership in the document's own project)
direct_by(user) := {doc_id |
	d := data.documents[doc_id]
	authz.is_member(user, d.project)
}

# --- PTD-OPA-003: what each position is worth --------------------------------
reach[user] := {
	"direct": count(direct_by(user)),
	"transitive": count(reachable_by(user)),
} if {
	some user
	data.users[user]
}

# --- THE 001 -> 003 CHAIN ----------------------------------------------------
# Same dataset, one single difference: the field the subject can write.
chain_before := count(reachable_by("mallory"))

chain_after := n if {
	n := count(reachable_by("mallory")) with data.users.mallory.profile.department as "platform"
}

# --- PTD-OPA-001: the decision before and after the field is written ---------
# The same writable field opens TWO different routes, depending on the value.
mallory_asks := {"user": "mallory", "action": "read", "doc": "d-t11-1"}

# value "security": a direct grant (PTD-OPA-001 on its own)
selfwrite_before := r if {
	r := authz.allow with input as mallory_asks
}

selfwrite_after := r if {
	r := authz.allow with input as mallory_asks
		with data.users.mallory.profile.department as "security"
}

# value "platform": membership on the root, and from there the whole subtree
# (001 -> 003)
chain_decision_after := r if {
	r := authz.allow with input as mallory_asks
		with data.users.mallory.profile.department as "platform"
}

# --- PTD-OPA-002: coverage of the data paths ---------------------------------
tenant_keys := {k | data.tenants[k]}

mfa_covered := {k | data.tenants[k].policy.require_mfa}

status_covered := {k | data.tenants[k].status}

coverage := {
	"tenant_keys": count(tenant_keys),
	"mfa_covered": count(mfa_covered),
	"mfa_uncovered": tenant_keys - mfa_covered,
	"status_covered": count(status_covered),
	"status_uncovered": tenant_keys - status_covered,
}
