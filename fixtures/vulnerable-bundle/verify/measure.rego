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

# --- PTD-OPA-006: a write one decision allows, a grant another one makes -----
# carol holds support and not editor. The role assignment decision lets her
# assign editor, to herself too, and not admin.
carol_publishes := {"user": "carol", "action": "publish", "doc": "d-t21-1"}

carol_withdraws := {"user": "carol", "action": "withdraw", "doc": "d-t21-1"}

carol_assigns_editor := {"user": "carol", "action": "assign_role", "target": "carol", "role": "editor"}

carol_assigns_admin := {"user": "carol", "action": "assign_role", "target": "carol", "role": "admin"}

split_grant := {
	"publish_before": publish_before,
	"assign_editor": assign_editor,
	"assign_admin": assign_admin,
	"publish_after": publish_after,
	"withdraw_after": withdraw_after,
} if {
	publish_before := data.quill.publish.allow with input as carol_publishes
	assign_editor := data.quill.admin.allow with input as carol_assigns_editor
	assign_admin := data.quill.admin.allow with input as carol_assigns_admin
	publish_after := data.quill.publish.allow with input as carol_publishes
		with data.users.carol.roles as ["support", "editor"]
	withdraw_after := data.quill.publish.allow with input as carol_withdraws
		with data.users.carol.roles as ["support", "editor"]
}

# --- PTD-OPA-007: a check written with every stops applying on the empty case -
# The unguarded decision approves an empty review list, because `every` over an
# empty collection is true; the guarded one denies it. Same every, same domain:
# only the guard tells them apart.
merge_empty := {"action": "merge", "reviews": []}

merge_rejected := {"action": "merge", "reviews": [{"approved": false}]}

merge_approved := {"action": "merge", "reviews": [{"approved": true}]}

empty_every := {
	"unguarded_empty": unguarded_empty,
	"unguarded_rejected": unguarded_rejected,
	"unguarded_approved": unguarded_approved,
	"guarded_empty": guarded_empty,
	"guarded_approved": guarded_approved,
} if {
	unguarded_empty := data.quill.review.allow_unguarded with input as merge_empty
	unguarded_rejected := data.quill.review.allow_unguarded with input as merge_rejected
	unguarded_approved := data.quill.review.allow_unguarded with input as merge_approved
	guarded_empty := data.quill.review.allow_guarded with input as merge_empty
	guarded_approved := data.quill.review.allow_guarded with input as merge_approved
}

# --- PTD-OPA-008: a document every request shares decides for anybody ---------
# Somebody no document names asks. The reading room decides for them on the
# setting alone; the console gives them nothing whatever its setting says,
# because it wants their record first, and decides for bob, who has one.
stranger_reads := {"user": "petard:nobody", "action": "read"}

stranger_asks := {"user": "petard:nobody", "action": "console"}

bob_asks := {"user": "bob", "action": "console"}

global_switch := {
	"reading_room_as_it_stands": reading_room_now,
	"reading_room_opened": reading_room_opened,
	"console_for_nobody": console_nobody,
	"console_for_nobody_switched_off": console_nobody_off,
	"console_for_bob": console_bob,
	"console_for_bob_switched_off": console_bob_off,
} if {
	reading_room_now := data.quill.platform.allow_reading_room with input as stranger_reads
	reading_room_opened := data.quill.platform.allow_reading_room with input as stranger_reads
		with data.settings.reading_room.open as true
	console_nobody := data.quill.platform.allow_console with input as stranger_asks
	console_nobody_off := data.quill.platform.allow_console with input as stranger_asks
		with data.settings.console.enabled as false
	console_bob := data.quill.platform.allow_console with input as bob_asks
	console_bob_off := data.quill.platform.allow_console with input as bob_asks
		with data.settings.console.enabled as false
}
