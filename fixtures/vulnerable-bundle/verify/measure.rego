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

# --- PTD-OPA-009: a request that says it is exempt -----------------------------
# An export without a second factor is refused, unless the body says it is the
# scheduled export. The policy cannot tell the job from anybody who writes the
# same field; the second factor lifts the same refusal, and the gateway sets it.
export_by_hand := {"user": "mallory", "action": "export", "tenant": "berq", "mfa": false}

export_saying_scheduled := {"user": "mallory", "action": "export", "tenant": "berq", "mfa": false, "scheduled": true}

export_with_mfa := {"user": "mallory", "action": "export", "tenant": "berq", "mfa": true}

self_asserted := {
	"without_a_second_factor": by_hand,
	"saying_it_is_scheduled": saying_scheduled,
	"with_a_second_factor": with_mfa,
} if {
	by_hand := data.quill.tenant_policy.allow_export with input as export_by_hand
	saying_scheduled := data.quill.tenant_policy.allow_export with input as export_saying_scheduled
	with_mfa := data.quill.tenant_policy.allow_export with input as export_with_mfa
}

# --- PTD-OPA-010: a grant on a name somebody else picks ------------------------
# The audit log is open to the group called security. mallory creates a group,
# names it security, and the single sign-on puts the name in her next request.
# The directory gives her group an id of its own, and the id of the real group
# is not one anybody can pick.
audit_log_before := {"user": "mallory", "action": "read_audit_log", "groups": [], "group_ids": []}

audit_log_named := {"user": "mallory", "action": "read_audit_log", "groups": ["security"], "group_ids": ["grp-9001"]}

audit_log_her_id := {"user": "mallory", "action": "read_audit_log", "groups": [], "group_ids": ["grp-9001"]}

audit_log_by_id := {"user": "bob", "action": "read_audit_log", "groups": ["platform"], "group_ids": ["grp-5821"]}

uncontrolled_name := {
	"before_creating_the_group": before,
	"after_naming_it_security": named,
	"the_id_of_her_group": her_id,
	"the_security_group_by_its_id": by_id,
} if {
	before := data.quill.platform.allow_audit_log with input as audit_log_before
	named := data.quill.platform.allow_audit_log with input as audit_log_named
	her_id := data.quill.platform.allow_audit_log with input as audit_log_her_id
	by_id := data.quill.platform.allow_audit_log with input as audit_log_by_id
}

# --- PTD-OPA-011: a grant on an identity somebody can assume --------------------
# The internal sync is authorized by the workload identity of the caller. The
# service account and the agent pinned to a verified credential are read the same
# way and both grant; who can BECOME each identity is not in the policy, it is in
# pep.yaml.
sync_as_service_account := {"action": "sync", "caller": {"spiffe": "spiffe://quill.internal/ns/platform/sa/sync"}}

sync_as_attested_agent := {"action": "sync", "caller": {"attested": "agent:indexer"}}

sync_as_another_workload := {"action": "sync", "caller": {"spiffe": "spiffe://quill.internal/ns/platform/sa/web"}}

assumable_identity := {
	"as_the_sync_service_account": as_service_account,
	"as_the_attested_agent": as_attested_agent,
	"as_another_workload": as_another_workload,
} if {
	as_service_account := data.quill.mesh.allow_sync with input as sync_as_service_account
	as_attested_agent := data.quill.mesh.allow_sync with input as sync_as_attested_agent
	as_another_workload := data.quill.mesh.allow_sync with input as sync_as_another_workload
}

# --- PTD-OPA-012: a value matched more loosely than it is enforced ------------
# The document is served when its id contains the marker "public", a substring.
# An id that merely embeds the marker is served all the same, though it names a
# document that is not public; an id with "public" as a whole component is the
# intended case, and one without it is not served.
doc_embedding := {"doc": "public-incident-q3"}

doc_component := {"doc": "handbook/public/intro"}

doc_private := {"doc": "secret-report"}

loose_match := {
	"embedding_id_served": embedding,
	"public_component_served": component,
	"private_not_served": private,
} if {
	embedding := data.quill.library.allow_doc with input as doc_embedding
	component := data.quill.library.allow_doc with input as doc_component
	private := data.quill.library.allow_doc with input as doc_private
}

# --- PTD-OPA-013: a requested authority not bounded by the delegator ----------
# The agent asks for scopes. The mint bounds them by the agent's own role, which
# is broad, but not by the delegating edge, so a scope within the role and
# outside the edge is minted all the same. The narrowed mint bounds them by the
# edge too, and refuses it.
mint_within_edge := {"action": "mint", "requested_scopes": ["read"], "role_scopes": ["read", "write"], "delegation_edge": {"scopes": ["read"]}}

mint_past_edge := {"action": "mint", "requested_scopes": ["write"], "role_scopes": ["read", "write"], "delegation_edge": {"scopes": ["read"]}}

delegation := {
	"minted_within_the_edge": within,
	"minted_past_the_edge": past,
	"narrowed_refuses_past_the_edge": narrowed,
} if {
	within := data.quill.delegation.allow_mint with input as mint_within_edge
	past := data.quill.delegation.allow_mint with input as mint_past_edge
	narrowed := data.quill.delegation.allow_mint_narrowed with input as mint_past_edge
}

# --- PTD-OPA-007 through a function: the every the release decision calls -----
# A function checks every signature the release carries. Handed none, its every
# is vacuously true and the release goes out signed by nobody; the release
# guarded by a count at the call refuses it.
release_unsigned := {"action": "release", "signatures": []}

release_forged := {"action": "release", "signatures": [{"valid": false}]}

release_signed := {"action": "release", "signatures": [{"valid": true}]}

empty_every_function := {
	"release_unsigned": unsigned,
	"release_forged": forged,
	"release_signed": signed,
	"guarded_unsigned": guarded_unsigned,
	"guarded_signed": guarded_signed,
} if {
	unsigned := data.quill.review.allow_release with input as release_unsigned
	forged := data.quill.review.allow_release with input as release_forged
	signed := data.quill.review.allow_release with input as release_signed
	guarded_unsigned := data.quill.review.allow_release_guarded with input as release_unsigned
	guarded_signed := data.quill.review.allow_release_guarded with input as release_signed
}

# --- PTD-OPA-012, a path canonicalized after the decision ---------------------
# The file store collapses the dot segments of the path after the decision. A
# path that starts in the public folder and climbs out of it is served as it is
# written, and what it resolves to, a private attachment, is refused when asked
# for plainly. The guarded decision refuses the climbing path; the decision by
# folder serves it, since its third component is still "public".
download_public := {"action": "download", "file": "/files/public/handbook.pdf"}

download_climbing := {"action": "download", "file": "/files/public/handbook.pdf/../../private/payroll.pdf"}

download_private := {"action": "download", "file": "/files/private/payroll.pdf"}

canonicalized := {
	"public_served": public,
	"climbing_served": climbing,
	"private_refused": private,
	"guarded_refuses_climbing": guarded_climbing,
	"guarded_serves_public": guarded_public,
	"by_folder_serves_climbing": folder_climbing,
	"by_folder_refuses_private": folder_private,
} if {
	public := data.quill.library.allow_attachment with input as download_public
	climbing := data.quill.library.allow_attachment with input as download_climbing
	private := data.quill.library.allow_attachment with input as download_private
	guarded_climbing := data.quill.library.allow_attachment_guarded with input as download_climbing
	guarded_public := data.quill.library.allow_attachment_guarded with input as download_public
	folder_climbing := data.quill.library.allow_attachment_by_folder with input as download_climbing
	folder_private := data.quill.library.allow_attachment_by_folder with input as download_private
}

# --- PTD-OPA-013 from a request given as granted -------------------------------
# The catalog mint grants only the scopes of its catalog, so the scope a pattern
# makes up is refused whatever the ceilings hold. The request of
# inputs/granted-mint.json is minted, and so is the same request asking for a
# scope within the role and past the edge.
mint_catalog_within := {"action": "mint", "requested_scopes": ["docs:read"], "role_scopes": ["docs:read", "docs:write"], "delegation_edge": {"scopes": ["docs:read"]}}

mint_catalog_past_edge := {"action": "mint", "requested_scopes": ["docs:write"], "role_scopes": ["docs:read", "docs:write"], "delegation_edge": {"scopes": ["docs:read"]}}

mint_made_up_scope := {"action": "mint", "requested_scopes": ["petard-scope"], "role_scopes": ["petard-scope"], "delegation_edge": {"scopes": ["petard-scope"]}}

delegation_catalog := {
	"minted_within_the_edge": within,
	"minted_past_the_edge": past,
	"made_up_scope_refused": made_up,
} if {
	within := data.quill.delegation.allow_mint_catalog with input as mint_catalog_within
	past := data.quill.delegation.allow_mint_catalog with input as mint_catalog_past_edge
	made_up := data.quill.delegation.allow_mint_catalog with input as mint_made_up_scope
}

# --- The declared answer -------------------------------------------------------
# The moderation decision answers one value of three. "posted" is the one the
# gateway acts on; "quarantined", which the substring match on the document
# decides, keeps the comment back as "held" does.
comment_reviewed := {"action": "comment", "reviewed": true, "doc": "d-t11-1"}

comment_on_a_draft := {"action": "comment", "reviewed": false, "doc": "draft-roadmap"}

comment_unreviewed := {"action": "comment", "reviewed": false, "doc": "d-t11-1"}

moderation := {
	"reviewed": reviewed,
	"unreviewed_on_a_draft": on_a_draft,
	"unreviewed": unreviewed,
} if {
	reviewed := data.quill.moderation.verdict with input as comment_reviewed
	on_a_draft := data.quill.moderation.verdict with input as comment_on_a_draft
	unreviewed := data.quill.moderation.verdict with input as comment_unreviewed
}
