# Quill, the decision behind merging a change.
# Holds: PTD-OPA-007 (case and counter case, written out and inside a function).
package quill.review

# METADATA
# scope: document
# title: Merge approval decision
# description: |
#   The entrypoint the PEP of POST /api/v1/changes/{id}/merge consumes. It
#   approves a merge when every reviewer has approved.
# entrypoint: true
default allow_unguarded := false

# PTD-OPA-007 CASE, fail-open on an empty domain.
# Approve when every reviewer approves. With no reviewers the every is
# vacuously true, and the change is merged with nobody having looked. The check
# stops applying exactly when there is nothing to apply it to.
allow_unguarded if {
	input.action == "merge"
	every review in input.reviews {
		review.approved
	}
}

# METADATA
# scope: document
# title: Merge approval decision, guarded against the empty case
# entrypoint: true
default allow_guarded := false

# PTD-OPA-007 COUNTER CASE, the guard.
# Requiring at least one reviewer makes the empty case deny. Same every, same
# domain, only the guard tells them apart, so the engine must not report it.
allow_guarded if {
	input.action == "merge"
	count(input.reviews) > 0
	every review in input.reviews {
		review.approved
	}
}

# METADATA
# scope: document
# title: Release approval decision
# entrypoint: true
default allow_release := false

# PTD-OPA-007 CASE, the every inside a function. all_signed checks every
# signature it is handed, and handed none it holds vacuously: the release goes
# out signed by nobody. The domain is the collection the call hands over.
allow_release if {
	input.action == "release"
	all_signed(input.signatures)
}

# METADATA
# scope: document
# title: Release approval decision, guarded at the call
# entrypoint: true
default allow_release_guarded := false

# PTD-OPA-007 COUNTER CASE, a guard the function does not show. The count sits
# next to the call, so the body of the function holds no guard, and the decision
# asked with no signature refuses.
allow_release_guarded if {
	input.action == "release"
	count(input.signatures) > 0
	all_signed(input.signatures)
}

# Every signature the release carries is valid.
all_signed(signatures) if {
	every signature in signatures {
		signature.valid
	}
}
