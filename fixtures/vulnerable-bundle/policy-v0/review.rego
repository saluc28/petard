# The Rego v0 variant of policy-v1/review.rego.
package quill.review

import future.keywords.every
import future.keywords.in

# METADATA
# scope: document
# title: Merge approval decision
# entrypoint: true
default allow_unguarded = false

# PTD-OPA-007 CASE, fail-open on an empty domain
allow_unguarded {
	input.action == "merge"
	every review in input.reviews {
		review.approved
	}
}

# METADATA
# scope: document
# title: Merge approval decision, guarded against the empty case
# entrypoint: true
default allow_guarded = false

# PTD-OPA-007 COUNTER CASE, the guard denies the empty case
allow_guarded {
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
default allow_release = false

# PTD-OPA-007 CASE, the every inside a function
allow_release {
	input.action == "release"
	all_signed(input.signatures)
}

# METADATA
# scope: document
# title: Release approval decision, guarded at the call
# entrypoint: true
default allow_release_guarded = false

# PTD-OPA-007 COUNTER CASE, a guard next to the call
allow_release_guarded {
	input.action == "release"
	count(input.signatures) > 0
	all_signed(input.signatures)
}

all_signed(signatures) {
	every signature in signatures {
		signature.valid
	}
}
