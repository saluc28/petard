# Quill, the decision on a comment before it is posted.
# Holds: an answer the gateway declares a refusal (section 4, row 19).
package quill.moderation

# METADATA
# scope: document
# title: Comment moderation decision
# entrypoint: true
default verdict := "held"

# The comment is posted once a moderator has reviewed it.
verdict := "posted" if {
	input.action == "comment"
	input.reviewed == true
}

# A comment on a draft nobody reviewed is quarantined, which the gateway treats
# as it treats "held": the comment is not posted. Nothing in the policy says so.
# Read without the declaration, every answer other than the default grants,
# and this substring match would read as a grant on a loose match.
verdict := "quarantined" if {
	input.action == "comment"
	input.reviewed == false
	contains(input.doc, "draft")
}
