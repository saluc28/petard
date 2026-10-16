# The Rego v0 variant of policy-v1/moderation.rego.
package quill.moderation

# METADATA
# scope: document
# title: Comment moderation decision
# entrypoint: true
default verdict = "held"

# The comment is posted once a moderator has reviewed it
verdict = "posted" {
	input.action == "comment"
	input.reviewed == true
}

# A comment on a draft nobody reviewed is quarantined, a refusal the gateway declares
verdict = "quarantined" {
	input.action == "comment"
	input.reviewed == false
	contains(input.doc, "draft")
}
