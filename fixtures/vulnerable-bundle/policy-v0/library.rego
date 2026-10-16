# The Rego v0 variant of policy-v1/library.rego.
package quill.library

import future.keywords.in

# METADATA
# scope: document
# title: Document serving decision
# entrypoint: true
default allow_doc = false

# PTD-OPA-012 CASE, a substring match on the resource
allow_doc {
	contains(input.doc, "public")
}

# PTD-OPA-012 COUNTER CASE, matched by whole path component
allow_doc {
	"public" in split(input.doc, "/")
}

# METADATA
# scope: document
# title: Attachment download decision
# entrypoint: true
default allow_attachment = false

# PTD-OPA-012 CASE, a path canonicalized after the decision
allow_attachment {
	input.action == "download"
	startswith(input.file, "/files/public/")
}

# METADATA
# scope: document
# title: Attachment download decision, refusing dot segments
# entrypoint: true
default allow_attachment_guarded = false

# PTD-OPA-012 COUNTER CASE, the same prefix behind a refusal of dot segments
allow_attachment_guarded {
	input.action == "download"
	not contains(input.file, "..")
	startswith(input.file, "/files/public/")
}

# METADATA
# scope: document
# title: Attachment download decision, by folder
# entrypoint: true
default allow_attachment_by_folder = false

# PTD-OPA-012 CASE, asked from a request given as granted
allow_attachment_by_folder {
	input.action == "download"
	split(input.file, "/")[2] == "public"
}
