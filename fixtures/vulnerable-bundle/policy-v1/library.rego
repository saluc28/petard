# Quill, serving documents by name and attachments by path.
# Holds: PTD-OPA-012 (case and counter case, on a match and on a path
# canonicalized after the decision).
package quill.library

# METADATA
# scope: document
# title: Document serving decision
# entrypoint: true
default allow_doc := false

# PTD-OPA-012 CASE. A document is served when its id contains the marker
# "public", a substring. A private document whose id merely embeds it,
# "public-incident-q3", is served all the same, because the match is wider than
# the id it names.
allow_doc if {
	contains(input.doc, "public")
}

# PTD-OPA-012 COUNTER CASE. The same intent by whole path component, the fix
# defenseclaw made: a document with "public" as a component matches, and one that
# merely embeds it does not.
allow_doc if {
	"public" in split(input.doc, "/")
}

# METADATA
# scope: document
# title: Attachment download decision
# entrypoint: true
default allow_attachment := false

# PTD-OPA-012 CASE, a path canonicalized after the decision. Attachments under
# the public folder are served to anybody. The gateway hands the path to the
# file store, which collapses dot segments after the decision: a path that
# starts in the public folder and climbs out of it reaches a private attachment.
allow_attachment if {
	input.action == "download"
	startswith(input.file, "/files/public/")
}

# METADATA
# scope: document
# title: Attachment download decision, refusing dot segments
# entrypoint: true
default allow_attachment_guarded := false

# PTD-OPA-012 COUNTER CASE. The same prefix, behind a refusal of any dot
# segment, so no path that climbs out of the folder is granted.
allow_attachment_guarded if {
	input.action == "download"
	not contains(input.file, "..")
	startswith(input.file, "/files/public/")
}

# METADATA
# scope: document
# title: Attachment download decision, by folder
# entrypoint: true
default allow_attachment_by_folder := false

# PTD-OPA-012 CASE, asked from a request given as granted. The folder is read as
# the component at a fixed place, which a path climbing out of it satisfies
# too. Partial evaluation leaves no condition to build a granted request from,
# so the decision is asked from inputs/granted-download.json.
allow_attachment_by_folder if {
	input.action == "download"
	split(input.file, "/")[2] == "public"
}
