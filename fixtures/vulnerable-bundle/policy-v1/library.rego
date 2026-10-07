# Quill, serving documents by name.
# Holds: PTD-OPA-012 (case and counter case).
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
