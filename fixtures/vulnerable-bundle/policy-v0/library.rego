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
