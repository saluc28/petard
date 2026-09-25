# The taxonomy

The patterns, the two chains that end in privilege escalation, and what holds a claim up. The
[README](../README.md) lists the ten patterns in one line each, and
[taxonomy-registry/README.md](../taxonomy-registry/README.md) is the format itself.

## The registry is data

Ten patterns live in `taxonomy-registry/`, versioned as data rather than written as code, and
all of them run against the fixture in `internal/taxonomy`. A pattern file carries what the
pattern looks for, the conditions under which it stays quiet, and what it has been held to: the
registry is the source of truth, and the glosses in the README are shorthand for what is
written there.

Each pattern also declares where it leaves its mark in the exported graph, in `graph.marks`, so
that a saved query asking for `PTD-OPA-002` and the code that writes that id cannot disagree
without a test failing.

## The two chains

Two patterns end in the words privilege escalation, and each draws a `PTD_CanEscalateTo` between
two principals.

`PTD-OPA-001` and `PTD-OPA-003` chain into the first. A principal who can write a single field
reaches the position of a principal who reads a whole subtree, and the edge names the document
to write and the endpoint to write it through. On the fixture that is MALLORY reaching DAVE by
writing their own profile department through `PATCH /api/v1/me/profile`.

`PTD-OPA-006` draws the second. One decision lets a principal write a value that another
decision grants on, so the writer reaches the principal who already holds the position. On the
fixture that is CAROL reaching ALICE by writing the role `editor` through
`PUT /api/v1/users/{id}/roles`: `data.quill.admin.allow` allows the write, and
`data.quill.publish.allow` grants the position on the value written.

Neither value is invented. The engine leaves the document unknown and asks OPA what is left of
the decision, so "some value here works" is an answer from the policy rather than a guess about
it. The same partial evaluation is what puts a number on a position: how many ways into the
decision the relation adds, and how many remain without it.

## What holds the claim up

Who can write what is not in the policy. It lives in deployment, in an API, in a pipeline, in
whatever merges a configuration repository, and it has to be declared: that is the write model
in `internal/writemodel`.

Without it every match stays a candidate, and the run reports how many of the paths the
decisions read the model covers, so that a clean result is distinguishable from an empty model.
With it, a match becomes a finding that names a principal, a document and the endpoint the write
goes through.

The write model also carries where each path came from. One a person asserted and one a
connector discovered are both usable and are not the same claim, so the edge keeps the
difference in `write_confidence`.
