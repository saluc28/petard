# The engine

How Petard reads a bundle, what it reports, and how each claim is checked. The
[README](../README.md) has the short version.

## The model

The model lives in `internal/graph`. The kind names and the property keys are a contract before
they are code: they end up in ingested data and in saved Cypher queries, so renaming one means
re-ingesting every graph and rewriting every query that mentions it. Getting them right is cheap
now and expensive in a month.

Nothing from OPA's AST crosses this package boundary. Residual conditions enter as strings that
are already serialized, which is the constraint that lets a second policy engine reuse the model
instead of forcing a rewrite of it, and it is cheap to keep only as long as nobody breaks it
once.

Whether an edge takes part in BloodHound's pathfinding is decided here, by `IsTraversable`, and
not in the export. Marking an edge traversable when it does not represent a capability invents
paths in the interface that nobody can walk, so it is a semantic decision rather than a cosmetic
one, and it lives next to the kinds so the schema and the model cannot drift apart.

## Reading a bundle

`internal/opaengine` loads a bundle in either Rego syntax, v1 or v0, and records which one it
read. A tool that analyzes somebody else's policies does not get to pick the syntax: every one
of the 51 bundles in the `open-policy-agent/gatekeeper-library` corpus parses as v0 and none of
them as v1, while all 28 in `open-policy-agent/contrib` parse as v1. A bundle that is half of
each loads as neither, with an error naming every file involved.

Its starting points are the decisions: the rules the policy annotates as entrypoints, plus any
the caller declares. Whole families of Rego annotate nothing, and that same corpus has no
`# METADATA` block at all across its 142 files. The alternative to declaring the decision is
guessing which rule a policy engine happens to query, so Petard stops instead of guessing.

A declared decision can also be the document that rules with a reference in their head build
together, such as `authzen/allow` for rules written `allow["decision"]`, or one field of what a
rule returns. A rule that answers `{"allowed": ..., "violations": [...]}` is defined whatever it
says, and AWX reads `allowed` out of it, so the decision to declare there is
`aac/aap/policy/owner_scope/allowed`. A decision can also be declared to deny, for an
enforcement point that refuses the request as soon as the decision holds or collects anything,
the way Gatekeeper reads `violation`: which side a read is on is then counted from the refusal
(`taxonomy-registry/README.md` section 3).

## What the analysis reports

From the decisions it walks the rules they depend on, following calls into functions and leaving
alone the expressions that mock the world with a `with` modifier, and reports:

- every place a decision reads `data`, with the normalized path, the reference as the author
  wrote it, the file and the line, and whether the read sits under a negation
- who chooses the document each read lands on: the caller, other data, a builtin, or nobody
  the analysis can name
- the values a decision depends on that the policy did not compute, such as the body of an
  HTTP response, and which decisions each of them reaches
- the shape of the request, with the level of confidence it was recognized at, which runs from
  a declaration down to a guess about field names and travels with the answer. Which field names
  the requester is decided where the request is built, so it can be declared too

Given concrete data it also evaluates every decision partially, and reports what is left of each
one once the documents are known. It is also how a position in a hierarchy gets a number: by
asking OPA what the decision still depends on, instead of walking the relation ourselves and
getting an answer the policy would not agree with.

Analyzing a policy never calls the endpoints written in it. A call to `http.send` stays inside
the residual condition, where it says something true: that the decision cannot be settled from
the data alone.

## How the claims are checked

Two fixtures, because they carry two different risks.

`fixtures/vulnerable-bundle/` is a policy with escalation built into it on purpose, written by
hand in both Rego syntaxes, next to an `EXPECTED.md` that declares in words what an analysis has
to find and what it has to stay quiet about. Every pattern gets a case and a counter case there.

It lints clean under `regal`, and that is deliberate. The claim the project makes is that the
code is correct and idiomatic and the defect is somewhere else: in the data somebody can write,
in the key that is missing, in the source that does not answer.

`internal/fixture` generates worlds from a seed and states the truth about each one, which is
what turns "did it find the planted escalation" into a measurement of precision as well as
recall. A pattern that finds everything and invents half of it is unusable in an assessment, and
only generated ground truth makes that visible.

The engine also runs over bodies of Rego written by other people, which do not live in this
repository:

```
go run ./cmd/measure-corpus /path/to/corpus/src
```

## The export

`internal/opengraph` turns the model into a BloodHound OpenGraph payload, over
[bhgraph](https://github.com/saluc28/bhgraph), and `schema/petard.json` is the extension
definition schema that tells BloodHound which of the edges its pathfinding may walk, what each
kind means, and what to show in the Entity Panel. The schema is generated from the model and
checked by a golden test, so the two cannot disagree.

`export-opengraph` refuses to run when the `opengraph_extension_management` feature flag is off.
With it off, pathfinding answers from the built-in AD and Azure kinds alone and says "path not
found" whether or not the path is there, so `-verify` would report a confident no for the wrong
reason.

`-install` saves the schema and the queries, and never deletes anything. BloodHound keys a saved
query by its name, so a query renamed between two versions of Petard arrives as a second query
and the old one stays: `-prune-queries` removes the ones this build no longer has, naming each
as it goes.
