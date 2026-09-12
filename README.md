# Petard

Attack-path analysis for policy-as-code. Petard reads Rego (OPA) policies, works out what
their decisions depend on, and applies a curated taxonomy of privilege-escalation patterns to
what it finds. The result is meant to leave the tool as a structured BloodHound OpenGraph.

The parser is not the point. The taxonomy is: the catalogue of ways a policy and the data it
reads can be turned against the system they protect, and above all the ones that cross the
line between whoever takes a decision and whoever writes the data that decision is taken on.
A linter sees one file. Petard is built to see the policy, the data and who can write it,
together.

## The graph model

The model lives in `internal/graph`, and it comes before the things that fill it because of what
it costs to change later: the kind names and the property keys end up in ingested data and in
saved Cypher queries, so renaming one means re-ingesting every graph and rewriting every query
that mentions it. Getting them right is cheap now and expensive in a month.

Two things about it are worth knowing.

Nothing from OPA's AST crosses this package boundary. Residual conditions enter as strings that
are already serialized, which is the constraint that lets a second policy engine reuse the model
instead of forcing a rewrite of it, and it is cheap to keep only as long as nobody breaks it
once.

Whether an edge takes part in BloodHound's pathfinding is decided here, by `IsTraversable`, and
not in the export. Marking an edge traversable when it does not represent a capability invents
paths in the interface that nobody can walk, so it is a semantic decision rather than a cosmetic
one, and it lives next to the kinds so the schema and the model cannot drift apart.

## What the engine does

`internal/opaengine` loads a bundle in either Rego syntax, v1 or v0, and records which one it
read. A tool that analyzes somebody else's policies does not get to pick the syntax, and a
bundle that is half of each loads as neither, with an error naming every file involved.

Its starting points are the decisions: the rules the policy annotates as entrypoints, plus any
the caller declares. Whole families of Rego annotate nothing, and the alternative to declaring
the decision is guessing which rule a policy engine happens to query, so Petard stops instead
of guessing.

From the decisions it walks the rules they depend on, following calls into functions and
leaving alone the expressions that mock the world with a `with` modifier, and reports:

- every place a decision reads `data`, with the normalized path, the reference as the author
  wrote it, the file and the line, and whether the read sits under a negation
- who chooses the document each read lands on: the caller, other data, a builtin, or nobody
  the analysis can name
- the values a decision depends on that the policy did not compute, such as the body of an
  HTTP response, and which decisions each of them reaches
- the shape of the request, with the level of confidence it was recognized at, which runs from
  a declared standard down to a guess about field names and travels with the answer

Given concrete data it also evaluates every decision partially, and reports what is left of
each one once the documents are known. It is also how a position in a hierarchy gets a number:
by asking OPA what the decision still depends on, instead of walking the relation ourselves and
getting an answer the policy would not agree with.

Analyzing a policy never calls the endpoints written in it. A call to `http.send` stays inside
the residual condition, where it says something true: that the decision cannot be settled from
the data alone.

## The fixture

`fixtures/vulnerable-bundle/` is a policy with escalation built into it on purpose, written by
hand in both Rego syntaxes, next to an `EXPECTED.md` that declares in words what an analysis
has to find and what it has to stay quiet about. Every pattern gets a case and a counter case,
because a tool that finds everything and invents half of it is unusable in an assessment.

It lints clean under `regal`, and that is deliberate. The claim the project makes is that the
code is correct and idiomatic and the defect is somewhere else: in the data somebody can write,
in the key that is missing, in the source that does not answer.

## The taxonomy

Five patterns live in `taxonomy-registry/`, which is versioned data rather than code, and are
implemented against the fixture in `internal/taxonomy`. The registry is the source of truth;
these are one-line glosses.

| ID | What it looks for |
|---|---|
| `PTD-OPA-001` | the subject writes an attribute the policy reads to decide about them |
| `PTD-OPA-002` | a deny rule is silent for part of the data, so the check does not apply there |
| `PTD-OPA-003` | a position in a hierarchy grants everything below it, and nothing says so |
| `PTD-OPA-004` | a decision depends on an external source, so whoever controls it decides |
| `PTD-OPA-005` | a check that needs an external source stops applying when it does not answer |

Only one claim in there deserves the words privilege escalation, and it comes from chaining two
of them: on the fixture, `PTD-OPA-001` and `PTD-OPA-003` together produce a single
`PTD_CanEscalateTo`, from a principal who can write one field to the position of a principal who
can read a whole subtree, naming the document to write and the endpoint to write it through. The
value is not invented: the engine leaves that document unknown and asks OPA what is left of the
decision, so "some value here works" is an answer rather than a guess.

What holds the whole claim up is the write model in `internal/writemodel`: who can write what is
not in the policy and has to be declared. Without it every match stays a candidate, and the
engine reports how many of the paths the decisions read the model covers, so that a clean run is
distinguishable from an empty model.

The BloodHound export lands next.

## License

Apache-2.0. See [LICENSE](LICENSE).
