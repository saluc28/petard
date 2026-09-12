# Petard

Attack-path analysis for policy-as-code. Petard reads Rego (OPA) policies, works out what
their decisions depend on, and applies a curated taxonomy of privilege-escalation patterns to
what it finds. The result is meant to leave the tool as a structured BloodHound OpenGraph.

The parser is not the point. The taxonomy is: the catalogue of ways a policy and the data it
reads can be turned against the system they protect, and above all the ones that cross the
line between whoever takes a decision and whoever writes the data that decision is taken on.
A linter sees one file. Petard is built to see the policy, the data and who can write it,
together.

## What is here

The graph model, in `internal/graph`. It is the first thing rather than an afterthought because
of what it costs to change later: the kind names and the property keys end up in ingested data
and in saved Cypher queries, so renaming one means re-ingesting every graph and rewriting every
query that mentions it. Getting them right is cheap now and expensive in a month.

Two things about it are worth reading before the rest arrives.

Nothing from OPA's AST crosses this package boundary. Residual conditions enter as strings that
are already serialized, which is the constraint that lets a second policy engine reuse the model
instead of forcing a rewrite of it, and it is cheap to keep only as long as nobody breaks it
once.

Whether an edge takes part in BloodHound's pathfinding is decided here, by `IsTraversable`, and
not in the export. Marking an edge traversable when it does not represent a capability invents
paths in the interface that nobody can walk, so it is a semantic decision rather than a cosmetic
one, and it lives next to the kinds so the schema and the model cannot drift apart.

The OPA engine, the taxonomy and the BloodHound export land next.

## License

Apache-2.0. See [LICENSE](LICENSE).
