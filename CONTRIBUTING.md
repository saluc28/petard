# Contributing

Thanks for looking. The most useful contributions here are a policy that breaks
the analysis, with the Rego and the data to reproduce it, and a pattern that
belongs in the registry with the reasoning behind it.

## Scope

Petard reads Rego, works out what its decisions depend on, applies the patterns
in `taxonomy-registry/` and exports the result as a BloodHound OpenGraph. It is
not a linter, not a policy engine, and not a general BloodHound client.

Three rules are unlikely to change.

Nothing from OPA's AST crosses the boundary of `internal/graph`. Residual
conditions enter as strings that are already serialized. That constraint is what
lets a second policy engine reuse the model instead of forcing a rewrite of it,
and it is cheap to keep only as long as nobody breaks it once.

Analyzing a policy never calls the endpoints written in it. Partial evaluation
can be told to evaluate nondeterministic builtins, and it is not: a run of the
analysis must not turn into HTTP requests to hosts chosen by whoever wrote the
file being read.

A pattern that `regal` could find by reading one file is a lint rule and does
not go in the registry. Every pattern carries a `not_a_lint_rule` field that has
to say, in one sentence, why a linter cannot find it. `taxonomy-registry/` has
the rest of the rules, and `taxonomy-registry/SCHEMA.md` has the fields.

## Getting set up

Go 1.26 or newer, which is the floor OPA declares.

```
go build ./...
go test -race -shuffle=on ./...
go vet ./...
gofmt -l .
```

`golangci-lint` runs in CI and its config is in `.golangci.yml`. To run it
locally, install it from https://golangci-lint.run and run `golangci-lint run`.

`opa` and `regal` are not needed to build or test. They are what the numbers in
`fixtures/vulnerable-bundle/EXPECTED.md` were produced with, and section 7 of
that file has the commands to regenerate them.

## Tests

Tests run offline and must stay that way. The fixture points at hosts under
`.invalid`, which never resolve, so a run that did make requests would still
pass its assertions. That is why the tests check the residual condition and not
the outcome.

Two things are checked against something outside the code and cannot be
regenerated casually. `schema/petard.json` is generated from the model, and
`go test ./internal/opengraph -update` rewrites it: read the diff before you do,
because those names are a contract with data already ingested and with saved
queries. `fixtures/vulnerable-bundle/EXPECTED.md` declares what the engine has
to find and what it must not, and it was written before the engine: changing it
to match a new result turns the criterion into a description of whatever the
code happens to do.

The end-to-end run against a live BloodHound is manual and not in CI.

## Changing a pattern

A pattern is data. Editing the YAML changes what the report says, and the engine
reads the id, the title, the category, `graph.emits` and
`detection.requires_write_model` out of it.

If you add a case the engine has to find, add the counter case too. Without one
only recall is measured, and precision is the half that decides whether the tool
is usable in an assessment.

## Pull requests

Keep the diff to one subject. Unrelated cleanups in the same pull request make a
change hard to review and hard to revert.

Commit messages: a short imperative subject line, then the reasoning if it is
not obvious from the diff. Explain why, not what. The diff already says what.

If a change touches the graph kinds, the property keys or the schema, say so in
the pull request. Those names end up in ingested data and in saved queries, so
renaming one means re-ingesting every graph and rewriting every query that
mentions it.

## Reporting a security issue

See [SECURITY.md](SECURITY.md). Please do not open a public issue for one.
