# Contributing

Thanks for looking. The most useful contributions here are a policy or a schema
that breaks the analysis, with the Rego and the data or the validation file to
reproduce it, and a pattern that belongs in the registry with the reasoning
behind it.

## Scope

Petard reads Rego policies and SpiceDB schemas, works out what their decisions
depend on, applies the patterns in `taxonomy-registry/`, and exports the analysis
of a policy as a BloodHound OpenGraph. It is not a linter, not a policy engine,
and not a general BloodHound client.

Four rules are unlikely to change.

Nothing from OPA's AST crosses the boundary of `internal/graph`. Residual
conditions enter as strings that are already serialized. That constraint is what
lets a second policy engine reuse the model instead of forcing a rewrite of it,
and it is cheap to keep only as long as nobody breaks it once.

The engine in `internal/zanzibar` imports nothing from SpiceDB. The front end in
`internal/zanzibar/spicedb` compiles a schema and lowers it into the engine's
model, and it is the one package that knows which product a model came from.
Where the products differ, the front end says so in what it builds.

Analyzing a policy never calls the endpoints written in it. Partial evaluation
can be told to evaluate nondeterministic builtins, and it is not: a run of the
analysis must not turn into HTTP requests to hosts chosen by whoever wrote the
file being read.

A pattern that a linter could find by reading one file, `regal` for Rego or the
warnings of SpiceDB for a schema, is a lint rule and does not go in the
registry. Every pattern carries a `not_a_lint_rule` field that has
to say, in one sentence, why a linter cannot find it. `taxonomy-registry/` has
the rest of the rules, and `taxonomy-registry/SCHEMA.md` has the fields.

## Getting set up

Go 1.26.6 or newer, which is the floor SpiceDB v1.56.2 declares.

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
that file has the commands to regenerate them. `zed` is not needed either: the
test that holds the Zanzibar engine to SpiceDB skips without it.

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
code happens to do. `fixtures/vulnerable-spicedb/EXPECTED.md` is the same for the
SpiceDB schema.

The Zanzibar engine is held to SpiceDB by `TestOracle` in
`internal/zanzibar/spicedb`. It answers every check the objects of each
validation file allow, writes the answers into the file as assertions, and runs
`zed validate` on it. CI runs it with zed v1.2.1 over `testdata` and the
integration test configurations SpiceDB ships, and a change to the engine has to
keep SpiceDB agreeing:

```
PETARD_ZED=zed PETARD_ZANZIBAR_CORPUS="$(go list -m -f '{{.Dir}}' github.com/authzed/spicedb)/internal/services/integrationtesting/testconfigs" go test ./internal/zanzibar/spicedb -run TestOracle
```

A block of output in a Markdown file, marked with `<!-- output of: petard ... -->`
on the line before its fence, is checked against what the command prints by
`TestTheDocsShowWhatTheCommandsPrint`. A change to the output fails it until the
block is rerun.

The end-to-end run against a live BloodHound is manual and not in CI. It is
`petard export -url ... -install -upload -verify`, it needs the
`opengraph_extension_management` feature flag on, and if you run it, say in the
pull request which BloodHound version answered.

## Changing a pattern

A pattern is data. Editing the YAML changes what the report says. The engine
reads the id, the name, the title, the status, the category, `closes`,
`detection.requires_write_model` and the `graph` block out of it, and runs the
case of each declared false positive. `petard explain` prints the prose.

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

## Layout

```
cmd/petard                 the binary, which dispatches to the subcommands
internal/cli               one package per subcommand, plus render for the printing rules
internal/opaengine         everything that knows what Rego is
internal/taxonomy          the registry reader and the patterns for policies
internal/zanzibar          the engine for Zanzibar models and its patterns, which knows no product
internal/zanzibar/spicedb  the SpiceDB front end, the one package that imports SpiceDB
internal/graph             the engine-neutral model of the exported graph
internal/opengraph         the adapter to what BloodHound ingests, over bhgraph
internal/writemodel        who can write which path, declared rather than inferred
internal/pep               who sets each part of the request, declared per enforcement point
internal/fixture           generated worlds, and the truth about them
queries/                   the saved Cypher queries, one file each
taxonomy-registry/         the patterns as versioned data, one directory per engine
pep-registry/              the enforcement points as versioned data, embedded for -pep
schema/                    the extension definition schema, generated from the model
fixtures/                  the policy and the SpiceDB schema written by hand, embedded for demo
```

## Reporting a security issue

See [SECURITY.md](SECURITY.md). Please do not open a public issue for one.
