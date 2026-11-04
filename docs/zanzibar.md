# Zanzibar models (ReBAC)

How Petard reads a relationship-based model: what the engine holds of a schema, how it answers a
check, how those answers are held to SpiceDB and OpenFGA, and the patterns it applies.
[spicedb.md](spicedb.md) and [openfga.md](openfga.md) have the files Petard reads from each product
and what a run on them prints, and [concepts.md](concepts.md) what every engine shares.

## The model

A Zanzibar model declares types of object, the relations a relationship can be stored against,
and permissions computed from them. SpiceDB compiles its schema language into that form, the
userset rewrites of the Zanzibar paper (`pkg/schemadsl/compiler/compiler.go:36-42` at v1.56.2),
and Petard reads the compiled form rather than the text. The front end in
`internal/zanzibar/spicedb` compiles a schema with SpiceDB's own compiler and lowers what it
returns into the model of `internal/zanzibar`, which imports nothing from SpiceDB. OpenFGA compiles
its language into the same rewrites (`pkg/typesystem/typesystem.go:1005-1124` at v1.22.1), and the
front end in `internal/zanzibar/openfga` lowers them into the same model.

A relation lists the subjects a relationship of it may hold:

- an object, `user`;
- a userset, the members of a group, `group#member`;
- every object of a type at once, `user:*`;
- any of them with a caveat, `user with ip_allowlist`, or with an expiration,
  `user with expiration`.

OpenFGA writes the same list in brackets, `[user, group#member, user:*, user with ip_allowlist]`,
and its tuples carry no expiration (`openfga/v1/openfga.proto:161-199` in openfga/api at
f153694bfc20).

A permission is an expression over the relations and permissions of the same object:

| SpiceDB | OpenFGA | Holds when |
|---|---|---|
| `a + b` | `a or b` | either holds |
| `a & b` | `a and b` | both hold |
| `a - b` | `a but not b` | `a` holds and `b` does not |
| `parent->view`, `parent.any(view)` | `view from parent` | `view` holds on any object `parent` reaches |
| `parent.all(view)` | | `view` holds on every object `parent` reaches, and `parent` reaches one |
| `self` | | the subject is the object itself |
| `nil` | | never |

SpiceDB declares a relation, what is written, apart from a permission, what is asked. OpenFGA keeps
both under one name: `define viewer: [user] or editor` stores tuples under `viewer`, and a check of
`viewer` also reads `editor`. The engine holds that as a
relation and a permission of one name, the permission reading the relation through the expression
`Stored`, the `_this` of the Zanzibar paper. So a relation of an OpenFGA model can be asked and can
be raised, except for two kinds that stay relations alone: one an arrow walks, which OpenFGA holds
to be direct (`pkg/typesystem/typesystem.go:1349-1353` at v1.22.1), and one read only to subtract
it, where holding it opens nothing.

A caveat is a condition a relationship can carry: a CEL expression over typed parameters, such as
`user_ip.in_cidr(cidr)`. The engine never reads the expression. The front end evaluates it in the
product's own CEL environment, so the types the product adds, `ipaddress` among them, behave as they
do there. OpenFGA calls a caveat a condition and a relationship a tuple, and a report on an OpenFGA
model uses those words.

## How a check is answered

A check asks whether a subject holds a permission or a relation on an object, and has three
answers: no, yes, or conditional. Conditional is yes if a caveat on the way turns out true, which
the check leaves open when it does not supply every value the caveat reads. Combined, `+` takes
the higher of two answers and `&` the lower. `a - b` is no where `b` is yes, and conditional
where `b` is conditional and `a` holds at all. That is the three-valued logic SpiceDB applies to
caveats it cannot settle (`internal/caveats/run.go:274-357` at v1.56.2). OpenFGA has no conditional
answer: a check that stops on a condition it cannot decide is refused, and the engine reads that as
conditional.

For a SpiceDB schema the rest follows SpiceDB, at v1.56.2:

- A caveat is evaluated on the context the check supplies, with the context written on the
  relationship copied over it, so a value the relationship carries wins
  (`internal/caveats/run.go:222-230`). This is what `PTD-ZAN-001` rests on.
- A userset asked as a subject holds its own relation: a check of `member` on `group:eng` with
  the subject `group:eng#member` is yes (`internal/graph/check.go:765-779`).
- A wildcard cannot be the subject of a check, and asking one is an error
  (`internal/graph/check.go:179`).
- `.all()` over a relation that reaches nothing holds for nobody
  (`internal/graph/check.go:842-844`).
- A relationship whose expiration is at the time of the run or before does not count, as the SQL
  datastores read it (`internal/datastore/common/sql.go:207-211`). The in-memory datastore still
  counts one that expires at that very instant (`internal/datastore/memdb/readonly.go:572`).

A check that comes back to itself on the way is answered from the paths without the loop, and
the answer says a loop was cut. SpiceDB follows the loop until its dispatch depth runs out, 50 by
default (`pkg/cmd/server/server.go:100`), and the check then fails with an error
(`internal/dispatch/dispatch.go:133-135`). Petard stops at ten thousand nested checks, so a chain
of relationships long enough to exhaust the stack ends in an error rather than a crash.

For an OpenFGA model the rest follows OpenFGA, at v1.22.1:

- A condition is evaluated on the context the check supplies, with the context written on the tuple
  merged over it, so a value the tuple carries wins (`internal/condition/eval/eval.go:112-123`,
  `internal/condition/condition.go:218-223`). `PTD-ZAN-001` rests on this as it does on SpiceDB.
- A condition evaluated without a parameter it reads is an error
  (`internal/condition/eval/eval.go:131-137`), and a check that stops on it is refused with a
  validation error.
- A tuple whose condition does not hold is not followed (`internal/checkutil/checkutil.go:85-91`,
  `internal/graph/check.go:909-915`), so a loop behind it is never met.
- A userset asked as a subject holds its own relation (`internal/graph/check.go:434-438`).
- A wildcard can be the subject of a check, as OpenFGA's own suite asks
  (`assets/tests/consolidated_1_1_tests.yaml:2972-2976`). The engine has no question that stands for
  it, and leaves such a check out.

A relation that only reaches itself OpenFGA can walk with a set of what it has seen, which meets no
loop (`internal/graph/recursive_resolver.go:277-300`). Otherwise it dispatches each step, and a loop
it meets on the side an exclusion subtracts means the exclusion is not allowed
(`internal/graph/check.go:358-360`). The front end tells the engine which loops a check meets, in
`Model.Walk`. Past its resolution depth, 25 by default (`pkg/server/config/config.go:25`), a check
fails with an error (`internal/graph/check.go:415-416`).

## Held to SpiceDB

The engine's answers are held to SpiceDB's own in CI. For every validation file of Petard's tests,
the SpiceDB fixture `petard demo` carries, and every integration test configuration SpiceDB
v1.56.2 ships, the engine answers every check the objects of the file allow, with objects and
usersets as subjects, with no context and with each context the assertions of the file supply. It
writes the answers into the file as assertions, and `zed validate`, from zed v1.2.1, says whether
SpiceDB gives the same ones.

On 76 files that is 26,543 checks, and SpiceDB agrees on all of them. Another 36 are left out:
they go round a loop and grant nothing, and SpiceDB fails them at its depth limit rather than
answering. To run it with a zed binary of your own:

```
PETARD_ZED=zed PETARD_ZANZIBAR_CORPUS="$(go list -m -f '{{.Dir}}' github.com/authzed/spicedb)/internal/services/integrationtesting/testconfigs" go test ./internal/zanzibar/spicedb -run TestOracle
```

## Held to OpenFGA

The engine's answers are held to OpenFGA's own `Check` on every `go test`, with nothing to install
and nothing reached over a network. A server from `pkg/server` of OpenFGA v1.22.1 runs in the test
process, as it ships, with its in-memory store. For every stage of Petard's test models, the OpenFGA
fixture `petard demo` carries and the check tests OpenFGA ships (`assets/tests`), the engine answers
every check the objects of the stage allow, with objects and usersets as subjects, with no context
and with each context the stage's assertions supply, and the server is asked the same.

It agrees on more than 20,000 checks. On about 210 more the two fit without being equal, all of them
on a condition the check leaves undecided: OpenFGA has no conditional answer, and `compareOracle` in
the test says what fits and why. Left out are 57 on an inline condition, which the engine reads as
conditional and does not evaluate, and about 15 past OpenFGA's resolution depth. The counts move by a
few from one run to the next, and the test holds on each. To run it:

```
go test ./internal/zanzibar/openfga -run 'TestOracle|TestCorpus' -v
```

`TestCorpus` reads the answers OpenFGA's own suite asserts, 454 answers and 13 refusals, and the
engine agrees with them.

## The patterns

Eight patterns apply to Zanzibar models. `petard explain <id>` prints each in full, and the files
in `taxonomy-registry/zanzibar/` are the source of truth.

| ID | What it looks for |
|---|---|
| `PTD-ZAN-001` | a caveat parameter the check is meant to supply, which whoever writes the relationship can set instead |
| `PTD-ZAN-002` | a deny an exclusion keeps, lifted by deleting the tuple it subtracts |
| `PTD-ZAN-003` | a relation granted to every object of a type at once, through a wildcard subject |
| `PTD-ZAN-004` | an object linked across an arrow to one the coalition holds a permission on |
| `PTD-ZAN-005` | a group an object grants to, a userset or an object it reads, which the coalition can join |
| `PTD-ZAN-006` | a gated write that grants to another a right the writer never held |
| `PTD-ZAN-007` | a weaker permission gating the write of a stronger one into the object |
| `PTD-ZAN-008` | a subject writing itself a relation behind a gate that needs no permission |

`PTD-ZAN-001` reads, for every parameter of every caveat a relation allows, whether the parameter
is meant for the check and who writes the relation. A write may set any parameter of the caveat
(`internal/relationships/validation.go:248-262` at SpiceDB v1.56.2,
`internal/validation/validation.go:284-309` at OpenFGA v1.22.1), so the writer can fix such a
parameter once, for every check to come. In the fixtures those parameters are the caller's address
and the time of the request.

With a write model the match is a finding: the model marks the parameter the application's and
names the gate that says who writes the relation, which petard confirms a coalition can reach
from a starting position. Without one, the validation file or the store file is the evidence of a
candidate: a check supplies the parameter, after `with` in an assertion or under `context` in a
test, or the relationships of the relation leave it out and none writes it, and the candidate
carries a check of the file whose answer rises once a relationship fixes the value.

A parameter every relationship writes and no check supplies, the network an allowlist holds a
viewer to, is the writer's by design, and the pattern leaves it alone.

`PTD-ZAN-002` through `PTD-ZAN-008` ask a different question, the one the definitions open with:
can a coalition, writing only what the write model allows, raise a permission it did not hold on an
object that was there before it started. The engine runs a closure from the starting states, the
relationships of the validation file or the store file and the positions generated from the schema, and labels each
escalation it finds by its decisive write, the write after which the permission rises (section 7.1
of the definitions): a delete under an exclusion, a wildcard subject, an arrow link to a controlled
object, a userset join, a grant written for another, and a self-write behind a permission or an
open gate. They rest on the write model and are reported only with one, since who writes a relation
is not in the schema. The report puts them under the write rule behind their decisive write, the
rule that opens the most first, since a rule is what somebody changes. A raise with another way up
comes back under the rule of that way on the next run. With -v it adds the whole witness: the writes
in order that reach the raise and who the write model lets make each, so a multi-write escalation
shows the setup it needs and not only the write that ends it.

The categories of the registry with no Zanzibar instance, and why, are in section 3 of
[taxonomy-registry/README.md](../taxonomy-registry/README.md).

## A store

The search for an escalation weighs every sequence of writes up to four, and its cost grows with the
power of how many objects a coalition can write on. To hold that down each object is weighed apart,
on the tuples a check of it can read. Those answer a check of it as the whole store does, so nothing
found this way is false.

A gate is asked of the object written, so a witness can use another object that already exists only
by naming it: as the subject of a write, where the tuple can carry something back to the coalition,
a userset or an object across a relation an arrow walks, or as what a creation is made on. Of each
type that can be named so, one object of each shape comes along. What this gives up is a witness that
needs that very object and not another of its shape, and the run says how many objects it weighed
this way.

A search stops at twenty thousand states, and what it found by then holds. The searches for an account
with nothing, and those for the subjects the relationships name, each have a limit on the work they
take together, spent on the smallest states first. When any of these stops short, the report says so.

## What the graph holds

`petard export` draws two kinds of fact. For the subjects the relationships name, a `PTD_CanPerform`
to each object says what the subject holds as they stand, and a `PTD_CanEscalateTo` says what it can
raise by writing what the write model allows. A holding is an unconditional yes: what waits on a
caveat, or rests on a walk that cut a loop, is not drawn. A subject is weighed for what it can raise on
the objects whose checks read a tuple naming it, and, on one object of each type, for what it can carry
there from what it holds: a folder it views, into which it may move any document. There only what an
account with nothing could not raise is drawn as the subject's. The work on what subjects hold and on what they can
raise each has a limit, the second spent on the smallest states first, and the export says what they
left out.

For what no relationship names, the same edge starts at an attacker the analysis supposes, an account
that holds nothing it did not write, and can end at an object of a state generated from the schema.
Those nodes carry `hypothetical`, since what they say holds for any account or object of the type.

BloodHound keeps one edge of a kind between two nodes (`drivers/pg/query/sql/schema_up.sql:146` at
dawgs v0.6.0), so each of these edges lists its `permissions`, and a `PTD_CanEscalateTo` its `patterns`.

## What a match rests on

Who writes a relation, and with which context, is decided by the application that writes to the
product, and no schema says it. A `relationship-writes` write model beside the schema does: it
names who writes each relation and, per caveat parameter, whether the writer or the application
fills it. With one, a match is a finding; without one, a candidate, and `-fail-on any` is what
fails a run on a candidate. A schema a write model stands beside is analyzed even with no
validation file or store file: the escalation patterns run from the positions generated from the
schema, so findings surface without such a file written by hand. A schema with neither a write
model nor such a file has nothing to run from, and the report names it as one with no evidence.
`petard export` reads the schemas the same way, and draws the escalations it finds as a BloodHound
OpenGraph.

## The write model

The write model is a YAML file that declares `model: relationship-writes`, the same file family as
the OPA write model (`model: write-paths`); the kind tells the two apart. `petard analyze` reads
one found beside a schema, and the `-write-model` flag passes one by path. A relation with no rule
is not writable by a coalition, so what is left out is a missed write, never an invented one.
`fixtures/vulnerable-spicedb/writes.yaml` and `fixtures/vulnerable-openfga/writes.yaml` are worked
examples.

A `writes` entry is a rule for one relation:

| Field | What |
|---|---|
| `resource`, `relation` | the relation written |
| `operations` | `create`, `touch`, `delete`. A `create` fails on a tuple that is there, whatever its caveat (`internal/datastore/memdb/readwrite.go:66-93` at SpiceDB v1.57.0, `pkg/storage/memory/memory.go:459-471` at OpenFGA v1.22.1), so only a rule that also touches or deletes can lift a conditional tuple |
| `gate` | who may write: `anyone`, `{ holds: <permission> }` the writer holds on the resource, or `{ service: <name> }` for a write no end user can cause |
| `subject` | what may be written as the subject: `self`, `any`, a list of types or usersets (`[user, "team#member"]`), or `{ holds: <permission> }` an object that holds the permission on the resource |
| `wildcard` | whether the writer may write `T:*` |
| `caveat` | the caveats the writer may attach, and per parameter whether the `writer` or the `application` fills it; `writer` is the default, because the written context wins over the check's |
| `expiration` | `writer`, `application` or `none` |
| `via`, `note`, `intended` | how the write happens, a note, and whether the raise it allows is by design and so not reported |

A `creates` entry is a rule for a new object a coalition can make. Sign-up is one on the user type
gated `anyone`, which is what puts sybil accounts in a coalition:

```yaml
writes:
  - resource: document
    relation: viewer
    operations: [create, touch]
    gate: { holds: edit }          # whoever can edit may share
    subject: [user, "team#member"]
    caveat:
      - name: ip_allowlist
        parameters:
          cidr: writer             # the network, chosen when the share is made
          user_ip: application     # the caller's address, meant to come with the check
    via: the share endpoint

creates:
  - creates: user                  # sign-up
    gate: anyone
```

A `creates` entry holds `creates`, a `gate`, an optional `on` (the objects it is made in, each
with its own gate), and `writes`, the tuples it writes, where `{created}` stands for the object
just made and `{creator}` for the coalition that made it.
