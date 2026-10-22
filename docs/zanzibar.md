# Zanzibar models (ReBAC)

How Petard reads a relationship-based model: what the engine holds of a schema, how it answers a
check, how those answers are held to SpiceDB, and the patterns it applies.
[spicedb.md](spicedb.md) has the files Petard reads from SpiceDB and what a run on them prints, and
[concepts.md](concepts.md) what every engine shares.

## The model

A Zanzibar model declares types of object, the relations a relationship can be stored against,
and permissions computed from them. SpiceDB compiles its schema language into that form, the
userset rewrites of the Zanzibar paper (`pkg/schemadsl/compiler/compiler.go:36-42` at v1.56.2),
and Petard reads the compiled form rather than the text. The front end in
`internal/zanzibar/spicedb` compiles a schema with SpiceDB's own compiler and lowers what it
returns into the model of `internal/zanzibar`, which imports nothing from SpiceDB.

A relation lists the subjects a relationship of it may hold:

- an object, `user`;
- a userset, the members of a group, `group#member`;
- every object of a type at once, `user:*`;
- any of them with a caveat, `user with ip_allowlist`, or with an expiration,
  `user with expiration`.

A permission is an expression over the relations and permissions of the same object:

| Written | Holds when |
|---|---|
| `a + b` | either holds |
| `a & b` | both hold |
| `a - b` | `a` holds and `b` does not |
| `parent->view`, `parent.any(view)` | `view` holds on any object `parent` reaches |
| `parent.all(view)` | `view` holds on every object `parent` reaches, and `parent` reaches one |
| `self` | the subject is the object itself |
| `nil` | never |

A caveat is a condition a relationship can carry: a CEL expression over typed parameters, such as
`user_ip.in_cidr(cidr)`. The engine never reads the expression. The front end evaluates it in
SpiceDB's own CEL environment, so the types SpiceDB adds, `ipaddress` among them, behave as they
do there.

## How a check is answered

A check asks whether a subject holds a permission or a relation on an object, and has three
answers: no, yes, or conditional. Conditional is yes if a caveat on the way turns out true, which
the check leaves open when it does not supply every value the caveat reads. Combined, `+` takes
the higher of two answers and `&` the lower. `a - b` is no where `b` is yes, and conditional
where `b` is conditional and `a` holds at all. That is the three-valued logic SpiceDB applies to
caveats it cannot settle (`internal/caveats/run.go:274-357` at v1.56.2).

The rest follows SpiceDB, at v1.56.2:

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

## The patterns

Eight patterns apply to Zanzibar models. `petard explain <id>` prints each in full, and the files
in `taxonomy-registry/zanzibar/` are the source of truth.

| ID | What it looks for |
|---|---|
| `PTD-ZAN-001` | a caveat parameter the check is meant to supply, which whoever writes the relationship can set instead |
| `PTD-ZAN-002` | a deny an exclusion keeps, lifted by deleting the tuple it subtracts |
| `PTD-ZAN-003` | a relation granted to every object of a type at once, through a wildcard subject |
| `PTD-ZAN-004` | an object linked across an arrow to one the coalition controls |
| `PTD-ZAN-005` | a userset a relation grants to, which the coalition can join |
| `PTD-ZAN-006` | a gated write that grants to another a right the writer never held |
| `PTD-ZAN-007` | a weaker permission gating the write of a stronger one into the object |
| `PTD-ZAN-008` | a subject writing itself a relation behind a gate that needs no permission |

`PTD-ZAN-001` reads, for every parameter of every caveat a relation allows, whether the parameter
is meant for the check and who writes the relation. A write may set any parameter of the caveat
(`internal/relationships/validation.go:248-262` at v1.56.2), so the writer can fix such a
parameter once, for every check to come. In the fixture those parameters are the caller's address
and the time of the request.

With a write model the match is a finding: the model marks the parameter the application's and
names the gate that says who writes the relation, which petard confirms a coalition can reach
from a starting position. Without one, the validation file is the evidence of a candidate: an
assertion supplies the parameter after `with`, or the relationships of the relation leave it out
and none writes it, and the candidate carries a check of the file whose answer rises once a
relationship fixes the value.

A parameter every relationship writes and no check supplies, the network an allowlist holds a
viewer to, is the writer's by design, and the pattern leaves it alone.

`PTD-ZAN-002` through `PTD-ZAN-008` ask a different question, the one the definitions open with:
can a coalition, writing only what the write model allows, raise a permission it did not hold on an
object that was there before it started. The engine runs a closure from the starting states, the
relationships of the validation file and the positions generated from the schema, and labels each
escalation it finds by its decisive write, the write after which the permission rises (section 7.1
of the definitions): a delete under an exclusion, a wildcard subject, an arrow link to a controlled
object, a userset join, a grant written for another, and a self-write behind a permission or an
open gate. They rest on the write model and are reported only with one, since who writes a relation
is not in the schema.

The categories of the registry with no Zanzibar instance, and why, are in section 3 of
[taxonomy-registry/README.md](../taxonomy-registry/README.md).

## What a match rests on

Who writes a relation, and with which context, is decided by the application that writes to
SpiceDB, and no schema says it. A `relationship-writes` write model beside the schema does: it
names who writes each relation and, per caveat parameter, whether the writer or the application
fills it. With one, a match is a finding; without one, a candidate, and `-fail-on any` is what
fails a run on a candidate. A schema no validation file reads is named in the report as one with
no evidence. `petard export` reads the schemas as well, and draws the escalations it finds as a
BloodHound OpenGraph.

## The write model

The write model is a YAML file that declares `model: relationship-writes`, the same file family as
the OPA write model (`model: write-paths`); the kind tells the two apart. `petard analyze` reads
one found beside a schema, and the `-write-model` flag passes one by path. A relation with no rule
is not writable by a coalition, so what is left out is a missed write, never an invented one.
`fixtures/vulnerable-spicedb/writes.yaml` is a worked example.

A `writes` entry is a rule for one relation:

| Field | What |
|---|---|
| `resource`, `relation` | the relation written |
| `operations` | `create`, `touch`, `delete` |
| `gate` | who may write: `anyone`, `{ holds: <permission> }` the writer holds on the resource, or `{ service: <name> }` for a write no end user can cause |
| `subject` | what may be written as the subject: `self`, `any`, a list of types or usersets (`[user, "team#member"]`), or `{ holds: <permission> }` the subject object holds |
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
