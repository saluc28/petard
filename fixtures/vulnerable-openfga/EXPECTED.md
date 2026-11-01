# What the analysis has to find in the OpenFGA fixture

`model.fga` is the model of Quill's documents, the service of the SpiceDB fixture, `store.fga.yaml`
the tuples written against it and the checks asserted about them (five tuples and seven checks),
and `writes.yaml` the write model: who the application lets write each tuple. Each rule of the
write model carries one defect, so the one fixture exercises every pattern of the engine.

```
petard analyze fixtures/vulnerable-openfga
```

Every relation of OpenFGA can be asked by a check, so a raise is reported on the relation as well
as on what reads it, `document#viewer` beside `document#view`. Two kinds of relation stay out of
that: `document#parent`, which an arrow walks, and `document#banned`, read only to subtract it.

## The condition finding

Two findings of `PTD-ZAN-001`, one per tuple a writer can exempt from a check.

| Relation | Condition | Parameter | Written by | Raises |
|---|---|---|---|---|
| `document#viewer` | `ip_allowlist` | `user_ip` | anyone | `view`, `access`, `viewer` |
| `document#editor` | `not_expired` | `now` | whoever holds `view` | `edit`, `view`, `access`, `editor` |

The conditions hold each tuple to a value the check supplies: the address of the caller for
`ip_allowlist`, the time of the request for `not_expired`. The write model marks `user_ip` and `now`
as the application's, but OpenFGA lets a write carry any parameter of the condition and the written
value wins over the check's, so whoever writes the tuple can fix them. Written with an address
inside the network, the viewer is let in from anywhere; written with a time before the date, the
editor never expires.

They are findings because the write model says who writes the relations and that the two parameters
are the check's. Without a write model they are the same two matches as candidates, which is what
a run with no `writes.yaml` reports.

## The escalations

Findings of `PTD-ZAN-002` through `PTD-ZAN-008`, one for each kind of decisive write a coalition can
make against the write model. Each is a relation the coalition raises on an object it did not start
out holding, through the write the row names.

| ID | Category | Decisive write | Raises |
|---|---|---|---|
| `PTD-ZAN-002` | FAIL-OPEN-ON-ABSENCE | delete `document#banned`, which anyone may do | `access` |
| `PTD-ZAN-003` | GLOBAL-SWITCH | write `document#viewer@user:*`, which the wildcard flag allows | `viewer`, `view`, `access` |
| `PTD-ZAN-004` | TRANSITIVE-GRANT | write `document#parent` to a folder the coalition controls | `view`, `access` |
| `PTD-ZAN-005` | ASSUMABLE-IDENTITY | join `team#member`, which anyone may do | `viewer`, `view`, `access` |
| `PTD-ZAN-006` | DELEGATION-NOT-NARROWED | write `document#editor` for a sybil, gated on holding `view` | `editor`, `edit` |
| `PTD-ZAN-006` | DELEGATION-NOT-NARROWED | write `document#viewer` for a sybil, which anyone may do | `viewer`, `view`, `access` |
| `PTD-ZAN-006` | DELEGATION-NOT-NARROWED | write `team#member` for a sybil, which anyone may do | `member` |
| `PTD-ZAN-007` | SPLIT-GRANT | write `document#editor` for itself, gated on holding `view` | `editor`, `edit` |
| `PTD-ZAN-008` | ATTR-SELF-WRITE | write `document#viewer` for itself, which anyone may do | `viewer`, `view`, `access` |
| `PTD-ZAN-008` | ATTR-SELF-WRITE | write `team#member` for itself, which anyone may do | `member` |

Each rests on the write model, which says who writes a relation and so who can make the decisive
write. With no `writes.yaml` the escalations are not reported at all, since who writes a relation
is nowhere in the model. The closure runs from the tuples of the store file and the starting
positions generated from the model, and labels each escalation by the write after which the
relation rises.

## Must not find

Nothing on `cidr` or `until`, the other parameters of the same two conditions. The write model marks
them the writer's, every tuple that carries the condition writes them, and no check supplies them:
they are the writer's to choose, which is what the model means them to be.

No escalation to `document#owner`. It has no write rule, so no coalition can write or delete its way
to it; the run proposes a safe gate for it instead (section 6 of the definitions), rather than
reporting it as reachable. That gate is `owner`: a holder of `edit` who made itself owner would
raise `owner`, which a check of OpenFGA can ask.

## How it is held

The test suite holds this file to OpenFGA v1.22.1, with a server running in the test process and
nothing reached over a network:

```
go test ./internal/zanzibar/openfga -run 'TestFixture|TestRegistryCases|TestOracle'
```

`TestFixture` asserts the matches above. `TestFixtureChecksHoldOnCheck` asks `Check` for the seven
checks of the store file. `TestFixtureExemptionsHoldOnCheck` writes the two tuples as the condition
findings say, and `Check` then allows the check from outside the network and the check after the
date, and a check that brings nothing. `TestFixtureWitnessesHoldOnCheck` makes the writes of every
escalation the engine finds on a real store, and `Check` does not allow the relation before them
and allows it after. `TestOracle` holds the engine's answers to `Check` over every check the objects
of the fixture allow.
