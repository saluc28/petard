# What the analysis has to find in the SpiceDB fixture

`schema.zed` is the schema of Quill's documents, `validation.yaml` the relationships written
against it and the checks asserted about them (five relationships and nine assertions), and
`writes.yaml` the write model: who the application lets write each relationship. Each rule of the
write model carries one defect, so the one fixture exercises every pattern of the engine.
`zed validate validation.yaml` accepts the file as it stands, with zed v1.2.1.

```
petard analyze fixtures/vulnerable-spicedb
```

## The caveat finding

Two findings of `PTD-ZAN-001`, one per relationship a writer can exempt from a check.

| Relation | Caveat | Parameter | Written by | Raises |
|---|---|---|---|---|
| `document#viewer` | `ip_allowlist` | `user_ip` | anyone | `view`, `access` |
| `document#editor` | `not_expired` | `now` | whoever holds `view` | `edit`, `view`, `access` |

The caveats hold each relationship to a value the check supplies: the address of the caller for
`ip_allowlist`, the time of the request for `not_expired`. The write model marks `user_ip` and
`now` as the application's, but SpiceDB lets a write carry any parameter of the caveat and the
written value wins over the check's, so whoever writes the relationship can fix them. Written with
an address inside the network, the viewer is let in from anywhere; written with a time before the
date, the editor never expires. Both were held against SpiceDB with zed v1.2.1, with the
relationships written as the witnesses say.

They are findings because the write model says who writes the relations and that the two
parameters are the check's. Without a write model they are the same two matches as candidates,
which is what a run with no `writes.yaml` reports.

## The escalations

Seven findings, `PTD-ZAN-002` through `PTD-ZAN-008`, one for each kind of decisive write a
coalition can make against the write model. Each is a permission the coalition raises on the
roadmap, an object it did not start out holding, through the write the row names.

| ID | Category | Decisive write | Raises |
|---|---|---|---|
| `PTD-ZAN-002` | FAIL-OPEN-ON-ABSENCE | delete `document#banned`, which anyone may do | `access` |
| `PTD-ZAN-003` | GLOBAL-SWITCH | write `document#viewer@user:*`, which the wildcard flag allows | `view`, `access` |
| `PTD-ZAN-004` | TRANSITIVE-GRANT | write `document#parent` to a folder the coalition controls | `view`, `access` |
| `PTD-ZAN-005` | ASSUMABLE-IDENTITY | join `team#member`, which anyone may do | `view`, `access` |
| `PTD-ZAN-006` | DELEGATION-NOT-NARROWED | write `document#editor` for a sybil, gated on holding `view` | `edit`, `view`, `access` |
| `PTD-ZAN-007` | SPLIT-GRANT | write `document#editor` for itself, gated on holding `view` | `edit` |
| `PTD-ZAN-008` | ATTR-SELF-WRITE | write `document#viewer` for itself, which anyone may do | `view`, `access` |

Each rests on the write model, which says who writes a relation and so who can make the decisive
write. With no `writes.yaml` the escalations are not reported at all, since who writes a relation
is nowhere in the schema. The closure runs from the relationships of the validation file and the
starting positions generated from the schema, and labels each escalation by the write after which
the permission rises.

## Must not find

Nothing on `cidr` or `until`, the other parameters of the same two caveats. The write model marks
them the writer's, every relationship that carries the caveat writes them, and no check supplies
them: they are the writer's to choose, which is what the schema means them to be.

No escalation to `document#owner`. It has no write rule, so no coalition can write or delete its
way to it; the run proposes a safe gate for it instead (section 6 of the definitions), rather than
reporting it as reachable.
