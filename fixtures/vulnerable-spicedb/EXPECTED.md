# What the analysis has to find in the SpiceDB fixture

`schema.zed` is the schema of Quill's documents, `validation.yaml` the relationships written
against it and the checks asserted about them (five relationships and nine assertions), and
`writes.yaml` the write model: who the application lets write each relationship.
`zed validate validation.yaml` accepts the file as it stands, with zed v1.2.1.

```
petard analyze fixtures/vulnerable-spicedb
```

## Has to find

Two findings of `PTD-ZAN-001`, one per relationship a writer can exempt from a check.

| Relation | Caveat | Parameter | Written by | Raises |
|---|---|---|---|---|
| `document#viewer` | `ip_allowlist` | `user_ip` | whoever can `edit` | `view` |
| `document#editor` | `not_expired` | `now` | the `owner` | `edit`, `view` |

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

## Must not find

Nothing on `cidr` or `until`, the other parameters of the same two caveats. The write model marks
them the writer's, every relationship that carries the caveat writes them, and no check supplies
them: they are the writer's to choose, which is what the schema means them to be.
