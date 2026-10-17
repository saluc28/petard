# What the analysis has to find in the SpiceDB fixture

`schema.zed` is the schema of Quill's documents, and `validation.yaml` the relationships written
against it and the checks asserted about them. `zed validate validation.yaml` accepts the file as
it stands, with zed v1.2.1: five relationships, nine assertions.

```
petard analyze fixtures/vulnerable-spicedb
```

## Has to find

Two candidates of `PTD-ZAN-001`, each with a check of the file that goes from no to yes once the
parameter is written on the relationship.

| Relation | Caveat | Parameter | The check that rises |
|---|---|---|---|
| `document#viewer` | `ip_allowlist` | `user_ip` | `document:roadmap#view@user:vic` from `192.168.0.1` |
| `document#editor` | `not_expired` | `now` | `document:roadmap#edit@user:erin` on `2026-12-01` |

The checks of the file supply `user_ip` and `now`, and the relationships leave them out: they are
meant to come with the check. Written on the relationship, the value stays whatever the check
brings, so Vic is let in from outside the office network and Erin's access never expires. Both
were held against SpiceDB with zed v1.2.1, with the relationships written as the witnesses say.

They are candidates because who writes `document#viewer` and `document#editor`, and with what
context, is decided by the application and not by the schema.

## Must not find

Nothing on `cidr` or `until`, the other parameters of the same two caveats. Every relationship
that carries the caveat writes them and no check supplies them: they are the writer's to choose,
which is what the schema means them to be.
