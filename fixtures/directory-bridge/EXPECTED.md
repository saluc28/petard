# What the analysis has to find in the directory bridge fixture

The fixture is an application whose users sign in with an external directory. It is not real.

`app/` is the application: a documents schema, its relationships and checks in `validation.yaml`,
the write model in `writes.yaml`, and the identity map in `identities.yaml`, which says that a user
of the application is the account of the directory whose `objectid` is the subject's id. The
subjects are the security identifiers of the accounts.

```
petard analyze fixtures/directory-bridge/app
petard export -out petard.json fixtures/directory-bridge/app
```

## The finding

One finding of `PTD-ZAN-007`. Adding an editor to a document takes only being able to view it, so
Dev, who views the roadmap, can make themselves an editor and raise `edit` on it.

## The graph

| Edge | From | To |
|---|---|---|
| `PTD_CanEscalateTo`, `edit` | `USER:S-1-5-21-1000-2000-3000-1106` | `DOCUMENT:ROADMAP` |
| `PTD_ActsAs` | the `User` whose `objectid` is `S-1-5-21-1000-2000-3000-1106`, Dev | `USER:S-1-5-21-1000-2000-3000-1106` |
| `PTD_ActsAs` | the `User` whose `objectid` is `S-1-5-21-1000-2000-3000-1104`, Olivia | `USER:S-1-5-21-1000-2000-3000-1104` |

The attacker the analysis supposes has its own escalation, on a document of a generated position,
and no `PTD_ActsAs`: it stands for any account and is nobody's.

## In BloodHound

Loaded into BloodHound next to a directory collection that holds the application's users, the
export's `PTD_ActsAs` and `PTD_CanEscalateTo` edges join each account to the escalation by
`objectid`, so pathfinding reaches a document from whoever can sign in as a user who can raise it.
