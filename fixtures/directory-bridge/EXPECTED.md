# What the analysis has to find in the directory bridge fixture

The fixture is an application whose users sign in with Active Directory, and the directory they
sign in with. Neither is real.

`app/` is the application: a documents schema, its relationships and checks in `validation.yaml`,
the write model in `writes.yaml`, and the identity map in `identities.yaml`, which says that a user
of the application is the account of the directory whose `objectid` is the subject's id. The
subjects are the security identifiers of the accounts.

`ad/` is the directory, the domain `PETARD.TEST` as SharpHound writes it: three users, the group of
the domain users, and one defect, the help desk account allowed to reset Dev's password.

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

## The path

Loaded into BloodHound, the directory first and the export after it, the two join into one path.
On BloodHound CE v9.9.2, on 2026-11-07, the shortest path from the help desk account to the roadmap
over the traversable kinds was this one, and Dev's account kept the kinds it had, `Base` and `User`:

```
HELPDESK@PETARD.TEST --ForceChangePassword--> DEV@PETARD.TEST
                     --PTD_ActsAs--> USER:S-1-5-21-1000-2000-3000-1106
                     --PTD_CanEscalateTo--> DOCUMENT:ROADMAP
```

The help desk account resets Dev's password, signs in to the application as Dev, adds Dev as an
editor of the roadmap, and edits it. Neither side shows the whole path: the directory does not know
what Dev can do in the application, and the application does not know who can sign in as Dev.

Helpdesk is no subject of the application, and gets no `PTD_ActsAs` of its own.
