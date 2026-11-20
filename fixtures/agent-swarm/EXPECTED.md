# What the analysis has to find in the agent-swarm fixture

The fixture is an agent platform whose sessions act for workload identities and
call tools. It is not real. It comes
in two: the same platform in OpenFGA under `openfga/` and in SpiceDB under
`spicedb/`, so one fixture shows the finding on both engines, and the SpiceDB one
shows the time bound OpenFGA cannot express.

## The platform

`openfga/` is the platform in OpenFGA: the model in `model.fga`, the store and its
checks in `store.fga.yaml`, the write model in `writes.yaml`, and the identity map
in `identities.yaml`, which says that a principal of the platform is a service
principal of Microsoft Entra ID, the one whose `objectid` is the subject's id.

`spicedb/` is the same platform in SpiceDB: `schema.zed`, its relationships and
checks in `validation.yaml`, and the same write model and identity map beside it. A
caller grant there may carry an expiration, which the write model leaves to the
writer.

The model is sound on its own: a session calls a tool it is registered to call, a
session acts for its members, and an observer may audit a tool without calling it.
The defect is in the write model: any session may register a sub-session it spawns
as a caller of any tool, so a sub-agent is delegated a tool the delegating session
never held. The planner is a workload identity that may audit the deploy tool and
not call it; the releaser may call it.

```
petard analyze fixtures/agent-swarm/openfga
petard export -out petard.json fixtures/agent-swarm/openfga
```

and the same under `spicedb/`.

## The finding

One escalation, `PTD-ZAN-006`. The planner spawns a sub-session and grants it the
deploy tool, so it raises `invoke` on a tool it could only audit. The write grants
to another a right the writer never held, a delegation that does not narrow.

It carries two aspects. The witness is a chain of two writes, spawn then grant, so
authority accumulates across the chain. On the SpiceDB twin the caller grant
carries an expiration the coalition sets or omits, so the grant does not lapse,
which is the stale authority and unbounded delegation of a non-human or agent
identity. OpenFGA has no expiration, so only the chain aspect shows there.

The attacker the analysis supposes reaches the same escalation, on a tool of a
generated position.

## The graph

| Edge | From | To |
|---|---|---|
| `PTD_CanEscalateTo`, `invoke` | the planner's principal | `TOOL:DEPLOY` |
| `PTD_ActsAs` | the `AZServicePrincipal` whose `objectid` is the planner's id | the planner's principal |
| `PTD_ActsAs` | the `AZServicePrincipal` whose `objectid` is the releaser's id | the releaser's principal |

The attacker the analysis supposes has its own `PTD_CanEscalateTo` and no
`PTD_ActsAs`: it stands for any account and is nobody's.

## In BloodHound

Loaded into BloodHound next to a directory collection that holds the planner's
account, the export's `PTD_ActsAs` and `PTD_CanEscalateTo` edges join the account
to the escalation by `objectid`, so pathfinding reaches the tool from whoever can
take over that account. Petard reads only `openfga/` or `spicedb/`, never the
directory collection.
