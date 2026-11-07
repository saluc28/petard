# The directory half of the agent-swarm walk

The agent platform under `openfga/` and `spicedb/` is analyzed by Petard. This
directory is the other half of the end-to-end path, the part a directory collector
ingests and BloodHound walks. Petard never reads it.

`azurehound.json` is a synthetic AzureHound collection, in the output format
AzureHound writes for BloodHound Community Edition (the `{"kind":...,"data":...}`
items under `data`, with `meta` naming the type and version). It names no real
tenant. It holds:

- the planner, a service principal, object id `11111111-1111-1111-1111-111111111111`
- the releaser, a service principal, object id `22222222-2222-2222-2222-222222222222`
- an attacker, a user, who is an owner of the planner's service principal

The attacker owning the planner's service principal is the take-over: an owner of a
service principal can add a secret or an owner to it and then sign in as it.
BloodHound turns ownership into a traversable Azure edge during post-processing, so
how it is named and which roles produce the same reach depends on the BloodHound
version, and it is confirmed there.

The object ids of the service principals are the ids of the planner and the
releaser in the Petard export, so once both are loaded the `PTD_ActsAs` edge joins
each service principal to its principal in the platform, and the path runs from the
attacker in the directory to `invoke` on the deploy tool in the platform.

The collection here is synthetic and its live walk is confirmed against a running
BloodHound, not by any test in this repository. `agent-swarm-entra-walk.md` in the
author's notes has the steps.
