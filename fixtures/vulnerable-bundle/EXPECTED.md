# The vulnerable fixture: what the engine has to find, and what it must not

A policy with escalation built into it on purpose, next to the statement, in words, of what an
analysis has to produce from it and what it has to stay quiet about. It is the criterion the
patterns are measured against.

Every number here was executed and not estimated, with `opa 1.20.2`. Section 7 has the commands
to regenerate them.

---

## 1. Layout

```
fixtures/vulnerable-bundle/
├── data/                 tenants, users, projects, documents, settings: the concrete data
├── policy-v1/            the policy in Rego v1
├── policy-v0/            the same policy in Rego v0, identical semantics
├── inputs/               sample inputs, kept OUT of the -d directories
├── verify/               the measuring instrument, not part of the bundle
├── write-model.yaml      who can write what, the one part not derivable from the policy
├── pep.yaml              who sets each part of the request, the gateway in front of Quill
└── EXPECTED.md           this file
```

> ⚠️ `data/` and `policy-*/` go to `opa eval` as **two separate `-d`**. A single
> `-d fixtures/vulnerable-bundle` would mount the JSON under `data.data.*` and the policy would
> stop finding it, **with no error**: `allow` would quietly fall back on its `default`.

### The two variants are the same policy

Checked on the value of every rule the two variants produce under `data.quill`, against every
input under `inputs/`, which is 190 values over 11 inputs: no divergence between `policy-v1` and
`policy-v0`, with the rego package of OPA v1.20.2.
The same pair of trees is also the test of dual parsing:

| | v1 parser | v0 parser (`--v0-compatible`) |
|---|---|---|
| `policy-v1/` | passes | 19 errors |
| `policy-v0/` | 30 errors, "`if` keyword is required before rule body" | passes |

---

## 2. The central criterion, the 001 to 003 chain

`mallory` is an ordinary user: role `viewer`, no membership, no documents. They do one thing,
and it is writing one field of their own profile, from the self-service form:

```
data.users.mallory.profile.department :  "sales"  →  "platform"
```

Nothing else changes. No privileged access anywhere. Measured:

| | documents reached |
|---|---|
| mallory, before | **0** |
| mallory, after | **18**, the whole dataset |

The mechanism, and the reason two separate patterns are not enough:

1. `PTD-OPA-001` says **how the position is obtained**: `profile.department` is read by
   `is_member` to derive membership, and the subject writes it (`write-model.yaml`).
2. `PTD-OPA-003` says **what the position is worth**: `root` holds no document of its own, but
   it is an ancestor of all eighteen.

On their own they are two observations, *"this field is writable"* and *"this position is
powerful"*. Neither one is an attack path. Together they are a route, and the graph is the only
place where the two facts meet.

> **Expected edge:** `PTD_CanEscalateTo` from `PTD_Principal(mallory)` to `PTD_Principal(dave)`,
> or to the position `dave` occupies, with `via_write_path` pointing at the
> `data.users.{owner}.profile.department` entry of the write model, the endpoint
> (`PATCH /api/v1/me/profile`) beside it, and the three places to look: the two reads of the
> field and the call that follows the hierarchy.
>
> Apart from the one `PTD-OPA-006` finds (section 3), it is the only
> `PTD_CanEscalateTo` the fixture may produce. Any other one is a false positive
> and counts as one.

The value to write is not invented. The document `data.users.mallory.profile.department` is left
**unknown** and OPA is asked what is left of the decision. The answer, read as a count of
residual conditions:

| | ways the decision grants to `mallory` |
|---|---|
| as the data stands | **0** |
| with the document unknown | **55** |
| with the document unknown and `data.projects[_].parent` cut away | 19 |

The 36 ways that disappear when the hierarchy is cut are what ties the write to the position
`dave` holds and not to just any route. The gap between 55 and 18 is not meant to be
read: the 55 count the value of the field as well and the 18 do not, which is why the figure
reported is the difference between two measurements taken the same way and not the comparison of
two different ones.

The other four principals produce no edge, and each for the right reason: they already get
something out of that decision, so writing the field widens what they hold instead of letting
them in. Saying what a widening is worth needs a threshold, which is the open question 003
declares.

> ⚠️ The `via_chain` property, the `team* → div* → root` ancestry, is **not emitted**: it is
> exactly the reconstruction of the hierarchy that section 5 says not to do. The edge carries
> the **relation** instead, `data.projects[_].parent`, which is the thing to act on to close it.

---

## 3. Case and counter case, pattern by pattern

The rule: **every pattern has at least one case to find and at least one to stay quiet about.**
Without the second only recall gets measured, and precision matters as much.

### PTD-OPA-001, attribute self-write

| | where | expected |
|---|---|---|
| **case** | `authz.rego`, `allow` on `profile.department == "security"` | **finding**, the write model has the field as writable by the subject |
| **counter case** | `authz.rego`, `allow` on `"admin" in ...roles` | **nothing**, same record, but `roles` is written by a role, `role:admin` or `role:support`, and not by the subject as such |
| **counter case** | `authz.rego`, `is_member` on `user in ...members` | **nothing**, the requester is searched among the members, and the model says the project owner writes that list |

The first counter case is the most important one in the fixture: signal 2 fires on **both**,
because in each of them the reference is indexed by the subject. Only signal 3, against a write
model with field granularity, tells them apart. A model with record granularity would report
both.

The second is the other half of signal 2. The membership check picks the projects that hold the
requester instead of a record keyed on them, so the engine reports it under the lookups by value,
and the write model decides: `owner_of:{project}` writes that list, and an entry naming the
element instead, `data.projects.{project}.members.{member}` writable by `{member}`, would make it
a finding, because then anybody could join. With no write model at all it is a candidate, like
every other read the subject picks.

Measured, `mallory` deciding on `d-t11-1`:

```
profile.department = "sales"      (the fixture as it stands)   allow = false
profile.department = "security"                                allow = TRUE
profile.department = "platform"                                allow = TRUE   ← through the chain
```

The same writable field opens **two different routes** depending on the value: a direct grant
with `"security"`, transitive membership with `"platform"`.

### PTD-OPA-002, fail-open on data that is not there

| | where | expected |
|---|---|---|
| **case** | `tenant_policy.rego`, `denied_mfa` on `data.tenants[t].policy.require_mfa` | **finding**, `uncovered_keys: ["dolm"]` |
| **counter case** | `tenant_policy.rego`, `denied_suspended` on `data.tenants[t].status` | **nothing**, the path is there for every tenant |

Measured:

```
tenant keys                              2
policy.require_mfa present for           1   → uncovered: [dolm]
status present for                       2   → uncovered: []

same input, no MFA:
  tenant berq     allow = false     (the check applies)
  tenant dolm     allow = TRUE      (the check does not exist)
```

Same policy, same user, same request. Only the tenant changes.

The side that applies the check is not guessed from the names. The engine walks down from the
rules annotated `entrypoint: true` and records which paths run through a `not`, so `denied_mfa`
comes out on the denying side because `allow` negates it and not because it is called
`denied_*`.

The consequence is measured separately, with partial evaluation, and says the same thing in
another form: fixing `input.tenant` and leaving `input.mfa` unknown, for `berq` the decision
stays conditional on `input.mfa`, while for `dolm` it grants with nothing left to check. That
belongs in a test and not in the pattern, because it is the effect and not the signal.

### PTD-OPA-003, transitive grant

| | where | expected |
|---|---|---|
| **case** | `dave`, member of `root` and nothing else | **candidate**, `reach_direct: 0`, `reach_transitive: 18` |
| **counter case** | `alice`, member of the `team11` leaf | **nothing**, amplification of 1 |

Measured across every principal:

| principal | position | direct | transitive |
|---|---|---|---|
| `dave` | member of `root` | **0** | **18** |
| `alice` | member of `team11` | 3 | 3 |
| `carol` | member of `team21` | 3 | 3 |
| `bob` | *owner* of the projects, member of none | 0 | 0 |
| `mallory` | none | 0 | 0 |

`bob` is deliberate noise: owner of nearly every project, while the policy decides on `members`
and not on `owner`. An engine that confuses the two fields reports `bob`, and is wrong.

**`dave` stays a `candidate` and does not become a `finding`**, and not out of any doubt about
the data, which is measured. The pattern says *"whoever gets here gets everything underneath"*,
not *"X can get here"*. Only the chain with 001 produces the second statement.

The engine measures this a different way from the table above. That table counts the transitive
branch alone, with `verify/measure.rego`; the engine evaluates the **whole decision** twice, once
with the data as it stands and once with `data.projects[_].parent` cut away, and counts the
residual conditions, which are the ways the decision grants:

| principal | with the hierarchy | without | reported |
|---|---|---|---|
| `dave` | **18** | **0** | candidate |
| `alice` | 7 | 7 | no |
| `bob` | 13 | 13 | no |
| `carol` | 5 | 5 | no |
| `mallory` | 0 | 0 | no |

These numbers run higher than the ones above because they take in the owner route and the role
route as well, and because a document granted through two branches counts twice. It is an honest
count of what partial evaluation gives back, and the registry declares it as such. The row that
carries the most weight is `bob`: thirteen ways of granting, and no report, because without the
hierarchy all thirteen are still there. That is the false positive the registry named, and the
differential measurement closes it without needing a list of privileged roles.

### PTD-OPA-004, taint from an external source

| | where | expected |
|---|---|---|
| **case** | `enrichment.rego`, `allow` on `enrichment.body.clearance` | **finding**, plus a `PTD_Principal` node for `idp.petard-fixture.invalid` |
| **second case** | `risk.rego`, `allow_positive_side` on `enrichment.body.risk_score` | **finding**, plus a `PTD_Principal` node for `risk.petard-fixture.invalid` |
| **denying cases** | `risk.rego`, `allow_vulnerable`, `allow_defensive` and `allow_default_option`, through their `denied_*` rules | **a finding each**, on the same host |
| **counter case** | `enrichment.rego`, `audit_trace` | **nothing**, the result reaches no decision |

The counter case tells the taint apart from the mere presence of the builtin: both rules call
`http.send`, and only one of them contributes to a decision.

`allow_positive_side` grants access when the service answers with a low score, so whoever
controls that host grants access to anybody, which is 004 exactly. Section 4 lists that rule
among the ones not to report, but for the reason **005** gives, which is fail-closed with
respect to the source being down, and that reason says nothing about the content of the answer.

The three denying decisions reach the answer only under a `not`, and they are findings all the
same: whoever controls the host decides who the risk check stops, so the host decides in place of
the policy on that side too. The side a value lands on matters when the value is missing, which
is 005's question, and not when somebody picks it (`taxonomy-registry/README.md` section 3).
`allow_defensive` reads the answer in three places, the error and the score in one branch and the
error in the other, and it is one finding with three places to look.

Worth keeping in mind when writing other fixtures: **every rule 005 looks at is also a 004
case**, on either side, because both start from a call to an external source. It is not an
overlap to be removed, it is the same rule seen through two different questions, and the
registry has made a rule of it (`taxonomy-registry/README.md` section 3).

For this pattern the runtime outcome is irrelevant, because the finding is static. The hosts sit
under `.invalid` (RFC 2606) and never resolve, so the fixture is reproducible without a network
and without mocks.

### PTD-OPA-005, fail-open when the source is unavailable

Four cases, because the pattern has three ways of getting it wrong. Measured with the host
unreachable:

| rule | what | `allow` | expected |
|---|---|---|---|
| `allow_vulnerable` | consumed on the denying side, error never checked | **true** | **finding**, `mitigation_available: false` |
| `allow_defensive` | one branch consumes `enrichment.error` and denies | false | **nothing** |
| `allow_positive_side` | the same call on the side that **grants** | false | **nothing**, fail-closed, this is availability |
| `allow_default_option` | the same vulnerable form, **without** `raise_error: false` | **true** | **finding**, `mitigation_available: true` |

The last row is the **inverted** counter case, and it is the one that matters most: the engine
has to report it even though there is no `raise_error: false` in it. It is the only
way to prove the pattern is not a lint rule on that option dressed up as graph analysis. The
fail-open happens identically in both forms; the option only changes whether
`strict-builtin-errors` would still have any effect.

So both forms get reported, and what separates them is only the sentence about mitigation. A
lint rule on `raise_error: false` would have reported the wrong one of the two.

### PTD-OPA-006, a write one decision allows and another decision grants on

Two decisions, each of them sound on its own: `admin.rego` lets support staff assign `viewer` and
`editor` to anybody, themselves included, and `publish.rego` lets editors publish. `carol` holds
`support`. The engine emits the edge below and stays quiet about the counter case.

| | where | expected |
|---|---|---|
| **case** | `admin.rego` lets `carol` write `editor` into her own `roles`; `publish.rego` grants `publish` on `"editor" in ...roles` | **finding**, `PTD_CanEscalateTo` from `carol` to `alice`, who holds `editor` |
| **counter case** | `publish.rego`, `withdraw` on `"admin" in ...roles` | **nothing**, the assignment decision does not let support write `admin` |

Measured with `data.quill.verify.split_grant`:

```
carol publishes, roles as they stand            publish.allow = false
carol assigns herself editor                    admin.allow   = TRUE
carol assigns herself admin                     admin.allow   = false
carol publishes, roles ["support", "editor"]    publish.allow = TRUE
carol withdraws, roles ["support", "editor"]    publish.allow = false
```

The counter case is what keeps the pattern honest. A check that stopped at "the assignment
decision lets carol write the field the publishing decision reads" would report the withdraw
branch too. What separates the two is the value: the write is allowed for `editor` and not for
`admin`, and only the first opens a branch.

`PTD-OPA-001` stays silent on the same field, and that is right: `roles` is written by a role,
`role:support`, and not by the subject as such, which is the line between the two patterns.

The membership the fixture also holds, `is_member` searching `data.projects[_].members` for the
requester, is a second counter case here: the pattern reads a search as a join, and a join it can
measure needs a writer with a decision behind them. That list is written by `owner_of:{project}`,
a way of finding somebody rather than an endpoint with a rule of the bundle governing it, so
there is nothing to ask and nothing is reported.

### PTD-OPA-007, a check that stops applying on the empty case

`review.rego` approves a merge when every reviewer has approved. With no reviewers the `every` is
vacuously true and the merge goes through, reviewed by nobody. The engine reports the case,
`allow_unguarded`, and stays quiet about the counter case.

| | where | expected |
|---|---|---|
| **case** | `review.rego`, `allow_unguarded` on `every review in input.reviews` | **finding**, the domain can be empty and nothing guards it |
| **counter case** | `review.rego`, `allow_guarded`, the same every behind `count(input.reviews) > 0` | **nothing**, the guard denies the empty case |

Measured with `data.quill.verify.empty_every`:

```
allow_unguarded, reviews []            allow = TRUE    ← fail-open, nobody reviewed
allow_unguarded, reviews [rejected]    allow = false
allow_unguarded, reviews [approved]    allow = true
allow_guarded,   reviews []            allow = false   ← the guard denies
allow_guarded,   reviews [approved]    allow = true
```

The counter case is what keeps the pattern from being a lint on the presence of an `every`: the
same quantifier over the same domain, and only the guard tells the fail-open from the safe form.

### PTD-OPA-008, a document every request shares decides for anybody

`platform.rego` opens a reading room to whoever asks while `data.settings.reading_room.open` says
so. That document is the same whatever the request, so whoever writes it decides for everybody at
once, and the write model says that is whatever gets merged into the configuration repository.
The console setting next to it is just as global and is the counter case.

| | where | expected |
|---|---|---|
| **case** | `platform.rego`, `allow_reading_room` on `data.settings.reading_room.open` | **finding**, the setting decides for somebody no document names, and `system:config-sync` writes it |
| **counter case** | `platform.rego`, `allow_console` on `data.settings.console.enabled`, next to `"admin" in ...roles` | **nothing**, somebody with no record gets nothing whatever the setting says |

Measured with `data.quill.verify.global_switch`, where `petard:nobody` is a principal no document
names:

```
reading room, petard:nobody, as it stands     allow = false
reading room, petard:nobody, room opened      allow = TRUE   ← one write, anybody
console,      petard:nobody, as it stands     allow = false
console,      petard:nobody, switched off     allow = false  ← the setting does not reach them
console,      bob,           as it stands     allow = true
console,      bob,           switched off     allow = false  ← it decides for the admins
```

The counter case is what keeps the pattern from being a lint on constant paths. Both decisions
read a document every request shares, and a linter sees the same thing in both. Only the second
wants the requester's own record before the setting matters, and that is what measuring for
somebody no document names finds.

### PTD-OPA-009, a request that says it is exempt

`tenant_policy.rego` refuses an export without a second factor, except for the nightly export
job, which says in the body of its request that it is the scheduled export. The policy reads
`input.scheduled` and `input.mfa` the same way, in the same rule, and only `pep.yaml`, the
declaration of the gateway, tells them apart: the gateway sets `mfa` from the session, and
`scheduled` is in the body with everything else the caller asks for.

| | where | expected |
|---|---|---|
| **case** | `tenant_policy.rego`, `allow_export`, `not input.scheduled` in `export_needs_mfa` | **finding**, the caller sets it, at confidence A |
| **counter case** | the same rule, `not input.mfa` | **nothing**, the gateway sets it |
| **counter case** | `tenant_policy.rego`, `allow`, `not input.mfa` in `denied_mfa` | **nothing**, for the same reason |

Measured with `data.quill.verify.self_asserted`:

```
export by mallory, no second factor               allow_export = false
the same, saying it is the scheduled export       allow_export = TRUE   ← the body says so
the same, with a second factor                    allow_export = true
```

Without `-pep` the pattern does not run, and the report says so. In a policy on a request the
caller writes whole, meeting a condition of a rule that refuses reads the same way as claiming an
exemption, and only the declaration says which parts are the caller's to assert.

---

## 4. What the engine must not report

Every row here is a false positive if it shows up in the output **of the pattern named in the
middle column**. The column is doing real work: row 8 is a false positive for one pattern and a
legitimate finding for another.

| # | Construct | For which pattern | Why it is not a finding |
|---|---|---|---|
| 1 | `allow if input.user == ...owner` | all | the healthy case: no pattern touches it |
| 2 | `"admin" in ...roles` | 001 | a field the subject does not write |
| 3 | `denied_suspended` | 002 | the path is there for every key |
| 4 | `alice`, `carol` in a leaf | 003 | amplification of 1 |
| 5 | `bob` as `owner` | 003 | the policy does not decide on `owner` |
| 6 | `audit_trace` | 004 | an `http.send` that reaches no decision |
| 7 | `allow_defensive` | 005 | the error is handled. **For 004 it is a finding**, because whoever answers decides the denial |
| 8 | `allow_positive_side` | 005 | fail-closed, this is availability. **For 004 it is a finding**, because the content of the answer grants |
| 9 | `data.users.{owner}.profile.*` | 001 | writable, but no decision reads it |
| 10 | `withdraw` on `"admin" in ...roles` | 006 | support cannot assign `admin`, so no allowed write reaches the branch |
| 11 | `allow_guarded` | 007 | `count(input.reviews) > 0` denies the empty case, so the every never goes vacuous |
| 12 | `user in ...members` | 001 | the members are written by the project owner, and joining is not declared |
| 13 | `allow_console` | 008 | the setting is just as global, but it only decides for somebody with a record |
| 14 | `not input.mfa`, in `allow_export` and in `allow` | 009 | the gateway sets it from the session |

Expected precision, with the gateway declared: **two `PTD_CanEscalateTo`** (mallory and carol),
**fourteen findings and one candidate**, and none of the rows above under the pattern they belong
to.

The fourteen: one from 001, one from 002, five from 004 (section 3), two from 005, one from 007 on
`allow_unguarded`, mallory's escalation, which comes out under the id of 003 because that is where
the registry says a candidate turns into a finding, carol's escalation under 006, the reading room
under 008, and the scheduled export under 009. The two escalations are the two findings that are also `PTD_CanEscalateTo`
edges.

---

## 5. A trap in `graph.reachable`, and what it forces on the engine

Checked on 2026-08-03 with `opa 1.19.0`:

> **`graph.reachable` puts a node in the result only if that node is a key of the graph
> object.** A node that is reachable but has no entry of its own never shows up, not even when
> it is the node the walk starts from.

```
graph.reachable({"a":["b"],"b":["c"]},          {"a"})  →  ["a","b"]      ← "c" is missing
graph.reachable({"a":["b"],"b":["c"],"c":[]},   {"a"})  →  ["a","b","c"]
graph.reachable({"a":["b"],"b":["c"]},          {"c"})  →  []
```

In a `child → parent` hierarchy the **root is exactly a node with no entry of its own**. Written
the way that comes naturally, the adjacency list leaves `root` out and the policy climbs one
level short of where it should **without raising anything**. The fixture uses a comprehension
that gives `[]` to the nodes with no parent.

What the trap forces on the engine matters more than the trap. Signal 3 of `PTD-OPA-003` says to
build the relation from the concrete data and work out the resources reached. An engine that
computes that with an implementation of its own gets **mathematical** reachability, and on an
incomplete adjacency list that **is not what the policy actually grants**.

On this very fixture, with the naive form of `parent_of`, such an engine would say *"dave reaches
18 documents"* while the real policy grants **0**. A systematic false positive, on a pattern that
emits a traversable edge.

The engine replicates no semantics at all. It evaluates the decision partially against this data
(`internal/opaengine/partial.go`) and counts the residual conditions, which are the documents
granted. Having no idea of its own about what `graph.reachable` means, it cannot have a wrong
one.

Measured by `TestResidualsFollowTheConstructThePolicyUses`, which loads this fixture and a copy
with the naive form of `parent_of`:

| principal | the fixture hierarchy | the naive hierarchy |
|---|---|---|
| `dave`, member of `root` | **18** | **0** |
| `alice`, member of the `team11` leaf | 7 | 7 |

`alice` is the control, and the control is needed: if that count dropped too, the test would be
measuring a broken policy instead of a missing root. The 7 is more than the 3 of section 3
because this counts the whole decision, where the owner route adds to the membership one, while
section 3 measures the transitive branch alone with `verify/measure.rego`.

The same property is checked one level up, on the pattern that rests on it. `PTD-OPA-003`
measures a position by cutting the relation out of the data instead of walking it, and on a
policy whose adjacency list is written the naive way it reports nothing, because there is
nothing to report (`TestTransitiveGrantFollowsTheConstructThePolicyUses`). A graph walk of our
own would report in both cases.

---

## 5a. The fixture lints clean, and that is the point

The registry rests on one claim: **if `regal` can find it by reading a file, it is not a
pattern.**

Run on 2026-09-24 with **regal v0.42.0** (which embeds OPA 1.18.2, irrelevant here, but worth
saying):

```
regal lint fixtures/vulnerable-bundle/policy-v1   →  8 files linted. No violations found.
```

The rule categories were confirmed **at the source**, by listing the directories in the pinned
version rather than reading them off a documentation page: `bugs`, `custom`, `idiomatic`,
`imports`, `performance`, `style`, `testing`. **No `security`.**

Two rules are turned off in `.regal/config.yaml`, `directory-package-mismatch` and
`unresolved-reference`, each with its reason written next to it. Neither can apply to a fixture
that is laid out by syntax variant and that reads data the lint does not see.

That the fixture lints clean is not cosmetic. The claim the project makes is that **the code is
correct and idiomatic and the defect is somewhere else**: in the data somebody can write, in the
key that is missing, in the source that does not answer. A fixture the linter complains about
would weaken exactly that claim.

### The entrypoint annotations, and what they change

The decisions carry:

```rego
# METADATA
# scope: document
# title: Document access decision
# entrypoint: true
default allow := false
```

Readable with `opa inspect -a`. They serve three purposes:

1. **They make the most fragile signal in the registry explicit.** `PTD-OPA-002` and
   `PTD-OPA-005` both declare *"how do you establish which side applies the check"* as an open
   question, because the answer depends on the PEP. With the annotation it is declared rather
   than inferred.
2. They exercise annotation reading, which `ast` supports natively.
3. They give the engine its starting set for `compiler.Graph`: which rules to walk down from.

There are no `schemas:`, and that is deliberate: they would raise the confidence of a finding
artificially. The realistic case is that nobody writes them.

**Fourteen decisions are annotated**, among them all four rules of `risk.rego`, the two halves
of the split grant, `admin` and `publish`, the guarded and unguarded merge decisions of `review`,
the reading room and the console of `platform`, and the export of `tenant_policy`. A rule
without the annotation is a rule the engine never looks at, and leaving the three counter cases
of `risk.rego` unannotated would break the fixture in two directions at once: *"the engine must
not report `allow_defensive`"* would be satisfied for the wrong reason, because that rule would
not exist as far as the analysis is concerned, and *"the engine must report
`allow_default_option`"*, the inverted counter case and the most important of the four, would not
be satisfiable at all. They are four distinct decisions that the PEP consumes the same way, which
is why they have four different names.

## 5b. The chain needs interprocedural analysis

The 001 to 003 chain runs through a function:

```rego
is_member(user, proj) if data.users[user].profile.department == data.projects[proj].department
```

`user` is a **formal parameter**. In the compiled form it becomes `__local0__`, and **nothing
inside the function body binds it to a term**: the binding lives at the call site,
`is_member(input.user, anc)`, which is in the body of another rule.

A resolver that works on one `ast.Body` at a time stops at the formal parameter on that
reference, and cannot say it comes from `input`.

> **Consequence:** without interprocedural analysis the engine **does not recognize this
> fixture's chain**, and fails the central criterion of section 2, not through a defect in the
> fixture but through a hole in the resolver.
>
> The fixture is written this way on purpose and stays this way: using a function is the normal
> way to write that policy, and a fixture that avoided functions to please the resolver would
> measure nothing.

The walk that closes the hole is in `internal/opaengine/calls.go`. It answers where a formal
parameter comes from by looking at what the callers pass in that position, aggregated over every
call site, and a path that reaches `input` wins over one that does not.

## 6. Write-model coverage

The number is reported and not left implied. What is counted: **distinct** paths rooted at
`data.`, read from the body of a rule that contributes to a decision, normalized to the field
path with the index as a capture.

| path read by the decisions | covered |
|---|---|
| `data.users.{u}.profile.department` | ✅ writable by `{owner}` |
| `data.users.{u}.roles` | ✅ writable by `role:admin` and `role:support` |
| `data.projects.{p}.members` | ✅ writable by `owner_of:{project}` |
| `data.tenants.{t}.policy.require_mfa` | ✅ written by `system:provisioning` |
| `data.tenants.{t}.status` | ❌ |
| `data.documents.{d}.owner` | ❌ |
| `data.documents.{d}.project` | ❌ |
| `data.projects.{p}.department` | ❌ |
| `data.projects.{p}.parent` | ❌ |
| `data.settings.reading_room.open` | ✅ written by `system:config-sync` |
| `data.settings.console.enabled` | ✅ written by `system:config-sync` |

```
data.* paths read by the decisions:  11
covered by the write model:           6  (54%)
not covered:                          5
```

A low number, and it is left low: **54% is realistic**, and a fixture that declared 100% would
teach the engine to run only against complete models, which do not exist in practice.

Two of the uncovered paths are deliberate rather than forgotten:

- `data.projects.{p}.department`, which if it were declared writable by the subject would open a
  **second** route into the same chain, and the fixture would measure two paths instead of one.
- `data.projects.{p}.parent`, because being able to restructure the hierarchy is a different
  capability and probably a pattern of its own.

The world is closed, so uncovered means *not writable*: these are known false negatives, which is
the right direction to be wrong in.

> Note for the engine: `data.documents.{d}.project` is read **through an alias**,
> `doc := data.documents[input.doc]` and then `doc.project` in a later expression. It is not
> visible to anything looking for whole references inside a single expression: it needs binding
> resolution. It is the path that exercises that ability on the fixture.

---

## 7. How to regenerate the numbers

The measurements live in `verify/measure.rego`, which is **not part of the bundle**: load it in
addition to the policy, never in place of it. The strings live in the rules rather than in the
queries, because on Windows PowerShell quoting breaks queries passed as an argument to
`opa eval`.

```bash
opa eval -d fixtures/vulnerable-bundle/data -d fixtures/vulnerable-bundle/policy-v1 -d fixtures/vulnerable-bundle/verify -f pretty 'data.quill.verify.reach'
```

```bash
opa eval -d fixtures/vulnerable-bundle/data -d fixtures/vulnerable-bundle/policy-v1 -d fixtures/vulnerable-bundle/verify -f pretty 'data.quill.verify.coverage'
```

```bash
opa eval -d fixtures/vulnerable-bundle/data -d fixtures/vulnerable-bundle/policy-v1 -d fixtures/vulnerable-bundle/verify -f raw 'data.quill.verify.chain_after'
```

```bash
opa eval -d fixtures/vulnerable-bundle/data -d fixtures/vulnerable-bundle/policy-v1 -d fixtures/vulnerable-bundle/verify -f pretty 'data.quill.verify.split_grant'
```

```bash
opa eval -d fixtures/vulnerable-bundle/data -d fixtures/vulnerable-bundle/policy-v1 -d fixtures/vulnerable-bundle/verify -f pretty 'data.quill.verify.global_switch'
```

```bash
opa eval -d fixtures/vulnerable-bundle/data -d fixtures/vulnerable-bundle/policy-v1 -d fixtures/vulnerable-bundle/verify -f pretty 'data.quill.verify.self_asserted'
```

Dual parsing, where the first has to pass and the second has to fail:

```bash
opa check --v0-compatible fixtures/vulnerable-bundle/policy-v0 && opa check fixtures/vulnerable-bundle/policy-v0
```
