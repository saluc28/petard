# Taxonomy registry

> The taxonomy of abuse patterns. **This is the project.** Reading Rego is largely solved by the
> official libraries; the part that is not solved is which of those reads matter, and that is
> what these files say.
>
> Versioned data, not code. The engine reads these files and holds no hardcoded pattern.

---

## 1. Why this registry exists

Two checks say what is not covered elsewhere.

**`regal` has no `security` category.** Its categories are `bugs`, `custom`, `idiomatic`,
`imports`, `performance`, `style`, `testing`, confirmed at the source of v0.42.0 by listing the
rule directories rather than reading them off a documentation page. The official linter of the
OPA ecosystem, written by the maintainers, has no notion of "this Rego is dangerous". And
`regal lint` on the fixture, which holds the case and the counter case of all ten patterns,
reports zero violations.

**OPA's security documentation is about the server, not about the policy.** It covers TLS,
binding to localhost, credentials that should not be passed on a command line, and the
authorization policy of the API itself. It says how to secure the *engine*. It says nothing
about how to reason about the attack surface of **policy plus data**.

So there is guidance on how to *write* clean Rego and on how to *expose* OPA safely, and none on
who can make a policy say what they want by writing the data it reads. That is what this
registry is for.

---

## 2. The rule that decides what goes in: the linter test

> **If `regal` can find it by reading a file, it is not a pattern of this registry. It is a lint
> rule.**

This is not a rule of taste. It is what keeps the project from becoming a worse version of a
linter that already exists. regal's `bugs` category holds, among others, `impossible-not`,
`constant-condition`, `rule-assigns-default`, `not-equals-in-loop` and
`redundant-existence-check`: real defects, some of them with security consequences, and all of
them **visible in one file**.

What Petard adds is what needs the **graph**: crossing the line between whoever decides and
whoever writes the data. A linter sees one file. Petard sees the policy, the data and who writes
it, together.

Every pattern carries a mandatory **`not_a_lint_rule`** field that has to explain, in one
sentence, why a linter cannot find it. **If you cannot write that sentence, the pattern does not
go in.**

---

## 3. A two level structure

An **abstract category**, independent of the engine, and one or more **concrete instances**.

```
Abstract category           ATTR-SELF-WRITE
   "the subject writes data the policy reads to decide about them"
        │
        ├── OPA instance    PTD-OPA-001   (how it shows up in Rego)
        └── Cedar instance  PTD-CED-001   (same category, new column)
```

A second engine is added as a **new instance on the same category**, not as a refactor. If a
category does not exist in some engine, that gets declared and explained: it is information, not
a hole.

### More than one instance per engine, when the causes are disjoint

`PTD-OPA-002` and `PTD-OPA-005` are **two OPA instances of the same category**,
`FAIL-OPEN-ON-ABSENCE`: in both, a check stops applying because the data holding it up is not
there. But the absence has two disjoint causes, one in the data (persistent, visible in a
snapshot) and one in the network (transient, visible in no snapshot), with different
preconditions, different signals and different engine capabilities: 002 requires
`concrete-data`, 005 does not.

```
Abstract category           FAIL-OPEN-ON-ABSENCE
        │
        ├── OPA instance    PTD-OPA-002   absence in the data     (persistent)
        └── OPA instance    PTD-OPA-005   absence from the network (transient)
```

The rule: **two instances on the same engine are justified when the cause is disjoint and the
signals do not overlap.** If the signals overlap it is one pattern written twice, and it gets
merged. The practical test: if the two `detection.requires` are identical and the `signals`
differ only in their prose, they are not two patterns.

### Two patterns on the same rule do not silence each other

One rule of the fixture, `quill.risk.allow_positive_side`, is a counter case of `PTD-OPA-005`,
because the source being unavailable makes it fail closed, and a finding of `PTD-OPA-004`,
because the content of the response grants access. Different categories, different claims, both
true.

**The rule: a pattern does not look at what the others say.** A result is identified by the pair
of pattern and site, not by the site. It is also how the linter of the ecosystem behaves,
checked by running it: `regal` v0.42.0 on a line that violates two rules reports two distinct
violations, one per rule.

It is written here rather than left to good sense because the alternative has a consequence that
does not show up straight away: suppressing the finding of 004 because 005 is quiet on that rule
would create a dependency between patterns, and from that moment the order in which the engine
applies them would change the output. The relation between patterns is declared in `related`,
where it serves whoever is reading, and it does not filter results.

### The side of a decision matters for absence, not for control

A value can reach a decision on the side that grants or on the side that denies. For some
patterns that side is the finding, and for others it does not count. The side is the parity of
the negations between the decision and the value, the one on the read included, so two take each
other back: an exemption a violation asks not to hold, in a decision that asks for no violation,
is on the side that grants.

It is the finding when the value is **missing**, because then the outcome is fixed and only the
side is left to decide it. An undefined read on the side that denies silences the check and the
request goes through, which is what `PTD-OPA-002` and `PTD-OPA-005` report, while the same read
on the side that grants fails closed. An empty collection makes an `every` true, which grants on
the side that grants, and that is `PTD-OPA-007`.

It does not count when somebody **controls** the value, because they pick it. A field read to
deny is a field its writer can clear, and a source consulted to deny is a source that decides
who is not denied. `PTD-OPA-001`, `PTD-OPA-004` and `PTD-OPA-008` report both sides for that
reason: a suspension the subject writes is one the subject lifts, a blocklist served from outside
is decided by whoever serves it, and a setting that shuts a door on everybody is one its writer
opens for everybody. `PTD-OPA-006` stays on the side that grants, and that is a limit of
how it measures rather than an exception to the rule: it writes the values a decision compares
with, and on the side that denies those are the values that deny, so its file declares the gap.

It is how CWE-807, "Reliance on Untrusted Inputs in a Security Decision", reads: a protection
an untrusted actor bypasses by changing an input, with no line drawn between inputs that grant
and inputs that deny. CodeQL's `java/user-controlled-bypass`, tagged with it, reports a
sensitive call that may not run depending on a user-controlled condition, which is the denying
side exactly (checked at `codeql-cli/v2.27.0`).

### A request carries identities, and a document can be picked by value

Two assumptions are easy to make about a request and wrong about most of them.

**The first is that a request names one principal.** Chef Automate sends the user and every team
the user is in, in one list, and the policy ranges over it
(`input.subjects`, built at `components/authz-service/engine/opa/opa.go:252` at `61ca031`).
Kubernetes does the same without calling it a list: a role binding applies when one of its
subjects equals the name **or one of the groups** of whoever is asking
(`appliesTo` and `appliesToUser`, `pkg/registry/rbac/validation/rule.go:263` at `v1.37.0`).

So a subject the decisions range over is read as one element of the list, `input.subjects[_]`,
and a request that names one principal carries a list holding that principal alone, which is how
Chef's own tests ask (`with input.subjects as ["z"]` in `authz_test.rego`). What somebody holds
together with the teams an authenticator would add is the union of those measurements, and which
teams go with which user is not in the policy.

**The second is that a document is picked by its key.** `data.users[input.user].tier` is one way,
and searching a collection for a value is the other. OPA compiles the second into a database
query and ships an example that does exactly that: `post.author == input.subject.user` over
`data.posts` becomes a `WHERE` clause (`data_filter_example` in `open-policy-agent/contrib` at
`90f7ca9`). A value compared with the request selects documents, the same way an index does.

The engine therefore records, on each read, the parts of the request it is compared with, and
counts it as a lookup **only when the segment holding the value ranges over its collection**.
`data.documents[input.doc].owner == input.user` is not one: that document is the one the request
asks about, and checking its owner is a check on a resource, not a search for the requester.

For `PTD-OPA-001` the write model is then asked about the **element**:
`data.teams.{team}.members.{member}` writable by `{member}` says anybody can add themselves,
while an entry on the list alone says who writes the list and nothing about who may join it.
BloodHound keeps the two apart for the same reason, `AddSelf` next to `AddMember`
(`packages/cue/bh/ad/ad.cue:1337` and `1427` at `v9.7.0`).

`PTD-OPA-006` reads the same search from the other side: there the writer is not the subject but
an endpoint with a decision behind it, and joining is what that decision authorizes. What varies
is then the collection rather than the value, since the value added is the subject.

A lookup marks the read that holds the value and not the other fields of the same element, but a
grant on one of those other fields is the third shape of `PTD-OPA-006` below, so a role read next
to a matched user is reached after all. One limit stays a false negative rather than noise: a
match on a prefix, as Chef's `team:*` members are, is not a lookup by value. The chain of
`PTD-OPA-001` into `PTD-OPA-003` leaves a join alone as well: it writes a document of the
subject's own and lets partial evaluation find the value, and an element added to a list is
neither.

### An element a list names the subject in is the subject's record

A list of records, each with a field that says which principal it is about, is a document keyed by
that field. A grant that reads `data.members[i].role` where `data.members[i].user` is the
requester reads the role of one document, the requester's, found by matching the field that names
them rather than by a key. Changing that role is writing a field of the subject's own record, the
value form of `PTD-OPA-006`, and the only thing new is how the record is located: by a matched
field instead of by a segment of the path. So the engine resolves the element against the concrete
data, and its finding comes out under `PTD-OPA-006` like the other two shapes.

It is not a fourth pattern, because the cause is the split grant already there: one decision
governs who may set the field, another grants on it, and the second instance the registry keeps is
for a disjoint cause, not a new shape of the same one. BloodHound draws a membership as an edge
and a role on it as a property of that edge, kept apart from the member; here there is no type to
lean on, so the engine reads the record's field the way the policy does, straight from the list,
and tells one member's record from another by the field that names them.

The values the write could set the field to are read off the data, the roles other members hold,
rather than off the residual, because the grant reaches the field through a lookup,
`roles[member.role] >= 3`, and a lookup leaves no constant to compare against. The write is a step
up only where the decision that authorizes it asks for less than the one that grants: an editor
who may assign roles setting their own to owner, while removing the team needs owner. Where the
two thresholds meet, no lower privilege reaches the value, and the file carries that counter case.

### A declared subject is level A, whoever declares it

The `confidence` of a finding says how the subject was found, and a declaration is worth more
than any way of recognizing one. The author of a policy can declare the shape of the request with
a `METADATA` schemas annotation. Whoever deploys the policy can declare the subject with
`-subject`, because which field names the requester is decided where the request is built, and
the policy only reads it.
AWX sends the user who launched a job under `created_by`, next to the teams and the superuser
flag (`awx/main/tasks/policy.py:49` and `194` at `bbda905`), where no recognizer looks.

Both declarations are level A. OPA takes a declaration of its input from either place too: it
checks the input against a schema given in an annotation or on the command line
(`opa eval --schema`, `cmd/eval.go:289` at `v1.20.2`). A declared subject that no decision reads
is refused, the way an entrypoint that names no rule is.

### Which way a decision answers is declared too

Whether a decision grants or refuses is up to the point that enforces it, and a policy has no way
to say it. Gatekeeper queries `violation` on every constraint template
(`data.template.violation[r]`, `frameworks/constraint/pkg/client/drivers/rego/rego.go:34` at
`241c4a079fc8`, the revision Gatekeeper `v3.21.0` vendors) and refuses the request when a result
carries the deny action (`pkg/webhook/policy.go:206` at `v3.21.0`). conftest counts every element
of a rule named `deny` or `violation`, with a suffix or without, as a failure
(`policy/engine.go:48` and `390` at `v0.70.0`). OPA's annotations mark an entrypoint and carry no
direction (`v1/ast/annotations.go:28` at `v1.20.2`).

So a decision that refuses is declared, `-deny-entrypoint k8sallowedrepos/violation`, like the
decision itself and the subject, and never inferred from a name: a rule called `deny` can just as
well be one an `allow` negates. The engine reads it as its own negation, a set asked to be empty
or a rule asked not to hold, so `violation` declared to deny and `allow if count(violation) == 0`
declared to grant put every value on the same side.

What partial evaluation leaves of a decision that denies are the ways to be refused. The patterns
that measure access with it, `PTD-OPA-003` and `PTD-OPA-006`, leave such a decision out, and so
do the capability edges of the graph: an edge somebody walks is a way in, and the complement of a
residual condition is a negation no edge can carry.

### An escalation edge goes towards a gain, read by content

A principal who can add themselves to a policy, or write a value a decision grants on, reaches
somebody else's position only when that position grants a request they could not already make.
Counting how many ways a decision has of granting cannot tell that: joining a policy that grants
one action adds a way to a principal who already grants every action, and the count rises while
nothing new is reached.

So the edge is drawn by reading what each side grants, not by counting it. Partial evaluation
leaves each way of granting as a condition on the request, and each condition reads as the
constraint it puts on the fields of the request: a value, a membership, a prefix from a wildcard
match, or nothing, which is any value. One grant covers another when it is at least as permissive
on every field, and a principal gains only when the position they reach grants a request none of
theirs covers.

When two positions can each add the other, the edge goes to the one that gains and not back. When
a condition constrains the request in a way the comparison cannot read, a builtin it does not
model or a truth test, the gain cannot be proven, and the match is a candidate rather than a
finding: an edge somebody walks is a claim, and a claim that cannot be proven is not made.

BloodHound draws the capability edge and leaves whether it gains anything to Tier Zero and the
pathfinding towards it. This registry marks no such target, so the edge carries the judgement
instead.

---

## 4. Format

**One YAML file per instance.** No accompanying `.md`: the prose lives in the fields as block
scalars, so there are never two documents about the same pattern drifting apart.

```
taxonomy-registry/
├── README.md          this file
├── SCHEMA.md          the fields, v1
├── opa/
│   └── PTD-OPA-001-attribute-self-write.yaml
└── cedar/             (not yet)
```

Every file carries `schema_version: 1` from the first day. The schema is versioned because it
will change: this is data, and data outlives the code that reads it.

---

## 5. Discipline

**A pattern is not a description of a risk. It is an executable specification.**

If the `detection` field does not say which pass of the engine produces which signal, the
pattern is not finished, it is a note. The difference between this registry and a blog post
about the risks of ABAC is entirely there.

**False positives get declared.** Precision is measured, not only recall: a pattern that finds
everything and produces noise is unusable in an assessment. Every file lists the conditions
where the signal fires with no abuse behind it, and what it would take to tell them apart.

**Nobody writes "privilege escalation" lightly.** Only a claim that names who can reach what
deserves the phrase, and that needs the write path model. A pattern that stops short produces a
**candidate**, not a finding, and the `graph.emits` field says which of the two.

**Every pattern has a fixture.** Without a case in the vulnerable bundle that the engine has to
find, the pattern is not verifiable and stays `status: draft`.

---

## 6. Status

| ID | Category | Engine | Emits | Conf. | Status |
|---|---|---|---|---|---|
| `PTD-OPA-001` | ATTR-SELF-WRITE | opa | finding | C | `verified`, with the case and the counter case separated on the fixture |
| `PTD-OPA-002` | FAIL-OPEN-ON-ABSENCE | opa | finding | B | `verified`, the one that emits findings on its own, with no write model |
| `PTD-OPA-003` | TRANSITIVE-GRANT | opa | candidate | B | `verified`, and it chains with 001, which is where a route comes from |
| `PTD-OPA-004` | EXTERNAL-SOURCE-TAINT | opa | finding | A | `verified`, and the one that exercises taint |
| `PTD-OPA-005` | FAIL-OPEN-ON-ABSENCE | opa | finding | B | `verified`, and it needs no attacker and nothing wrong beforehand: a slow endpoint is enough |
| `PTD-OPA-006` | SPLIT-GRANT | opa | finding | C | `verified`, the second edge that means escalation, from a write a decision authorizes rather than a position: a value in the subject's record, the subject added to a collection, or a field of a record a list names them in |
| `PTD-OPA-007` | FAIL-OPEN-ON-ABSENCE | opa | finding | B | `verified`, the third instance of the category: an `every` over a domain the request can empty |
| `PTD-OPA-008` | GLOBAL-SWITCH | opa | finding | C | `verified`, a document every request shares, and the question asked about somebody no document names |
| `PTD-OPA-009` | SELF-ASSERTED-EXEMPTION | opa | finding | A | `implemented`, the first to read the request instead of the data, for a check the caller lifts by writing a part of it |
| `PTD-OPA-010` | UNCONTROLLED-IDENTIFIER | opa | finding | A | `implemented`, a grant on a group name an issuer hands over, where whoever creates or renames the group picks the name |

Between them the ten exercise `binding-resolution`, `concrete-data`, `enforcement-point`,
`rule-graph` and `taint`. 007 adds no new capability, only a new construct within `rule-graph`,
008 asks a new question of `concrete-data`, what a decision gives a principal the data knows
nothing about, 009 needs the declaration of the enforcement point, which says who sets each part
of the request, and 010 asks the same declaration what kind of value an issuer puts there.

`partial-eval` is not among the capabilities a pattern requires. Partial evaluation is the tool
the engine measures with, and in 002 it is how the fixture checks the **consequence** of a
finding. The distinction is worth keeping: `detection.requires` says what it takes to **find** a
defect, not what it takes to show its effect.

### The two escalations, and what holds them up

Two claims in the registry deserve the words privilege escalation, and each is a
`PTD_CanEscalateTo` between two principals. The first is the chain from `PTD-OPA-001` to
`PTD-OPA-003`, closed on the fixture as one edge from `mallory` to `dave`, with the path to write
and the endpoint to write it through. It lives in `internal/taxonomy/escalation.go`, which is not
a pattern of its own but the place where two of them meet, and that is why its result comes out
under the id of `PTD-OPA-003`, where the registry says a candidate becomes a finding. The second
is `PTD-OPA-006`, one edge from `carol` to `alice`: a value one decision lets her write, and
another decision grants on.

What holds both up is **the write model**. Without one, 001 produces a candidate and the chain
stays quiet, 006 has no decision behind the write to ask, and everything else is still measured.
That is the closed world rule applied where it matters most: an incomplete model costs false
negatives, not false positives.

### What `verified` asks for

`implemented` means the engine looks for the pattern and finds it in the fixture together with
its counter case. `verified` adds the other half: every condition the file declares it fires on
for nothing is **settled**, and there are two ways to settle one.

Either the condition can be written as a policy, and then the file carries that policy and the
engine is run over it on every build, or the thing that would tell it apart is not in the policy
and not in the data, and then the file says exactly that. Intent is of the second kind. So is a
guarantee something upstream of OPA makes and nothing in the bundle enforces. Naming those is
not a way around measuring: it is what tells whoever reads a report which findings a person
still has to judge, and which ones the engine has already been held to.

A case that still fires is the honest outcome and not a defect to hide. Running it is what keeps
the admission true: the day the engine learns to tell that condition apart, the case goes quiet
and the file is wrong about itself where the tests run instead of in somebody's assessment.

The linters of this field measure their own precision the same way. Semgrep annotates the lines
of a test file with `ruleid` where the rule has to fire and `ok` where it must not, and keeps
`todoruleid` and `todook` for what fails today and is declared. `regal` v0.42.0 ships a test
beside every rule of its bundle, `impossible_not.rego` next to `impossible_not_test.rego`. In
both, precision is a small case per condition rather than a corpus.

The table above says which patterns are there. In `PTD-OPA-007`, two of the three conditions are
intent and are declared as such. The third, an `every` guarded by iterating its domain instead of
counting it, is a policy in the file that the engine runs on every build, and it reports: the
false positive is measured rather than only admitted. A case can also come out quiet, like the
fail-open in 005 that the rule writes down by reading `error`: a condition the engine already
tells apart, and running it keeps that true.

### What generated worlds answer instead

Generated worlds with a fixed seed answer a different question: whether the engine invents
escalations. That is the worst thing it could do and the hardest to catch by reading the code
that does it. On worlds it has never seen, it does not, and that covers both
escalations, the 001 to 003 chain whose planted principals it finds and no others, and the split
grant of 006, which it reports for nobody on data that gives everybody the viewer role. The
every of 007 is measured there too, from the other side: it rests on the policy, so on every
generated world it reports the same one decision and never a second, the way 004 and 005 do.

The two measurements do not overlap. A dataset can produce the case and never the reason, so
intent stays out of reach, and so does the completeness of the write model, which a person
declares by definition. Those are the conditions a file marks `out-of-band`.

### What a real corpus said

The engine has been run over
[`open-policy-agent/gatekeeper-library`](https://github.com/open-policy-agent/gatekeeper-library),
at commit `e4d3bd2448b20bc7910417f5b2cf18b63a0bd33c`: 51 units under `src/`, 142 Rego files, all
of them written by other people. On that corpus the patterns find **zero**, and not because of a
limit in the engine:

| Pattern | Why it is silent |
|---|---|
| `PTD-OPA-001` | no recognized subject, so no read indexed by the subject. `input.review.userInfo` appears once in 142 files |
| `PTD-OPA-002` | the few policies that read `data` all read the same inventory document Gatekeeper replicates |
| `PTD-OPA-003` | no transitive construct anywhere in the corpus |
| `PTD-OPA-004`, `PTD-OPA-005` | **zero** calls to nondeterministic builtins in the whole corpus |
| `PTD-OPA-006` | needs a write model naming the decision behind a write, and the corpus ships none |
| `PTD-OPA-007` | not one `every` in the corpus: the keyword does not appear in any of the 142 files |
| `PTD-OPA-008` | it measures against concrete data, and the corpus ships none. One read in the whole corpus names a document every request shares, the storage classes Gatekeeper replicates into its inventory |
| `PTD-OPA-009` | it runs only with the enforcement point declared, and `pep-registry/` declares none for Gatekeeper, since an admission review is the object the policy judges, written whole by the caller. With a declaration that covers no field it reports 26 candidates in 14 units, among them a container's own resource limits |
| `PTD-OPA-010` | it runs only with the enforcement point declared, too. The one policy that reads who is asking, `noupdateserviceaccount`, compares the user's name and groups with the lists the constraint passes in its parameters, and never with a name the policy writes |

A zero against a real corpus is neither a confirmation nor a refutation of the declared false
positives: it is a measurement of what that corpus holds. Kubernetes admission policies decide
about an object that is being admitted and almost never about who is asking for it, so the line
between whoever decides and whoever writes the data, which is the material of this registry, is
barely there.

[`open-policy-agent/contrib`](https://github.com/open-policy-agent/contrib), at commit
`90f7ca99ce603c4ce3e40cc990b5a33bb895b557`, is a different kind of corpus: 28 units, all of them
Rego v1, among them OPA behind Kafka, Kong, PAM, a Kubernetes authorizer and an AuthZEN proxy, and
in front of databases that filter by a decision.
Each of those queries its own decision, so each unit was run through `petard analyze` with the
decision its configuration or code queries; `petard measure` declares decisions by rule name,
which suits Gatekeeper and not this. 16 units have a request to decide about. The other 12 are
configuration checks, libraries, test inputs and a bundle signing demo.

| Units | What the decisions read | What the patterns say |
|---|---|---|
| 1, the AuthZEN interop policy | `data.users[input.subject.id].roles` and `.email` | `PTD-OPA-001`: two candidates, confidence B |
| 2, Puppet and a Kubernetes node selector | a document the request picks, with no recognizable subject | nothing |
| 6, data filtering over SQL, Elasticsearch, MongoDB and Azure, and an image policy | documents that other data picks, and in two of them a record the requester is searched for | `PTD-OPA-001`: three candidates over those two |
| 7, an HTTP API, Kafka, Kong, PAM, a Kubernetes authorizer, Dart, Wasm | no `data` | nothing |

The three candidates are what a lookup by value finds. The Elasticsearch example keeps the posts
whose `author` is the requester, and the MongoDB one the employees whose `name` is, plus the ones
whose `manager` is. None of the three is indexed by anybody: they are rows kept by a comparison,
which is what data filtering is for. Whoever can write those fields decides who reads what, and
the write model is where that gets declared.

No value from outside the policy reaches any of the 16 decisions, so `PTD-OPA-004` and
`PTD-OPA-005` have nothing to look at, and no policy in contrib uses `every` either, so
`PTD-OPA-007` has nothing to find in its 49 files. No decision reads a document every request
shares, so `PTD-OPA-008` has nowhere to start. The two candidates of the AuthZEN policy stay
candidates: whether a user can change their own `roles` depends on the application that stores
them, and the write model is where that is declared.

Four more corpora were run the same way, with the decisions their enforcement points query:

| Corpus | Decisions | What they read | What the patterns say |
|---|---|---|---|
| `ynotbhatc/rego_policy_libraries`, `enforcement/aap` | 11 | one block of `data.aac.aap.config` each | `PTD-OPA-008`: 11 candidates, confidence A |
| `chef/automate` | 3 | 15 reads over 8 paths under `data.policies` and `data.roles` | `PTD-OPA-001`: one candidate, confidence D |
| `SAP/InfraBox` | 1 | 64 reads over 6 paths, in the two documents its API pushes | `PTD-OPA-001`: one candidate, confidence A |
| `magda-io/magda` | 1 | no `data` | nothing |

[`ynotbhatc/rego_policy_libraries`](https://github.com/ynotbhatc/rego_policy_libraries), at commit
`e1eb90b5a73f8d90362833228837dded51547c87`, gives `petard measure` 296 units, all Rego v1, and
every one of them loads. 123 define the `compliance_report` its README queries, and for 122 of
those no request shape is recognized, because the input they take describes a system rather than
somebody asking. `enforcement/aap` is the part that decides about a request, eleven decisions
Ansible Automation Platform queries before it runs a job, each answering in an `allowed` field.
Run with those eleven, the subject declared as `input.created_by.username` and the example
configuration the directory ships as data, each decision reads its own block of
`data.aac.aap.config`, and that block decides for a principal no document names. On the example
configuration `deny_all` and `maintenance_mode` grant that principal whatever they ask, and the
other nine grant it in one way each. They stay candidates until a write model says who can change
the configuration.

[`chef/automate`](https://github.com/chef/automate), at commit
`61ca031112bf605c9c2a8975957b505635374e49`, has six Rego files in the whole repository, the three
policies of its authorization service and their tests, in
`components/authz-service/engine/opa/policy`, Rego v0. The service queries three decisions
(`engine/opa/opa.go:36` to `38`), `authz/authorized_project`, `authz/introspection/authorized_pair`
and `authz/introspection/authorized_project`. The subject is recognized from field names as
`input.subjects[_]`, level D, and the candidate is `data.policies[_].members[_]` at
`authz.rego:10`, where a policy applies to a request when one of the request's subjects is among
its members. Whoever can add a member to a policy decides who it applies to. The repository ships
no data, so the four patterns that evaluate against it did not run.

[`SAP/InfraBox`](https://github.com/SAP/InfraBox), at commit
`946edc0871c3b04e477ed216ffb47db4d11ef089`, keeps 25 policies and one test in
`src/openpolicyagent/policies`, one package, Rego v0. The API asks `data.infrabox.authz`
(`src/pyinfraboxutils/ibopa.py:12`) and, on a timer, pushes two documents out of its database:
who collaborates on which project with which role, and which projects are public (`ibopa.py:39`
to `52`). With the subject declared as `input.token.user.id`, the walk finds 64 reads over 6
paths, all of them in those two documents. `PTD-OPA-001` reports one candidate,
`data.infrabox.collaborators.collaborators[_].user_id`, which the decisions search for the
requester in 17 places. The functions that make the search take the requester and the project as
one array, `project_collaborator([user, project])` at `project.rego:11`, and the requester is the
first element of what the caller passes. Whoever can add a row to the collaborator table decides
who the search finds. No value from outside the policy reaches the decision, no rule uses
`every`, and the repository ships no data.

[`magda-io/magda`](https://github.com/magda-io/magda), at commit
`854854fa53c4852437f81cfb044e9e744adf354e`, keeps 45 policy files in 27 directories under
`magda-opa/policies`, Rego v0. Loaded directory by directory, 24 of the 27 fail to compile on the
functions of `common` they call, so the tree was run as one bundle. Its decision is
`data.entrypoint.allow`, the one the authorization API asks
(`magda-authorization-api/src/createOpaRouter.ts:505` and `511`), and it hands each kind of object
to the `allow` of its own package. The 45 files read no `data`. The roles, permissions and
organizational units of the user travel in the request under `input.user`, which the API sets to
the current user it looks up before asking (`createOpaRouter.ts:143` and `180`). Eight of the
ten patterns start from a read of `data`, from a value from outside the policy or from an
`every`, and the 45 files contain none of them. The other two, `PTD-OPA-009` and `PTD-OPA-010`,
run only with the enforcement point declared.

A corpus is not what `verified` waits for, and this is worth separating: a corpus says what other
people write, which is why these six are here, while the conditions a pattern declares against
itself are settled one case at a time, in the file that declares them.

### The fixture

`fixtures/vulnerable-bundle/` holds a case **and at least one counter case** for each of the
ten, in Rego v1 and v0, with the write model, the declaration of its gateway, and an
`EXPECTED.md` that declares in words what the engine has to find and what it must not. The numbers
there are executed, not estimated.

### Candidates not yet written

None open. The two the registry used to list are both resolved.

**`every` over an empty collection became `PTD-OPA-007`.** The signals do not overlap 002 or 005:
the construct is `ast.Every` with an empty domain, an empty set rather than 002's missing key, and
there is no network source, so 005's taint does not apply. It earned a file, now `verified`: a
case and a counter case in the fixture, and its three declared false positives settled.

**Role hierarchy expansion is not a pattern of its own.** It is `PTD-OPA-003`. The
relation the transitive signals cut is named by what the rule building it reads, whatever that
relation connects, and Rego forbids recursion between rules, so an unbounded role expansion runs
through `graph.reachable` or `walk` like any other hierarchy. A role that reaches far only through
the inheritance graph is measured there, with no file of its own.
