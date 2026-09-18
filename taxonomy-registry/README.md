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
`regal lint` on the fixture, which holds the case and the counter case of all eight patterns,
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
patterns that side is the finding, and for others it does not count.

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

Two limits come with all this, and each is a false negative rather than noise: a lookup marks the
read that holds the value and not the other fields of the same document, so a role read next to a
matched member is not reported; and a match on a prefix, as Chef's `team:*` members are, is not a
lookup by value. The chain of `PTD-OPA-001` into `PTD-OPA-003` leaves a join alone as well: it
writes a document of the subject's own and lets partial evaluation find the value, and an element
added to a list is neither.

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
| `PTD-OPA-006` | SPLIT-GRANT | opa | finding | C | `verified`, the second edge that means escalation, from a write a decision authorizes rather than a position: a value in the subject's record, or the subject added to a collection |
| `PTD-OPA-007` | FAIL-OPEN-ON-ABSENCE | opa | finding | B | `verified`, the third instance of the category: an `every` over a domain the request can empty |
| `PTD-OPA-008` | GLOBAL-SWITCH | opa | finding | C | `verified`, a document every request shares, and the question asked about somebody no document names |

Between them the eight exercise `binding-resolution`, `concrete-data`, `rule-graph` and `taint`;
007 adds no new capability, only a new construct within `rule-graph`, and 008 asks a new question
of `concrete-data`: what a decision gives a principal the data knows nothing about.

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

The engine has been run over `open-policy-agent/gatekeeper-library`, at commit
`e4d3bd2448b20bc7910417f5b2cf18b63a0bd33c`: 51 units under `src/`, 142 Rego files, all of them
written by other people. On that corpus the patterns find **zero**, and not because of a limit in
the engine:

| Pattern | Why it is silent |
|---|---|
| `PTD-OPA-001` | no recognized subject, so no read indexed by the subject. `input.review.userInfo` appears once in 142 files |
| `PTD-OPA-002` | the few policies that read `data` all read the same inventory document Gatekeeper replicates |
| `PTD-OPA-003` | no transitive construct anywhere in the corpus |
| `PTD-OPA-004`, `PTD-OPA-005` | **zero** calls to nondeterministic builtins in the whole corpus |
| `PTD-OPA-006` | needs a write model naming the decision behind a write, and the corpus ships none |
| `PTD-OPA-007` | not one `every` in the corpus: the keyword does not appear in any of the 142 files |
| `PTD-OPA-008` | it measures against concrete data, and the corpus ships none. One read in the whole corpus names a document every request shares, the storage classes Gatekeeper replicates into its inventory |

A zero against a real corpus is neither a confirmation nor a refutation of the declared false
positives: it is a measurement of what that corpus holds. Kubernetes admission policies decide
about an object that is being admitted and almost never about who is asking for it, so the line
between whoever decides and whoever writes the data, which is the material of this registry, is
barely there.

`open-policy-agent/contrib`, at commit `90f7ca99ce603c4ce3e40cc990b5a33bb895b557`, is a different
kind of corpus: 28 units, all of them Rego v1, among them OPA behind Kafka, Kong, PAM, a
Kubernetes authorizer and an AuthZEN proxy, and in front of databases that filter by a decision.
Each of those queries its own decision, so each unit was run through `analyze-opa` with the
decision its configuration or code queries; `measure-corpus` declares decisions by rule name,
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

A corpus is not what `verified` waits for, and this is worth separating: a corpus says what other
people write, which is why these two are here, while the conditions a pattern declares against
itself are settled one case at a time, in the file that declares them.

### The fixture

`fixtures/vulnerable-bundle/` holds a case **and at least one counter case** for each of the
eight, in Rego v1 and v0, with the write model and an `EXPECTED.md` that declares in words what
the engine has to find and what it must not. The numbers there are executed, not estimated.

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
