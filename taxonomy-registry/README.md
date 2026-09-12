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
`regal lint` on the fixture, which holds the case and the counter case of all five patterns,
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
| `PTD-OPA-001` | ATTR-SELF-WRITE | opa | finding | C | `implemented`, with the case and the counter case separated on the fixture |
| `PTD-OPA-002` | FAIL-OPEN-ON-ABSENCE | opa | finding | B | `implemented`, the one that emits findings on its own, with no write model |
| `PTD-OPA-003` | TRANSITIVE-GRANT | opa | candidate | B | `implemented`, and it chains with 001, which is where a route comes from |
| `PTD-OPA-004` | EXTERNAL-SOURCE-TAINT | opa | finding | A | `implemented`, and the one that exercises taint |
| `PTD-OPA-005` | FAIL-OPEN-ON-ABSENCE | opa | finding | B | `implemented`, with the lowest precondition: no attacker needed |

Between them the five exercise `binding-resolution`, `concrete-data`, `rule-graph` and `taint`.

`partial-eval` is not among the capabilities a pattern requires. Partial evaluation is a tool of
the engine, the one it measures what a decision grants today with, and in 002 it is how the
fixture checks the **consequence** of a finding. The distinction is worth keeping:
`detection.requires` says what it takes to **find** a defect, not what it takes to show its
effect.

### The chain, and what holds it up

The chain from `PTD-OPA-001` to `PTD-OPA-003` is closed: on the fixture exactly one
`PTD_CanEscalateTo` comes out, from `mallory` to `dave`, with the path to write and the endpoint
to write it through. It lives in `internal/taxonomy/escalation.go`, which is not a sixth
pattern: it is the place where two of them meet, and that is why its result comes out under the
id of `PTD-OPA-003`, where the registry says a candidate becomes a finding.

The chain is the only claim in the registry that deserves the words privilege escalation, and
what holds it up is **the write model**. Without one, 001 produces a candidate and the chain
stays quiet, while everything else is measured as before. That is the closed world rule applied
where it matters most: an incomplete model costs false negatives, not false positives.

### Why nothing is `verified`

`implemented` means the engine looks for the pattern and finds it in the fixture together with
its counter case. `verified` means the declared false positives have been **measured** as well.

Generated worlds with a fixed seed answer part of that, and the part they answer is the worst
risk: that the engine invents escalations. On worlds it has never seen, it does not. What
generated data cannot settle is most of what these files actually declare:

- **intent**, which no dataset contains. "The absence is deliberate", "the breadth is known and
  wanted", "the fail-open is a choice about availability": a generator can produce the case, not
  the reason.
- **the shape of the policy** rather than of the data. `PTD-OPA-004` and `PTD-OPA-005` read
  builtin calls, and against any dataset they give the same four results. Measuring them would
  mean generating **policies**, which is a second tool and not one more parameter of this one.
- **the completeness of the write model**, which is declared by a human by definition.

### What a real corpus said

The engine has been run over `open-policy-agent/gatekeeper-library`, at commit
`e4d3bd2448b20bc7910417f5b2cf18b63a0bd33c`: 51 units under `src/`, 142 Rego files, all of them
written by other people. **No pattern moved a millimetre**, and it is worth saying why, because
the opposite temptation was strong.

On that corpus the five find **zero**, and not because of a limit in the engine:

| Pattern | Why it is silent |
|---|---|
| `PTD-OPA-001` | no recognized subject, so no read indexed by the subject. `input.review.userInfo` appears once in 142 files |
| `PTD-OPA-002` | the few policies that read `data` all read the same inventory document Gatekeeper replicates |
| `PTD-OPA-003` | no transitive construct anywhere in the corpus |
| `PTD-OPA-004`, `PTD-OPA-005` | **zero** calls to nondeterministic builtins in the whole corpus |

A zero against a real corpus is neither a confirmation nor a refutation of the declared false
positives: it is a measurement of what that corpus holds. Kubernetes admission policies decide
about an object that is being admitted and almost never about who is asking for it, so the line
between whoever decides and whoever writes the data, which is the material of this registry, is
barely there.

`verified` therefore still needs what it needed: a measurement of the **declared** false
positives, which for 004 and 005 would mean generating policies rather than data, and for the
others a corpus that crosses that line.

### The fixture

`fixtures/vulnerable-bundle/` holds a case **and at least one counter case** for each of the
five, in Rego v1 and v0, with the write model and an `EXPECTED.md` that declares in words what
the engine has to find and what it must not. The numbers there are executed, not estimated.

### Candidates not yet written

Three, and this is the only place all of them are listed: a candidate that lives only in
somebody's notes does not exist by the next reading.

| Candidate | Where the reasoning stopped |
|---|---|
| Role hierarchy expansion with no upper bound | The weakest of the three. To be decided whether it deserves a file of its own or is a property of `PTD-OPA-003` |
| Privilege creep: chains across different policies that together grant an action neither grants alone | The only one that does not start from a single rule, which makes it the test of the schema: if the schema holds this, it holds nearly anything |
| `every` over an empty collection is true, so a check written with `every` stops applying exactly when there is nothing to apply it to | The same shape as `PTD-OPA-002` on another axis. Probably a third OPA instance of `FAIL-OPEN-ON-ABSENCE`, but first it has to be shown that its signals do not overlap those of 002 and 005, otherwise it is a pattern already written in a third prose |
