# Registry schema, v1

> The fields of an instance file. `schema_version: 1` is mandatory in every one of them.
>
> Changing this schema means bumping `schema_version` and writing the migration. Do not do it
> before there are **at least three patterns**: freezing a schema on a single example is the
> classic way of freezing the wrong thing.

---

## Mandatory fields

| Field | Type | What |
|---|---|---|
| `schema_version` | int | `1` |
| `id` | string | `PTD-<ENGINE>-<NNN>`. Stable forever: it ends up in the properties of exported edges and in saved Cypher queries |
| `name` | slug | kebab-case, used in logs and in test names |
| `title` | string | one readable line |
| `engine` | enum | `opa` \| `cedar` |
| `status` | enum | `draft` → `implemented` → `verified`, see below |
| `category` | object | the abstract level: `id`, `title`, `summary` |
| `summary` | string | one paragraph: what it lets somebody do, not how it is implemented |
| `preconditions` | list | **what the attacker has to hold already.** See below |
| `mechanism` | object | `description` plus `example`, which is real Rego that compiles |
| `detection` | object | **the field that makes the pattern executable.** See below |
| `graph` | object | what it emits in the data model |
| `false_positives` | list | conditions where the signal fires with no abuse behind it, and how each one is settled. See below |
| `not_a_lint_rule` | string | why `regal` cannot find it. **If you cannot write this line, the pattern does not go in** |
| `fixture` | object | the case in the vulnerable bundle |
| `references` | list | sources, with the date each was consulted |
| `verified` | object | `date` plus `tool_version` plus `how`. See below |

### `status`

| Value | Means |
|---|---|
| `draft` | documented, not implemented |
| `implemented` | the engine looks for it, and finds it in the fixture together with its counter case |
| `verified` | every declared false positive is settled as well: see `false_positives` |

### `preconditions`

This is the field that makes a pattern **actionable** instead of interesting, and it is the
lesson of the Rhino Security Labs IAM taxonomy, where every method reads *"an attacker with
`iam:CreatePolicyVersion` can..."*. Without the precondition a pattern is a generic risk. With
it, it is an attack path you can tell applies to you or not.

Each entry names **one capability the attacker has to hold already**, in the terms of the system
around OPA rather than in the terms of Rego.

### `detection`

| Subfield | What |
|---|---|
| `ast_source` | `compiled` \| `raw`. In practice **always `compiled`**: on the raw AST a nested builtin call is not an expression of its own, so a pass over the expressions never sees it |
| `requires` | which engine capabilities are needed: `binding-resolution`, `rule-graph`, `concrete-data`, `taint` |
| `signals` | an ordered list of checks. Each one has to be computable rather than interpretable |
| `confidence` | `A` to `E`, on how the shape of the request was recognized: A is a declared `METADATA` schema, B an AuthZEN shaped request, C a domain convention, D a heuristic on field names, E syntax alone |
| `requires_write_model` | bool. If `true`, without the `WrittenBy` model the pattern **cannot** emit `PTD_CanEscalateTo` |

> A `signals` entry written as *"the policy trusts its input"* is not a signal, it is an opinion.
> A signal is *"there is a reference rooted at `data.` whose term in index position derives from
> `input` once the local bindings are resolved"*.

Partial evaluation is deliberately not in `requires`. It is a tool the engine uses to measure
what a decision grants today, and no pattern needs it in order to find a defect: `requires` says
what it takes to **find** a defect, not what it takes to show its effect.

### `graph`

| Subfield | What |
|---|---|
| `emits` | `finding` \| `candidate`. **`finding` only when `requires_write_model` is false, or the model is there.** Otherwise `candidate` |
| `edge` | the edge kind in the data model |
| `from` / `to` | which nodes it joins |
| `traversable` | bool: it becomes `is_traversable` in the OpenGraph schema. Marking an edge traversable when it does not stand for a capability produces **paths in the interface that nobody can walk** |

### `false_positives`

Every entry has a `condition`, which is when the signal fires for nothing, and a
`discriminator`, which is what it would take to tell the two apart. An empty `discriminator` is
an honest admission and is worth more than a condition left unsaid.

A pattern that wants `status: verified` also says, per condition, **how that condition is
settled**, in `measurement`:

| Value | Means |
|---|---|
| `case` | a policy can be written that realizes the condition. The entry carries one in `case`, and the engine is run over it |
| `out-of-band` | the discriminator is not in the policy and not in the data. There is no case to write, and saying so is the measurement |

`out-of-band` is where intent lives, and with it every guarantee something upstream of the
engine makes and nothing in the bundle enforces. It is not an excuse: it is what tells whoever
reads a finding that this one needs a person, and which ones do not.

A `case` holds:

| Field | What |
|---|---|
| `policy` | a bundle of its own, holding the condition and nothing else, with its decision marked as an entrypoint. The fixture is a world and has to stay coherent; this is one question asked in isolation |
| `reports` | what the engine does with it. `true` is the admission that the false positive still happens, written down and executed; `false` means the condition turned out to be told apart |
| `note` | what the run showed |

`reports: true` is not a defect to hide. A declared false positive that still happens is the
honest outcome, and running it means that the day the engine starts telling the condition
apart, the file stops being right about itself in the test suite rather than in somebody's
report.

This is how the linters of the field measure their own precision. Semgrep annotates the lines
of a test file with `ruleid` where the rule has to fire and `ok` where it must not, plus
`todoruleid` and `todook` for what fails today and is declared, and `regal` v0.42.0 ships a test
next to every rule of its bundle, `impossible_not.rego` with `impossible_not_test.rego`. In both
the measurement is a small case per condition, not a corpus.

### `verified`

`date`, `tool_version` and `how`, and nothing else. `how` says what was executed and what came
out of it, describing the pattern as it stands rather than the order in which it got there.
Something measured but still open goes in `notes`; something not measured at all goes in
`open_questions`.

---

## Optional fields

| Field | What |
|---|---|
| `related` | other registry ids: patterns that chain or overlap |
| `notes` | observations that do not fit anywhere else |
| `open_questions` | what is not known yet. Better written down than left implied |

---

## What is deliberately not here

| Absent | Why |
|---|---|
| `severity` or a score | False precision. How bad an escalation is depends on what it gives you, which is the client's context and not the pattern's. BloodHound itself assigns no severity to its edges: it assigns **traversability**, which is an objective property, and that is what `graph.traversable` holds |
| `remediation` | It would be a second source of truth against the documentation of the system being analyzed, and it would age. Remediation belongs in the report, generated from the context |
| `cvss` or `cwe` | A pattern is not a vulnerability in a product. Forced mappings onto taxonomies built for something else make a thing look rigorous when it is not. If a mapping is useful it goes in `references` |
