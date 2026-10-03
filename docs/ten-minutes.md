# Ten minutes with Petard

Petard reads an OPA policy to ask one thing. Who can write the data a decision
trusts? Where a subject can write the data that decides their own access, that is
a privilege escalation. This page takes one from a public example to a finding in
about ten minutes, against policy someone else wrote and published, so you can
reproduce every step.

## The example

The AuthZEN interop policy in `open-policy-agent/contrib` decides whether a
subject may read or change todos. It reads each subject's roles from a data
document, which is the shape Petard is built for.

```bash
git clone https://github.com/open-policy-agent/contrib
cd contrib/authzen/authzen-interop/policy
```

The output below is from commit `90f7ca9`.

## Run it

```bash
petard analyze .
```

```
1 file, 1 decision, parsed as rego v1

Escalations
  none named: without a write model nobody is declared able to write,
  so a chain that would escalate stays a candidate below.

Findings
  nothing

Candidates, which need a write model to become findings
    2  PTD-OPA-001  The subject writes an attribute the policy reads to decide about them

Questions, which turn candidates into findings
  Declare who writes each path in a write model, or write one to fill in with -questions <file>.
  data.users[_].email  can the subject write their own?  (PTD-OPA-001)
  data.users[_].roles  can the subject write their own?  (PTD-OPA-001)
```

Petard took no flags. It inferred the decision, the one rule no other rule uses,
read the data the bundle carries, recognized `input.subject.id` as the subject,
and found two documents the subject indexes to decide about themselves: their
roles and their email. The policy grants admin to a subject whose roles hold
`admin`, and treats a subject as owner when their email matches a resource, so
both documents decide the subject's own access.

## The question

They come back as candidates, not findings. Whether `data.users[_].roles` is a
hole depends on who can write it, and no policy contains that fact. It lives outside the Rego, in the profile API or the
identity sync, and Petard will not guess it. It names the paths and asks you the
one question only you can answer.

So answer it. The `-questions` flag writes a write model with one entry per open
question, ready to fill in:

```bash
petard analyze -questions write-model.yaml .
```

```yaml
# Write model skeleton written by petard analyze -questions.
#
# Fill in each via, the endpoint or form that makes the write, and change the
# principal when it is not the one suggested. Then rerun with -write-model and
# this file. A path nobody can write is one to delete rather than leave open.
# The subject is input.subject.id.
schema_version: 1
model: write-paths
entries:
  # can the subject write their own? (PTD-OPA-001)
  - path: data.users.{owner}.email
    writable_by:
      - principal: "{owner}"
        via: ""
  # can the subject write their own? (PTD-OPA-001)
  - path: data.users.{owner}.roles
    writable_by:
      - principal: "{owner}"
        via: ""
```

Each entry says the subject (`{owner}`) can write their own record. Fill in the
`via`, the endpoint or form that makes the write, for the paths where that is
true. Say a self-service profile endpoint lets a user edit their own row:

```yaml
    via: "PUT /users/{id} (self-service profile)"
```

## Rerun, and read the finding

```bash
petard analyze -v -write-model write-model.yaml .
```

```
PTD-OPA-001, The subject writes an attribute the policy reads to decide about them
  PTD-OPA-001 finding: data.users[_].roles, 3 places to look (confidence B), written via PUT /users/{id} (self-service profile)
    data.users[input.subject.id].roles at authzen/authzen.rego:27 in data.authzen.user_is_admin
    data.users[input.subject.id].roles at authzen/authzen.rego:31 in data.authzen.user_is_editor
    data.users[input.subject.id].roles at authzen/authzen.rego:29 in data.authzen.user_is_evil_genius
    declared writable at data.users.{owner}.roles
  to close: A field the subject cannot write, assigned by a role through an administration API, is the counter case.
```

The candidate is now a finding. A subject who can write their own `roles` can add
`admin` to themselves, and the decision reads that same document to grant admin.
The `-v` output names every place the policy reads it, by file and line, so you
can see the three rules that trust it. The `to close` line says what makes the
finding go away: a role field the subject cannot write, set only through an
administration API.

The email path is a finding for the same reason. The owner check compares the
subject's email to a resource's owner, so a subject who can write their own email
can claim ownership of a resource and then update or delete it.

## When Petard has little to say

This policy reads data that someone writes, so Petard had something to weigh.
Many OPA policies do not. An admission controller or a config check decides on
the request it is handed and reads no stored document, and there the lens that
asks who writes the data has nothing to work on. Point Petard at one of those and
it says so, under the heading `These decisions read no data`, and sends you to
the request side, where `-pep` declares which parts of the request the caller
controls.

For how each claim above is checked, see [the engine](engine.md). For what a
pattern looks for and what it will not report, run `petard explain PTD-OPA-001`.
