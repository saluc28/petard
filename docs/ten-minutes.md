# Ten minutes with Petard

Petard asks who can change the answer of a policy without changing the policy. This page takes
two public examples to an answer, a Rego policy and a SpiceDB schema, in about five minutes each.
Both were written and published by somebody else, so you can reproduce every step.

## A Rego policy

The AuthZEN interop policy in `open-policy-agent/contrib` decides whether a subject may read or
change todos. It reads each subject's roles from a data document, which is the shape Petard is
built for.

```bash
git clone https://github.com/open-policy-agent/contrib
cd contrib/authzen/authzen-interop/policy
```

The output below is from commit `90f7ca9`.

### Run it

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

Candidates, which match a pattern and are not proven
    2  PTD-OPA-001  The subject writes an attribute the policy reads to decide about them

Questions, which turn candidates into findings
  Declare who writes each path in a write model, or write one to fill in with -questions <file>.
  data.users[_].email  can the subject write their own?  (PTD-OPA-001)
  data.users[_].roles  can the subject write their own?  (PTD-OPA-001)
```

The report goes on with the patterns that did not run and how much to trust what it found.

Petard took no flags. It inferred the decision, the one rule no other rule uses, read the data
the bundle carries, recognized `input.subject.id` as the subject, and found two documents the
subject indexes to decide about themselves: their roles and their email. The policy grants admin
to a subject whose roles hold `admin`, and treats a subject as owner when their email matches a
resource, so both documents decide the subject's own access.

### The question

They come back as candidates, not findings. Whether `data.users[_].roles` is a hole depends on
who can write it, and no policy contains that fact. It lives outside the Rego, in the profile API
or the identity sync, and Petard will not guess it. It names the paths and asks you the one
question only you can answer.

So answer it. `-questions` writes a write model with one entry per open question, ready to fill
in:

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

Each entry says the subject (`{owner}`) can write their own record. Fill in the `via`, the
endpoint or form that makes the write, for the paths where that is true. Say a self-service
profile endpoint lets a user edit their own row, for both paths:

```yaml
        via: "PUT /users/{id} (self-service profile)"
```

### Rerun, and read the findings

```bash
petard analyze -v -write-model write-model.yaml .
```

`-v` prints the evidence under the summary, and under each pattern what it found:

```
PTD-OPA-001, The subject writes an attribute the policy reads to decide about them
  PTD-OPA-001 finding: data.users[_].roles, 3 places to look (confidence B), written via PUT /users/{id} (self-service profile)
    data.users[input.subject.id].roles at authzen/authzen.rego:27 in data.authzen.user_is_admin
    data.users[input.subject.id].roles at authzen/authzen.rego:31 in data.authzen.user_is_editor
    data.users[input.subject.id].roles at authzen/authzen.rego:29 in data.authzen.user_is_evil_genius
    declared writable at data.users.{owner}.roles
  PTD-OPA-001 finding: data.users[_].email, 1 place to look (confidence B), written via PUT /users/{id} (self-service profile)
    data.users[input.subject.id].email at authzen/authzen.rego:33 in data.authzen.user_is_owner
    declared writable at data.users.{owner}.email
  to close: A field the subject cannot write, assigned by a role through an administration API, is
  the counter case.
```

The candidates are now findings. A subject who can write their own `roles` can add `admin` to
themselves, and the decision reads that same document to grant admin. The output names every
place the policy reads it, by file and line, so you can see the three rules that trust it. The
email is a finding for the same reason: the owner check compares the subject's email to a
resource's owner, so a subject who can write their own email can claim ownership of a resource
and then update or delete it. The `to close` line says what makes the pattern stop firing: a
field the subject cannot write, set only through an administration API.

### When Petard has little to say

This policy reads data that someone writes, so Petard had something to weigh. Many OPA policies
do not. An admission controller or a config check decides on the request it is handed and reads
no stored document, and there the question of who writes the data has nothing to work on. Point
Petard at one of those and it says so, under the heading `These decisions read no data`, and
sends you to the request side, where `-pep` declares which parts of the request the caller
controls.

## A SpiceDB schema

SpiceDB runs its integration tests on validation files, the format `zed validate` reads, and one
of them, `caveatip.yaml`, holds an allowlist small enough to read whole. A viewer of a document
may be held to a network with the caveat `is_valid_ip(user_ip ipaddress, cidr string)`. The
relationships write the network, and the checks bring the caller's address.

```bash
git clone --branch v1.56.2 https://github.com/authzed/spicedb
cd spicedb/internal/services/integrationtesting/testconfigs
```

### Run it

```bash
petard analyze caveatip.yaml
```

```
1 SpiceDB file
  caveatip.yaml  validation file, 3 relationships, 7 assertions; 2 definitions, 1 relation, 1 permission, 1 caveat

Findings
  nothing

Candidates, which match a pattern and are not proven
    1  PTD-ZAN-001  A relationship fixes a caveat value the check was meant to supply

  document#viewer, user_ip of caveat is_valid_ip  (PTD-ZAN-001)
    written on   document#viewer at caveatip.yaml:10:2, and whoever writes it chooses the context of
                 is_valid_ip
    supplied by  4 checks of the file, the first at caveatip.yaml:23:7
    shown by     document:firstdoc#view@user:tom with {"user_ip":"1.2.3.4"}, at caveatip.yaml:29:7,
                 goes from no to yes once document:firstdoc#viewer@user:tom carries
                 {"cidr":"10.0.0.0/8","user_ip":"10.2.3.4"}

Run petard explain <id> for what a pattern looks for and what it will not report.
```

The checks of the file supply `user_ip`, and the relationships leave it out, so the address is
meant to come with the check. A relationship can carry any parameter of its caveat, though, and
SpiceDB evaluates the caveat on the check's context with the relationship's context copied over
it. Whoever writes tom's relationship can write an address inside the network once, and from
then on the address the check brings no longer counts.

`shown by` is that write, taken from the file itself: written on the relationship, the address
one check supplies turns the check from `1.2.3.4`, at line 29, from no into yes. The match is a
candidate because who writes `document#viewer`, and with what context, is decided by the
application that calls SpiceDB, and no schema says it.

### Check it with zed

The witness is a change to the file, so `zed validate` can check it. Write tom's relationship the
way `shown by` says:

```
document:firstdoc#viewer@user:tom[is_valid_ip:{"cidr":"10.0.0.0/8","user_ip":"10.2.3.4"}]
```

```bash
zed validate caveatip.yaml
```

zed v1.2.1 accepts the file as it was published, and fails on two of its assertions once the
relationship is written that way: the check from `1.2.3.4` at line 29 is no longer refused, and
the check without a context at line 26 is no longer caveated.

SpiceDB's own tests rely on the same precedence. In `caveatexpiration.yaml`, at the same tag, one
relationship carries `current_time` as well as its expiration (line 15), and the check on it holds
with no context at all (line 24).

For what the engine reads of a schema and how its answers are held to SpiceDB, see
[zanzibar.md](zanzibar.md); for how each claim about a policy is checked, [opa.md](opa.md). To see
what a pattern looks for and what it will not report, run `petard explain PTD-OPA-001` or
`petard explain PTD-ZAN-001`.
