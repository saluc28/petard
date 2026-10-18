# Petard

[![Tests](https://github.com/saluc28/petard/actions/workflows/test.yml/badge.svg)](https://github.com/saluc28/petard/actions/workflows/test.yml)
[![Lint](https://github.com/saluc28/petard/actions/workflows/lint.yml/badge.svg)](https://github.com/saluc28/petard/actions/workflows/lint.yml)
[![Security](https://github.com/saluc28/petard/actions/workflows/security.yml/badge.svg)](https://github.com/saluc28/petard/actions/workflows/security.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/saluc28/petard.svg)](https://pkg.go.dev/github.com/saluc28/petard)

An authorization system answers who has access now: OPA evaluates a decision, SpiceDB answers a
check. Petard asks who can change that answer without changing the policy: by writing the data a
decision reads, by setting a part of the request it trusts, or by writing a relationship with the
context its caveat reads already filled in. It reads Rego (OPA) policies and SpiceDB schemas,
applies a registry of escalation patterns kept as data, and reports each match with what it rests
on and, where it finds one, a request or a check that shows it.

A linter sees one file. Petard is built to see the policy, what it decides on and who can write
that, together, because that is where the interesting failures live: the ones that cross the line
between whoever takes a decision and whoever writes what the decision is taken on. The
escalations it finds in a policy leave it as a BloodHound OpenGraph, as edges the interface can
walk.

It has little to say about a policy that judges the object it is handed and reads nothing stored,
an admission controller or a configuration check, and the report says so when that is the case.

## What it reads

| Engine | Reads | Patterns | Answers held to |
|---|---|---|---|
| [OPA](docs/opa.md) | Rego policies in either syntax, directories and bundle archives, a running OPA over its API, and the data beside them | 13, `PTD-OPA-001` to `PTD-OPA-013` | OPA v1.21.2, compiled in, which Petard asks by partial evaluation what is left of each decision |
| [Zanzibar](docs/zanzibar.md) | [SpiceDB](docs/spicedb.md) schemas (`.zed`) and the validation files `zed validate` reads | 1, `PTD-ZAN-001` | SpiceDB v1.56.2, whose compiler and caveats are compiled in, and `zed validate`, which agrees with the engine on 25,703 checks in CI |

On a policy, a match becomes a finding once what it rests on is known: the policy alone, or a
write model and an enforcement point you declare. On a SpiceDB schema every match is a candidate,
because who writes a relationship, and with which context, is decided by the application that
writes to SpiceDB, and Petard reads no declaration of it. [docs/concepts.md](docs/concepts.md) is
what the two engines share.

## Quickstart

With Go 1.26.6 or newer:

```
go install github.com/saluc28/petard/cmd/petard@latest
petard demo
petard analyze path/to/policy-or-schema
```

Without Go, [Install](#install) has a binary for Linux, macOS and Windows, and a container image.
Analyzing a policy never calls the endpoints written in it, and analyzing a schema never connects
to SpiceDB.

`demo` analyzes a policy and a SpiceDB schema carried inside the binary, written by hand with
defects in them, so there is something to look at before you point the tool at your own. For the
policy it leads with who can take whose place:

<!-- output of: petard demo -->
```
Escalations
  mallory -> dave  (PTD-OPA-003, confidence D)
    writes     data.users.{owner}.profile.department
    through    PATCH /api/v1/me/profile
    in         data.quill.authz.allow
    proven by  {"action":"read","doc":"d-t11-1","user":"mallory"}

  carol -> alice  (PTD-OPA-006, confidence D)
    writes     editor into data.users.{owner}.roles
    through    PUT /api/v1/users/{id}/roles
    allowed by data.quill.admin.allow
    in         data.quill.publish.allow
    proven by  {"action":"publish","user":"carol"}
```

The `proven by` line is a request the decision refuses as the data stands and grants once the
write is made. For the schema it names each caveat parameter that is meant to come with the check
and that whoever writes the relationship can set instead:

<!-- output of: petard demo -->
```
  document#viewer, user_ip of caveat ip_allowlist  (PTD-ZAN-001)
    written on   document#viewer at vulnerable-spicedb/schema.zed:26:3, and whoever writes it
                 chooses the context of ip_allowlist
    supplied by  2 checks of the file, the first at vulnerable-spicedb/validation.yaml:14:7
    shown by     document:roadmap#view@user:vic with {"user_ip":"192.168.0.1"}, at
                 vulnerable-spicedb/validation.yaml:19:7, goes from no to yes once
                 document:roadmap#viewer@user:vic carries {"cidr":"10.0.0.0/8","user_ip":"10.1.2.3"}
```

`shown by` is a check of the validation file whose answer rises once the relationship carries the
value, and `zed validate` fails on its assertion once the relationship is written that way. Around
these the demo counts the matches by pattern, and for the policy says how much to trust them. `-v`
adds the evidence behind the policy: every read with its file and line, and every place to look.

`analyze` needs no flags to start. Where a policy annotates no entrypoint it takes the rules no
other rule uses as the decisions, it reads the data the bundle carries and the SpiceDB files under
the paths, and it lists what only you can answer as questions.
[docs/ten-minutes.md](docs/ten-minutes.md) takes a public policy and a public schema from that
first run to an answer.

The patterns travel in the binary, so the two commands that read them work without a checkout:

```
petard patterns
petard explain PTD-ZAN-001
```

`explain` prints what the pattern looks for signal by signal, what it needs to run, what has to be
true for a match to be a defect, the conditions it fires on with nothing behind them, what closes
it, and where the file is.

## Install

Without Go, one file and no runtime:

```
# Linux, x86_64
curl -L -o petard https://github.com/saluc28/petard/releases/latest/download/petard_Linux_x86_64
chmod +x ./petard

# macOS, Apple silicon
curl -L -o petard https://github.com/saluc28/petard/releases/latest/download/petard_Darwin_arm64
chmod +x ./petard
```

On Windows:

```
Invoke-WebRequest -Uri "https://github.com/saluc28/petard/releases/latest/download/petard_Windows_x86_64.exe" -OutFile "petard.exe"
```

In a pipeline, `ghcr.io/saluc28/petard:latest`, or pin the version.

`petard version` says which build it is and which OPA and SpiceDB are compiled into it, which is
what an analysis depends on.

## BloodHound

The escalations Petard finds in a policy go to BloodHound CE as an OpenGraph, where they are
edges pathfinding walks. `petard export` writes the payload or uploads it, installs the extension
schema and 39 saved queries, and with `-verify` asks the server for a path between the two
principals of every escalation, and fails if it will not walk one.

![Two escalations in the graph](docs/assets/escalations.png)

[docs/opa.md](docs/opa.md#bloodhound) has the command, what it prints, and what the Entity Panel
of an escalation says.

## In a pipeline

```
petard analyze -quiet -fail-on findings -write-model write-model.yaml -data data policy
```

| Exit | What it means |
| ---- | ------------- |
| 0 | nothing above the threshold |
| 1 | the analysis could not run |
| 2 | the command line was wrong |
| 3 | matches above the threshold |

`-fail-on findings` is the default and counts findings; `any` counts candidates as well, which is
what fails a run on a SpiceDB schema, and `none` reports and exits 0 whatever it finds. Exit 3
means the analysis ran and found something, exit 1 means it could not run, and a pipeline needs
to tell those apart.

`-quiet` prints the escalations and the matches and nothing around them, and prints nothing at
all when there are none. The report goes to stdout and everything else to stderr, and two runs
over the same files print the same bytes, unless a relationship expires in between. Escape
sequences are used only when the output is a terminal that takes them; `NO_COLOR` and
`-no-color` turn them off.

## What it does not do

It does not decide whether a finding is a problem in your system. A position in a hierarchy is a
target rather than a defect, and the report says who can take it and leaves the judgment to you.

It does not know who writes what in your deployment unless you say so. A match on a policy that
rests on who writes a path stays a candidate until a write model names the writer, and a match on
a SpiceDB schema stays one in any case.

It reads files, and a running OPA over its API, read only. It never asks the server to decide
anything, and it never connects to SpiceDB.

## Documentation

- [docs/ten-minutes.md](docs/ten-minutes.md): a public policy and a public schema, from the first
  run to an answer
- [docs/concepts.md](docs/concepts.md): what every engine shares, from the question to the graph
- [docs/opa.md](docs/opa.md): how a Rego policy is read, the patterns, the flags for a policy of
  your own, BloodHound, and how each claim is checked
- [docs/zanzibar.md](docs/zanzibar.md): how a Zanzibar model is read and a check answered, how the
  answers are held to SpiceDB, and the patterns
- [docs/spicedb.md](docs/spicedb.md): the SpiceDB files Petard reads, and what a run on them
  prints
- [taxonomy-registry/README.md](taxonomy-registry/README.md): the format of a pattern file and
  what `verified` means
- [pep-registry/README.md](pep-registry/README.md): the format of an enforcement point
  declaration, and the ones the binary carries
- [fixtures/vulnerable-bundle/EXPECTED.md](fixtures/vulnerable-bundle/EXPECTED.md) and
  [fixtures/vulnerable-spicedb/EXPECTED.md](fixtures/vulnerable-spicedb/EXPECTED.md): what the
  analysis has to find in the demo fixtures, and what it must not
- [queries/README.md](queries/README.md): the saved queries, and what the BloodHound backend
  will and will not run
- [CHANGELOG.md](CHANGELOG.md): what changed between versions
- [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md): how to send a change, and
  how to report a vulnerability

## License

Apache-2.0. See [LICENSE](LICENSE).
