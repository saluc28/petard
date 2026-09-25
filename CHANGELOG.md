# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `petard analyze -v` lists the checks on the request: every place a decision holds a part of the
  request against a value the policy writes, as `input.session.teams[_] == "DevOps"` or
  `not input.emergency`, and whether the check holding grants, refuses or lifts a refusal.
  `petard measure` counts them, and how many lift a refusal.
- `-pep` on `analyze` and `export`, which names the product that asks for the decisions: the
  decisions are declared by the names it asks for and the side each lands on, the subject by where
  it puts the requester, and the summary says how much of the request the declaration speaks
  about. `pep-registry/` holds the first two, the login policy of Spacelift and the MCP Gateway of
  Kuadrant with the OPA authorization of Authorino.
- `PTD-OPA-009`, a request lifts a check on itself by saying it is exempt: a check on a part of
  the request that lifts a refusal, where the enforcement point declares that the caller sets that
  part. It runs with `-pep`. The fixture holds its case and its counter case in one rule, and
  `fixtures/vulnerable-bundle/pep.yaml` declares the gateway in front of it.
- `PTD-OPA-010`, a decision grants on a name somebody else picks: a check that grants on a part of
  the request an issuer sets, where the enforcement point declares that the issuer puts a name
  there, such as the name of a group. It runs with `-pep`. An entry of the write model on that part
  of the request, `input.groups[_]` in the fixture, says who can make the issuer say a name and
  turns the candidate into a finding. Such an entry adds no writer to a document and does not count
  towards coverage. The fixture holds the case and the counter case in one decision: the same group
  by its name and by the id the directory assigned it.

### Changed

- The extension schema describes `PTD-OPA-009` and `PTD-OPA-010` in the Entity Panel, and two
  saved queries ask for each: `petard export -install` puts them in place.

### Fixed

- `petard demo -v` prints the same report on every run. The header of the table of reads was
  padded for the path of the temporary directory the bundle is unpacked into. That directory has a
  random name, so the header sat out of line with the rows by a different amount each time.

## [0.2.1] - 2026-09-25

### Fixed

- A policy that imports the `not`, `and` or `or` keyword is read in full. With `not` imported,
  every negation in a module parses to a form the analysis did not go into, so the reads under
  it were missing from the report, and with them findings of `PTD-OPA-002`, `PTD-OPA-004` and
  `PTD-OPA-005`. The fixture with that one import added now reports what it reports without it.
- Partial evaluation answers for a rule written with `and` or `or` the way it answers for the
  same rule written as separate bodies: with the requests that make it hold, rather than with
  the documents its operands read.
- A read of a key that is not a bare name, such as `data.inventory.cluster["storage.k8s.io/v1"]`,
  no longer stops `petard analyze`. The key is one segment, the way OPA parses it, and a write
  model can name it in the same notation.
- The analysis follows a value into an argument the head of a function takes apart, as
  `collab([user, project])` does. A lookup of the requester made there was missing from the
  report, and a document picked there with what the caller passes was reported as unresolved.

## [0.2.0] - 2026-09-23

### Added

- `petard patterns`, which lists the taxonomy grouped by the category each pattern belongs to,
  with `-format json` for whatever reads a list of ids.
- `petard explain <id or name>`, which prints one pattern in full: what it looks for signal by
  signal, what has to be true for a match to be a defect, the conditions it fires on with
  nothing behind it and how each was settled, and where the file is.
- A summary at the top of `petard analyze`: the escalations first, with who takes whose place,
  what they write and through which endpoint, then the findings counted per pattern, then one
  line on how much of it to believe. `-v` prints the evidence under it, which is what the
  report used to be.
- `-fail-on findings|any|none` and the exit codes that go with it: 3 for matches above the
  threshold, 1 for an analysis that could not run, 2 for a command line that made no sense.
- `-quiet`, which prints the escalations and the findings alone and nothing at all when there
  are none, and `-no-color`, next to `NO_COLOR` and a check that the output is a terminal.
- The registry travels inside the binary, so a report names every pattern by its title and
  `explain` and `patterns` work without a checkout.
- `petard help <command>` prints the flags of that command.

### Changed

- `petard analyze` exits 3 when it has findings to report. It used to exit 0 whatever it found,
  which left it unusable as a gate. `-fail-on none` restores the old behavior.
- `-registry` now means "read the patterns from this directory instead of the ones built in",
  and a directory with no pattern in it is an error rather than a report with the titles
  silently missing.
- `petard demo` takes `-v` as well, and reports without failing over the escalations the bundle
  was written to have.

## [0.1.0] - 2026-09-21

### Added

- `petard`, one binary with subcommands: `analyze`, `export`, `measure`, `demo` and
  `version`, which reports the build and the versions of OPA and bhgraph compiled into
  it, since those decide what an analysis says.
- `petard analyze`, which reads an OPA bundle in either Rego syntax and reports what its decisions
  depend on: every read of `data` with the reference, the file and the line, who chooses the
  document each read lands on, the values the policy did not compute, and the shape of the
  request with the level it was recognized at. Given concrete data it evaluates each decision
  partially and reports what is left of it.
- The taxonomy registry, eight patterns as versioned data under `taxonomy-registry/`, each with
  the conditions under which it stays quiet and the cases it has been held to. Two of them end
  in a `PTD_CanEscalateTo` edge between two principals.
- The write model, which declares who can write which path, since no policy says it. Without one
  every match stays a candidate, and the run reports how much of what the decisions read the
  model covers.
- `petard export`, which sends the same analysis to BloodHound CE as a structured OpenGraph:
  it installs the extension schema and the saved queries, uploads the payload, and with
  `-verify` asks the server to walk every escalation the payload declares. `-prune-queries`
  removes saved queries a rename left behind.
- The extension definition schema in `schema/petard.json`, generated from the model, with five
  node kinds, five relationship kinds, and what BloodHound shows in the Entity Panel for each.
- 29 saved Cypher queries under `queries/`, two to four per pattern, in the format of the
  BloodHound Query Library.
- `petard measure`, which runs the engine over a body of Rego written by somebody else.
- `petard demo`, which analyzes the vulnerable bundle carried inside the binary, so a
  release can be tried without a policy of your own. `-extract` writes the bundle to disk.
