# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- A policy that imports the `not`, `and` or `or` keyword is read in full. With `not` imported,
  every negation in a module parses to a form the analysis did not go into, so the reads under
  it were missing from the report, and with them findings of `PTD-OPA-002`, `PTD-OPA-004` and
  `PTD-OPA-005`. The fixture with that one import added now reports what it reports without it.
- Partial evaluation answers for a rule written with `and` or `or` the way it answers for the
  same rule written as separate bodies: with the requests that make it hold, rather than with
  the documents its operands read.

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
