# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `petard analyze` lists, under the candidates, the questions that settle them: each path the self
  write or the global document reads that no write model covers, and what to find out about it, such
  as whether the subject can write it, add themselves to it, or who writes it at all. The self write
  questions come from the reads, so a partial write model still shows what it leaves open.
- `petard analyze -questions <file>` writes those questions as a write model to fill in: one entry
  per open path, with the subject's segment named and a principal to confirm, and an empty `via` to
  complete. It refuses to overwrite an existing file. Fill it in and rerun with `-write-model`.
- `petard analyze -v` shows, for a question that would open an escalation, who reaches whom and the
  request that proves it, run against a model where every open question is answered yes. It is what
  a yes would cost, shown before anyone declares the writer.
- `petard analyze -v` lists the writes a bundle authorizes: each branch of a decision that grants on
  a write method, PUT, POST, PATCH or DELETE, with the path it fixes and the decision that lets it
  through. A path segment the branch holds to a variable is shown as a `{name}` placeholder, so an
  endpoint addressed by record, `PUT /teams/{team}/members/{user}`, comes out whole. It
  is where a write model's `authorized_by` points, so declaring the write behind `PTD-OPA-006` starts
  from what the policy already describes. `-questions` writes those same endpoints into the skeleton
  as commented `authorized_by` blocks, to attach to the writer of the document each one changes.
- `petard analyze -v` prints, under each pattern that found something, the one line the registry
  holds in its `closes` field: what structurally makes the pattern not fire, which is where a fix
  starts. The line is a property of the pattern, not advice about a particular system.
- An escalation comes with a request that proves it, when asking the decision finds one: the
  decision refuses it as the data stands and grants it once the write is made. `petard analyze`
  prints it under the escalation as `proven by`, and `-v` adds the document the write changes, the
  value it puts there and, when a decision of the policy allows the write, the request it allows.
- `petard analyze -tests <file>` writes each of those proofs as an opa test. A test fails while
  its escalation is open and passes once it is closed, so it can stay in the suite afterwards.
  When a decision of the policy allows the write, the test asks that decision too, and refusing
  the write, which is how `PTD-OPA-006` is closed, makes it pass.
- The write model declares a part of the request as a list, the way a gateway sends the path of a
  call split into segments: `input.path: [teams, "{team_id}", members, "{user_id}"]`. For a write
  into an element of a list, a capture the path does not have names a field of that element.
  Declared by its method alone, such a write was asked about as any call with that method, which
  a decision that lets anybody call its health check allows.
- Without `-data`, `petard analyze` and `petard export` read the data a bundle keeps next to its
  policies, the files called `data.json`, `data.yaml` or `data.yml`, each at the path of its
  directory as OPA reads a bundle. The report says the data came from the bundle, and `-data`
  names other documents in its place.
- A bundle archive, such as the `bundle.tar.gz` that `opa build` writes, is read in place by
  `petard analyze` and `petard export`, and by `-data`: the policies and the data files inside it,
  with the size limit OPA applies to each file.
- `petard analyze` and `petard export` take the URL of a running OPA in place of a path, and read
  it over its API, read only, so the analysis is of what the server runs: the policies over
  `GET /v1/policies`, and, for each top-level document the decisions read, the data under it over
  `GET /v1/data/<root>`. The server is never asked to decide anything. A bearer token is read from
  `$PETARD_OPA_TOKEN`, and `-data` replaces the data read over the API.
- `PTD-OPA-011`, a decision grants on an identity somebody can assume: a check that grants on a part
  of the request the enforcement point asserts as a runtime identity, a workload's SPIFFE id for
  instance, where the declaration says who can assume it in another layer, such as whoever can deploy
  the service account the id names. It runs with `-pep`. An `assumable_by` entry on that part of the
  request turns the candidate into a finding, and an identity declared `pinned` to a verified
  credential is left alone. The declaration takes two new keys on a field, `identity` and
  `assumable_by`, with `pinned` for an identity nobody can assume. The fixture holds the case and the
  counter case in one decision: the sync service account and an agent identity bound to a verified
  credential, read the same way.
- `PTD-OPA-012`, a decision grants on a value matched more loosely than it is enforced: a check that
  grants on a resource or an action matched with `contains`, `startswith`, `endswith`, `glob.match`
  or an unanchored `regex.match`, so a crafted value satisfies the match but resolves to a different
  resource. A substring and an unanchored regex are findings, because a value embedding the written
  one passes; a prefix, a suffix or a glob is a candidate, often an intended wildcard. It reads the
  policy alone, needing no enforcement point and no data, and reports only the grant side. The
  fixture serves a document whose id merely embeds a marker.
- The engine reads the loose-match builtins, `contains`, `startswith`, `endswith`, `glob.match` and
  an unanchored `regex.match`, as checks on the request, where only `==` and `in` were read before.
  Besides `PTD-OPA-012` this closes a false negative in `PTD-OPA-009` and `PTD-OPA-010`: an exemption
  lifted by a prefix match, and a grant on a group name matched by a prefix or a glob, are now
  reported.
- `PTD-OPA-013`, a decision grants a requested authority not bounded by the delegator's: a granting
  decision mints the scopes a delegated agent asks for, bounding them by the agent's own role but not
  by the authority the delegating edge carries, so the agent mints scopes the delegating user never
  held. It asks the decision itself, pinning the requested authority within every declared ceiling
  and reaching one element past one of them, so the verdict holds whatever form the bound takes. It
  runs with `-pep` and the data, and the declaration takes two new keys on a field, `authority` and
  `bounded_by`, naming the requested authority and the ceilings it must sit under. A requested
  authority with no ceiling declared is a candidate. The fixture mints a credential bounded by the
  role and not by the edge.
- `petard explain` says what a pattern needs to run, the enforcement point declared with `-pep`,
  concrete data, or both, and what closes it, the `closes` line of its file.
- A decision that answers with one value of several, `default verdict := "scan"` next to
  `"allowed"`, `"blocked"` and `"clean"`, is declared with the answers it grants on, one
  `-entrypoint gate/verdict=allowed` for each, or with `answers` on the decision in an enforcement
  point declaration, which also takes `field` for a product that reads one field of the object a
  rule returns. Such a rule is defined for every request, its refusals included, and nothing in
  the policy says which answer is a grant. Declared this way the decision is asked for those
  answers alone, by the patterns that evaluate it and in the tests `-tests` writes, a rule that
  writes out another answer is on the side that refuses, and `-v` lists the decision with its
  answers. `-deny-entrypoint` takes an answer the same way, for the values a decision refuses on.
- `PTD-OPA-012` finds a decision that grants a path before it is canonicalized. An enforcement
  point declaration marks a part of the request the caller sets with
  `canonicalized_after_decision`, listing `dot-segments`, `percent-encoding` or both, when the
  value is acted on after they are collapsed. Every granting decision that reads the part is
  asked three requests: one it grants, the same with the path leaving the granted value through
  dot segments for a place outside it, and the same with the path set to that place. Granting
  the second and refusing the third is a finding at level `A`, with the request that proves it,
  whatever form the match and the guard take: a prefix the policy writes, one from the data, one
  taken from another part of the request. A candidate the form of the match left on the same
  decision and the same part is dropped. A decision that reads documents when none were given,
  or that OPA panics on, is a candidate saying so.
- `-action` and `-resource`, on `petard analyze` and `petard export`, declare the parts of the
  request that name what is asked for, as `-subject` declares who is asking, and an enforcement
  point declaration takes them as `action` and `resource`. A gateway that hands the policy the
  path of a call under `input.request.remainder_path` asks about a resource no field name gives
  away, and nothing read it: `PTD-OPA-012` stayed quiet and the graph had no resource to point
  at. A declared part is level `A`, declaring one of the two replaces what was recognized for
  both, and one no decision reads is refused on the command line.

### Changed

- The extension schema, now `v0.2.4`, shows on a `PTD_CanEscalateTo` edge the request that proves
  it, which the payload carries as `witness_request`, `witness_document`, `witness_value` and
  `witness_write_request`, and describes `PTD-OPA-011`, `PTD-OPA-012` and `PTD-OPA-013` in the Entity
  Panel, with two saved queries each. `petard export -install` puts the new schema in place.
- `petard analyze` and `petard export` no longer stop at a policy that annotates no entrypoint
  when no flag or `-pep` names one. The decisions are then the rules no other rule uses, and the
  report says they were inferred. A rule called `deny`, `violation` or `warn`, alone or with a
  suffix such as `deny_root`, is taken to deny, as conftest reads it. `-entrypoint` still names
  them.
- OPA v1.21.1 is compiled in, up from v1.20.2. It reads YAML against the 1.2 core schema: in a
  YAML document given with `-data`, and in the `data.yaml` or `data.yml` of a bundle, the bare
  words `y`, `n`, `yes`, `no`, `on` and `off` are strings, where they were booleans, so a decision
  on `data.settings.open == true` no longer holds over `open: yes`. It also types an empty object,
  array or set literal as empty, so a policy that selects a key from one, or iterates one, no
  longer compiles, and the analysis stops with the compiler's error.
- A write model, and an enforcement point declaration given with `-pep`, is refused when it holds
  a key its format does not have, and the error names the key and its line. Such a key was
  ignored: `identifer: name` in place of `identifier: name` dropped the `PTD-OPA-010` finding that
  rests on it and said nothing.
- The `kuadrant-mcp-gateway` declaration marks the `x-mcp-annotation-hints` header
  `identifier: name`, since the upstream server picks what the annotations of its tools say, so
  `PTD-OPA-010` reports a decision that compares the header with a value the policy writes.
- `petard analyze` heads its candidates `Candidates, which match a pattern and are not proven`,
  and without a write model says that a match resting on who writes a path stays a candidate.
  Both lines said every candidate waits for a write model, and some wait for the declaration of
  the enforcement point, or for a judgment.
- `petard` and `petard help` say what the tool is for and where to start, before the list of
  commands.
- `petard export` says, under the count of nodes and edges, what the analysis knows and the graph
  could not hold, in the lines `petard analyze -graph` prints: the declared writers that name a
  rule for finding somebody, the ways of granting that depend on something an edge cannot say,
  the findings about something the graph does not hold, and the questions OPA panicked on. A
  payload was written without them, and read as all the policy grants. Both commands write a
  count of one in the singular.
- `PTD-OPA-012` reports a loose match against a value the decision reads from the data,
  `contains(input.path, data.markers[_])`, where it reported only one against a value the policy
  writes: a substring as a finding, and a prefix, a suffix, a glob or a regex as a candidate. The
  value can be read where it is matched or out of a record a function is handed, and the finding
  names its path. `petard analyze -v` lists these matches after the checks on the request.
- A part of the request passed through `lower` or `upper` is read as that part, so a check made
  on the folded value, `contains(lower(input.path), "/admin")` or `upper(input.method) == "GET"`,
  is a check on `input.path` or `input.method`. The patterns that read the request,
  `PTD-OPA-009` to `PTD-OPA-012`, no longer miss a match made after a case fold.
- A part of the request read with `object.get` is followed as the field it names, through one
  call inside another too: `object.get(object.get(input, "parameters", {}), "exemptImages", [])`
  is `input.parameters.exemptImages`. A check on what the call returned is a check on that
  field, and a subject read this way picks the documents it indexes, so `PTD-OPA-001` and the
  patterns that read the request report on a policy that does not trust a request to be
  complete. A key the policy computes is followed as an element of the part it is looked up in,
  `object.get(input.current_spend, cost_center, 0)` as `input.current_spend[_]`, and is not
  followed when it is looked up in the request itself.

### Fixed

- An escalation was reported when the write, or what it opens, is allowed only to a requester who
  claims something an issuer sets, as if it were allowed to every principal. A claim is a part of
  the request next to the subject, as `input.subject.role` sits next to `input.subject.id`, or one
  `-pep` declares an issuer sets. Such an escalation, of `PTD-OPA-006` or of the chain from
  `PTD-OPA-001` to `PTD-OPA-003`, is now a candidate, and the report says what rests on the claim.
- A residual condition that negates an equality, such as `not input.action = "delete"`, was read
  as the equality it negates, as if it granted delete alone. Comparing two grants through such a
  condition could report a gain that is not there, or miss one that is. The negated field now
  counts as one the comparison cannot turn into values, so the gain is settled by evaluating the
  decision on concrete requests, as for a negation OPA could not inline.
- With data and no write model, `PTD-OPA-006` printed `nothing` under its title in `-v` and was
  missing from the patterns that did not run, so it read as a pattern that ran and found nothing.
  It is now listed among them, and says it needs a write model naming the decision that allows
  each write.
- `PTD-OPA-006` reported an escalation for a principal the decision behind the write refuses,
  when the decisions read nothing of the request but the parts the question fixes: who asks, the
  value written, the document it lands in. Whether that principal may make the write was then
  asked with the whole request left open, and answered for anybody who may. It happened for a
  value written into the subject's record and for a subject added to a collection, and drew
  `PTD_CanEscalateTo` edges nobody can walk. The question is now a plain yes or no about that
  request.
- A check on the request named something that is not a part of it, when a function tested a
  value a builtin had made of the request: `contains(object.get, "*")` for a host name read with
  `object.get`, or the name of a local list. `PTD-OPA-009` then reported candidates on parts no
  declaration of the enforcement point can cover. A check is now read only where it names a
  part of the request.
- A count of one is written in the singular: `1 read over 1 data path`, `graph: 1 node, 1 edge`,
  `against 1 data document`.
- `PTD-OPA-012` read a regex by its first and last character and a glob by its name. A regex
  anchored at the start alone, `^/admin`, was a finding on a value said to embed the pattern, and
  is a candidate, the prefix it is. An alternation that pins one end in each branch,
  `^/public|/health$`, was taken for anchored and not read, and is a candidate too. A glob with a
  wildcard at each end, `*admin*`, was a candidate and is a finding, like the substring it is. A
  glob with no wildcard is read as the equality it is, and is no longer reported.
- `PTD-OPA-007` reported an `every` guarded against the empty case by anything but a count of
  the domain next to it: an iteration of the domain, a `some` that binds an element, a count in
  another rule the decision also asks for. Each match is now put to the decision, with the domain
  empty and the rest of the request left open, and dropped when nothing can make the decision
  hold. A match that cannot be asked about stays as before: a domain in the data or under an
  element of a list, a decision declared to deny, a decision that reads documents when none were
  given. `petard analyze -v` names the domain on the line of each place to look, where it left
  a blank.
- `PTD-OPA-009` reported a finding at level `A` on a part of the request read under a key the
  policy computes, `not input[data.settings.flag]`, whenever a catch-all entry of the declaration
  gives the request to the caller, though an entry before it gives one field, the second factor
  for one, to the enforcement point. Such a part stands for every field the key could name, and
  is now a finding only where every entry that covers one of them says the caller sets it, and a
  candidate where they disagree.
- `PTD-OPA-013` did not run without data, even where the decisions it asks read none, as in a
  token service that decides on the request alone, and an empty document was no way round it. It
  now runs with no data given when no decision that reads a requested authority reads a
  document, and still says the data is missing when one does. Without `-pep` it says the
  enforcement point is what it needs, whatever the data.
- A `PTD-OPA-013` result carried the level the subject was recognized at, `D` on the fixture,
  though it rests on the declaration of the enforcement point and on no subject. It carries level
  `A`, as the results of `PTD-OPA-009`, `PTD-OPA-010` and `PTD-OPA-011` that rest on the same
  declaration do.
- `PTD-OPA-013` asked only a decision that ranges over the requested authority with an `every`
  in the rule itself. One that bounds it by the role alone with `object.subset`, a set difference,
  a count of the offenders or an `every` inside a function went unreported, and so did one that
  bounds it by nothing. Every granting decision that reads the requested authority is now asked,
  and a finding names each ceiling the decision does not enforce.
- A field read through the parameter of a function was not a read: `privileged(user)` testing
  `user.role`, called with `data.users[input.user]`, left the role out of what the decision
  reads, so `PTD-OPA-001` reported nothing on a role the subject can write, and no write model
  entry on the field could apply. The read is now made of each document a call hands over, a
  comparison of the field with the requester is a lookup by value as it is in the body that
  names the document, and a field of a part of the request handed to a function is a check on
  that part. Policies that keep their tests in functions report more checks and more reads.
- `PTD-OPA-012` said nothing about a decision that grants on a loosely matched path unless some
  decision of the bundle also read a field named like a subject, and nothing at all when the
  subject was declared with `-subject` or by the enforcement point: the resource and the action
  were recognized only along with a subject. They are now recognized on their own, and `-v`
  prints them on a line of their own, `asked for:`, when the request shape names neither.
- A decision whose default is a value other than `true` or `false`, such as `default result :=
  {"decision": "deny"}`, was taken to grant a fixed request whatever it answered, the default
  included, because a defined value holds. `PTD-OPA-013` then reported a decision that bounds the
  requested authority by every ceiling. Such a decision now grants a request it answers with
  anything other than its default, which is how the conditions partial evaluation leaves of it
  were already read, and the report names the decision and that reading under `How much to trust
  this`.
- `petard analyze` and `petard export` ended in a Go panic on a decision OPA panics on: OPA
  v1.21.1 panics on the partial evaluation of a negated rule whose body holds an `every` over a
  value left unknown. The pattern that asked is now reported as not applied, with the decision
  and the panic, `-v` says the same on the decision's row of residual conditions, and the graph
  counts the questions it could not ask.
- Declaring the subject, with `-subject` or in the declaration of an enforcement point, left the
  request with no action and no resource, so the graph drew no `PTD_CanPerform` edge: on the
  fixture 46 capabilities became none, and every way of granting was counted as left out. The
  action and the resource are now recognized under a declared subject as they are without one,
  and each capability edge carries the weaker of the two levels.
- An entry of an enforcement point declaration answered for the part of the request it names and
  for nothing inside it, so a field of that part fell to a later entry. With `input.user` set by
  an issuer and `input.*` by the caller, `not input.user.vip` was a `PTD-OPA-009` finding at
  level `A`, on a field said to be the caller's. An entry now answers for the part it names and
  for whatever is inside it, and an entry ahead of it that names one field still answers for that
  field.

## [0.4.0] - 2026-09-30

### Changed

- A `PTD_CanEscalateTo` edge is drawn by comparing what each position grants, not by counting the
  residual conditions of a decision. A principal who can add themselves to a policy reaches another
  only when that policy grants a request they could not already make, so one who already grants
  everything is no longer reported joining a narrower policy. A gain that depends on a condition
  the comparison cannot read, a builtin or a truth test, is a candidate rather than a finding.
- `PTD-OPA-006` reaches a third shape: a decision that grants on a field of a list element the
  requester is matched to by value on another field of the same element, such as the role of the
  member whose user is the requester. When one decision authorizes setting that field below the
  threshold another reads to grant, a member sets their own to the granting value and reaches the
  position of whoever holds it. The comparison of a request field against a list is read element by
  element, so two paths that differ at a fixed segment are told apart.

### Fixed

- A residual condition holding `not data.partial.__not1_0_2__`, the rule OPA generates for a
  negation it cannot inline, was read as if that part were not there, and a gain or a coverage that
  rested on it was reported as certain. A policy written `allow` and `not deny` carries its deny in
  that form into every condition when the deny cannot be inlined. Petard now checks such a gain by
  evaluating the decision, before and after the write, on the requests the rest of the condition
  names. A request granted after and refused before makes it a finding; without one it stays a
  candidate, and a coverage through such a condition is no longer taken as certain.
- A rule with an `else` moves on to the next branch when a branch's condition holds but its value is
  undefined, as OPA does. In `region := input.region if input.verified else := "unknown"`, a
  verified request without a region got an undefined `region` instead of `"unknown"`, and a
  decision behind such a rule missed the way through the `else`.
- The analysis reads every leg of an `else`, where it used to stop at the first. A document read
  only in a later leg, or a value from an external source that only the `else` returns, went
  unreported; both now reach the decisions behind the rule.

## [0.3.0] - 2026-09-25

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

- The extension schema, now `v0.2.3`, describes `PTD-OPA-009` and `PTD-OPA-010` in the Entity
  Panel, and two saved queries ask for each: `petard export -install` puts them in place.

### Fixed

- `petard demo -v` prints the same report on every run. The header of the table of reads was
  padded for the path of the temporary directory the bundle is unpacked into. That directory has a
  random name, so the header sat out of line with the rows by a different amount each time.
- A read of an element by its position, such as `data.admins[0]`, no longer stops
  `petard analyze`. The position is one segment, the same as in `data.admins["0"]`, because OPA's
  store looks both up under the key `"0"`. A write model can name it either way.

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
