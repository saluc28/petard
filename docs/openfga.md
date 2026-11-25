# OpenFGA

The OpenFGA files Petard reads, how it reads them, and what a run on them prints.
[zanzibar.md](zanzibar.md) is how the engine answers a check and the patterns it applies.

## The files

`petard analyze` reads these OpenFGA files under the paths it is given, beside any policy or
SpiceDB schema there:

- a model in the DSL, ending in `.fga`;
- a modular model: an `fga.mod` and the modules it lists, which are not read as models of their
  own;
- a model in JSON, a mapping that holds `schema_version` and `type_definitions`;
- a store file, the YAML format `fga model test` reads
  (`internal/storetest/storedata.go:45-89` at openfga/cli v0.9.0): a `model` written inline or a
  `model_file` naming one, the `tuples` written against it, written inline or named by `tuple_file`
  and `tuple_files`, and the `tests`.

A file named `.fga.yaml` is read as a store file. Any other YAML file is, when every top-level key
is one of those of a store file and it holds a model or names one. Any other YAML or JSON file is
left alone, and so is a directory whose name starts with a dot. A file named on the command line is
read the same way, on its own.

A directory of modules with no `fga.mod` is not read as one model: a directory may hold models that
are not one, so petard does not combine modules on its own. An application that assembles its modules
in code, and so ships no `fga.mod`, can hand petard the model it builds as JSON, which petard reads as
it is; the refusal says so, and shows an `fga.mod` that lists the modules found under the path if you
would rather write one.

A tuple file can be JSON, YAML, JSONL or CSV, the formats fga reads
(`internal/tuplefile/read.go:37-49` at openfga/cli v0.9.0). A tuple the model does not admit stops
the run, since `fga model test` would have OpenFGA refuse it.

A check of a test can carry the context it supplies:

```yaml
tests:
  - name: the roadmap
    check:
      - user: user:vic
        object: document:roadmap
        context:
          user_ip: 192.168.0.1
        assertions:
          view: false
```

Those contexts, and the contexts the tuples carry, are the evidence `PTD-ZAN-001` reads for a
candidate. A `writes.yaml` beside the model, a `relationship-writes` write model, turns it into a
finding: it says who writes a relation and, per condition parameter, whether the writer or the
application fills it. A test that brings tuples of its own is a state of its own, because
`fga model test` sends those tuples with that test's checks alone
(`internal/storetest/localtest.go:237-265` at openfga/cli v0.9.0), so it is one analysis more. A
check that asks with a wildcard is left out. The `list_objects` and `list_users` tests are not
read: they say nothing a check does not.

Models are compiled with OpenFGA's own language module, v0.3.2, and validated with OpenFGA's own
type system, from OpenFGA v1.23.0, which `petard version` names. A model that does not compile
stops the run, as a policy that does not parse does, and so does one OpenFGA would refuse to store.

Nothing outside the paths given is read. The files are opened through an `os.Root`, so a link that
leads out of a directory is refused rather than followed. A `model_file`, a module or a tuple file
is resolved against the directory of the file that names it, and one that is absolute or climbs out
of the directory analyzed is refused.

Conditions are evaluated with OpenFGA's own compiled conditions, so `ipaddress` and `in_cidr` behave
as they do there (`internal/condition/types/ipaddress.go:45-49` at v1.23.0). A parameter the context
leaves out stays unknown, and a condition that depends on it is conditional. A tuple with an inline
`$expression`, which OpenFGA takes only behind an experimental flag (`pkg/server/write.go:58-66` at
v1.23.0), reads as conditional: its expression is not evaluated.

## A running OpenFGA

A store of a running OpenFGA can be named in place of a path, as `openfga://host:port/store`, or
`openfga+insecure://host:port/store` over plaintext for a local development server without a
certificate. `/model` after the store reads a model other than the latest. The address is the gRPC
one. Petard reads the model and a sample of up to 1,000 tuples, read only, so a finding can rest on
what the store holds and not only on the positions the model generates. It never asks the server to
check anything, and the offline default is untouched: nothing connects unless a path names an
endpoint.

```
petard analyze openfga://localhost:8081/01HVMMBCMGZNT3SED4Z17ECXCA
```

This is how a model that lives only inside a running OpenFGA is analyzed. A tuple the model does not
admit is left out, as a check of OpenFGA leaves it out (`internal/validation/validation.go:379-384`
at v1.23.0). The server returns the compiled form, which holds no positions, so what the report says
names the endpoint alone. A bearer token the server needs is read from `$PETARD_OPENFGA_TOKEN`, and
the insecure scheme also lets that token reach a local server over plaintext.

A store has no directory beside it to hold a `writes.yaml`, so a write model for it comes from
`-write-model`. Without one the model is read as one with no evidence, and petard proposes the safe
gates to start a write model from.

## A run

`fixtures/vulnerable-openfga` holds a model of a documents service and a store file for it, written
by hand with a case and a counter case for each pattern in them, and
`fixtures/vulnerable-openfga/EXPECTED.md` says what an analysis has to find there. It is the service
of the SpiceDB fixture. `petard demo openfga` analyzes it on its own, and `petard demo` beside the
other fixtures.

<!-- output of: petard analyze fixtures/vulnerable-openfga -->
```
2 OpenFGA files
  fixtures/vulnerable-openfga/model.fga       4 types, 12 relations, 2 conditions
  fixtures/vulnerable-openfga/store.fga.yaml  store file of fixtures/vulnerable-openfga/model.fga, 5 tuples, 7 checks

Findings
    2  PTD-ZAN-001  A relationship fixes a condition value the check was meant to supply
    1  PTD-ZAN-002  Deleting a tuple an exclusion reads lifts the deny
    3  PTD-ZAN-003  A wildcard subject grants a relation to every object of a type
    2  PTD-ZAN-004  An arrow links an object to one the coalition holds a permission on
    3  PTD-ZAN-005  Joining a group an object grants to takes on its access
    6  PTD-ZAN-006  A gated write grants to another a right the writer never held
    4  PTD-ZAN-007  A weaker permission gates writing a stronger one into the object
    4  PTD-ZAN-008  A subject writes itself a relation behind an open gate

  document#viewer, user_ip of condition ip_allowlist  (PTD-ZAN-001)
    written by   anyone may write document#viewer, at fixtures/vulnerable-openfga/model.fga:24:12,
                 with ip_allowlist, through POST /api/v1/documents/{id}/viewers
    the check brings user_ip, which the writer may set on the tuple instead, fixing it for every check
                 that goes through
    raises       view, access and viewer on document, from conditional to unconditional
```

They are findings because `fixtures/vulnerable-openfga/writes.yaml` is a write model beside the
model. The run reads as a run on a SpiceDB schema does, and [spicedb.md](spicedb.md#a-run) says what
each line means. A SpiceDB schema keeps a permission apart from a relation, and a check asks for the
permission. OpenFGA keeps both under one name, and a check can ask for any of them, so a raise is
reported on the relation as well as on what reads it:
`viewer` beside `view` on a document, and `member` on a team. Two kinds of relation stay
out of that, one an arrow walks and one read only to subtract it, because holding one opens nothing.

Without a write model the two `PTD-ZAN-001` matches are candidates instead, read off the tuples and
the checks, and the candidate carries the check whose answer rises once a tuple fixes the parameter.
The escalations rest on who writes a relation, which only a write model says, so with none they are
not reported at all.

## The write model it proposes

A relation the write model leaves without a rule is one no coalition can write (section 4.3 of the
definitions), and petard proposes a gate for it, the relations that let no coalition raise anything
when their holders write it.

<!-- output of: petard analyze fixtures/vulnerable-openfga -->
```
Relations with no write rule
  folder#viewer   can raise 4  safe to gate on viewer
  document#owner  can raise 4  safe to gate on owner
  folder#parent   can raise 3  safe to gate on view, viewer
```

`owner` is the safe gate for `document#owner`, where on the SpiceDB fixture it is `edit`: a holder of
`edit` who makes itself owner raises `owner`, which a check of OpenFGA can ask. The gates, and
`-questions <file>`, work as they do for a schema, and [spicedb.md](spicedb.md#the-write-model-it-proposes)
has the details. For an OpenFGA model the skeleton proposes `create`.

A tuple of OpenFGA carries no expiration (`openfga/v1/openfga.proto:161-199` in openfga/api at
c0650ce2169b), so the `expiration` field of a write rule has nothing to apply to.

## How a finding is held

The test suite holds the findings on the fixture to OpenFGA itself, with a server from `pkg/server`
running in the test process and nothing reached over a network. It writes Vic's tuple with the
address set, the write the finding describes, and `Check` allows the check from `192.168.0.1`, and
one that supplies no address. For every escalation the engine finds, it makes the writes of the
witness on a real store, and `Check` does not allow the relation before them and allows it after.

```
go test ./internal/zanzibar/openfga -run TestFixture -v
```

[zanzibar.md](zanzibar.md#held-to-openfga) has how the engine's answers are held to the same server
over every check the objects allow.

`-proofs <dir>` writes each escalation as a store file, with one test for each point of its witness
where something is asked, and `fga model test` passes on it while the escalation is open:

```
petard analyze -proofs proofs fixtures/vulnerable-openfga
fga model test --tests "proofs/*.fga.yaml"
```

A check that waits on a condition is asked under a context one of the store's own checks supplies,
since OpenFGA answers it with an error otherwise. [zanzibar.md](zanzibar.md#proofs) has what a proof
holds and when an escalation has none.

## In a pipeline

A match on a model with a write model beside it is a finding, which fails a run by default. A match
with no write model is a candidate, which `-fail-on any` fails on:

```
petard analyze -quiet -fail-on any path/to/models
```

The exit codes are those of any run: 0 when nothing is above the threshold, 3 when something is, 1
when the analysis could not run, and 2 for a command line that is wrong.
