# SpiceDB

The SpiceDB files Petard reads, how it reads them, and what a run on them prints.
[zanzibar.md](zanzibar.md) is how the engine answers a check and the patterns it applies.

## The files

`petard analyze` reads two kinds of SpiceDB file under the paths it is given, beside any policy
there:

- a schema file, ending in `.zed`;
- a validation file, the YAML format `zed validate` reads (`pkg/validationfile/fileformat.go:21-47`
  at v1.56.2): a `schema` written inline or a `schemaFile` naming one, the `relationships` written
  against it, the `assertions` checked against them, under `assertTrue`, `assertFalse` and
  `assertCaveated`, and the expected relations under `validation`.

A YAML file is read as a validation file when every top-level key is one of those five and it
holds or names a schema. Any other YAML file is left alone, and so is a directory whose name
starts with a dot. A file named on the command line is read the same way, on its own.

An assertion can carry the context of its check after `with`, as JSON:

```yaml
assertions:
  assertFalse:
    - 'document:roadmap#view@user:vic with {"user_ip": "192.168.0.1"}'
```

Those contexts, and the contexts the relationships carry, are the evidence `PTD-ZAN-001` reads
for a candidate. A `writes.yaml` beside the schema, a `relationship-writes` write model, turns it
into a finding: it says who writes a relation and, per caveat parameter, whether the writer or the
application fills it. Petard counts the expected relations of a file and does not read them.

Schemas are compiled with SpiceDB's own compiler, from SpiceDB v1.56.2, which `petard version`
names. A schema that does not compile stops the run, as a policy that does not parse does, and so
does one that names a type, a relation, a permission or a caveat it does not declare, or that
walks a permission or a wildcard with an arrow. A schema reads its imports from its own
directory, and SpiceDB refuses an import path that holds `..` or is not local
(`pkg/schemadsl/compiler/importer.go:35-50` at v1.56.2).

Nothing outside the paths given is read. The files are opened through an `os.Root`, so a link
that leads out of a directory is refused rather than followed. A `schemaFile` is resolved against
the directory of its validation file, as SpiceDB resolves it
(`pkg/validationfile/loader.go:153-158` at v1.56.2), and one that is absolute or climbs out of the
directory analyzed is refused. So is a validation file that holds a schema and names a
`schemaFile` as well, which SpiceDB refuses too (`pkg/validationfile/loader.go:124-126` at
v1.56.2).

Caveats are evaluated with SpiceDB's own caveat package, in the CEL environment SpiceDB uses, so
`ipaddress` and `in_cidr` behave as they do there. A parameter the context leaves out stays
unknown, and a caveat that depends on it is conditional.

## A run

`fixtures/vulnerable-spicedb` holds a schema of a documents service and a validation file for it,
written by hand with the case and the counter case of `PTD-ZAN-001` in them, and
`fixtures/vulnerable-spicedb/EXPECTED.md` says what an analysis has to find there.
`petard demo spicedb` analyzes it on its own, and `petard demo` beside the policy fixture.

<!-- output of: petard analyze fixtures/vulnerable-spicedb -->
```
2 SpiceDB files
  fixtures/vulnerable-spicedb/schema.zed       4 definitions, 8 relations, 4 permissions, 2 caveats
  fixtures/vulnerable-spicedb/validation.yaml  validation file of fixtures/vulnerable-spicedb/schema.zed, 5 relationships, 9 assertions

Findings
    2  PTD-ZAN-001  A relationship fixes a caveat value the check was meant to supply
    1  PTD-ZAN-002  Deleting a tuple an exclusion reads lifts the deny
    2  PTD-ZAN-003  A wildcard subject grants a relation to every object of a type
    2  PTD-ZAN-004  An arrow links an object to one the coalition controls
    2  PTD-ZAN-005  Joining a userset a relation grants to takes on its access
    3  PTD-ZAN-006  A gated write grants to another a right the writer never held
    1  PTD-ZAN-007  A weaker permission gates writing a stronger one into the object
    2  PTD-ZAN-008  A subject writes itself a relation behind an open gate

  document#viewer, user_ip of caveat ip_allowlist  (PTD-ZAN-001)
    written by   anyone may write document#viewer, at fixtures/vulnerable-spicedb/schema.zed:33:3,
                 with ip_allowlist, through POST /api/v1/documents/{id}/viewers
    the check brings user_ip, which the writer may set on the relationship instead, fixing it for every
                 check that goes through
    raises       view and access on document, from conditional to unconditional

  document#editor, now of caveat not_expired  (PTD-ZAN-001)
    written by   whoever holds view may write document#editor, at
                 fixtures/vulnerable-spicedb/schema.zed:32:3, with not_expired, through POST
                 /api/v1/documents/{id}/editors
    the check brings now, which the writer may set on the relationship instead, fixing it for every
                 check that goes through
    raises       edit, view and access on document, from conditional to unconditional

  document#access, a deny lifted by a delete  (PTD-ZAN-002)
    written by   anyone may delete document#banned, through DELETE
                 /api/v1/documents/{id}/bans/{user}
    raises       access on document, from no to yes
```

They are findings because `fixtures/vulnerable-spicedb/writes.yaml` is a write model beside the
schema. The run lists what each file declares, then a count per pattern, then the matches. Two
kinds of finding come out of it.

`PTD-ZAN-001` is the caveat finding, a parameter the check was meant to bring and the writer can
fix instead. Each match names a relation, a parameter and the caveat it belongs to, and under it:

- `written by` is who the write model lets write the relation, and where the schema declares it.
  SpiceDB lets a write carry any parameter of the caveat and the written value wins over the
  check's, so that writer can fix the parameter.
- `the check brings` is the parameter the write model marks the application's, the one the writer
  sets instead.
- `raises` is the permissions the relation feeds, which go from conditional to unconditional once
  the parameter is fixed.

`PTD-ZAN-002` through `PTD-ZAN-008` are the escalation findings, one per kind of decisive write a
coalition can make: deleting a tuple an exclusion reads, writing a wildcard subject, linking an
object across an arrow, joining a userset, writing a grant for another, and writing itself in
behind a gate that is a permission or none. Each names the permission it raises and, under it:

- `written by` is who the write model lets make the write, and the endpoint it goes through.
- `raises` is the permission the write lifts on the object, from no to yes.

The heading says the kind of write in a few words, and the id says which pattern classified it.
`petard explain <id>` has the full account of each.

Without a write model the two `PTD-ZAN-001` matches are candidates instead, read off the
relationships and the checks: a parameter a check of the file supplies and the relationships leave
out is one meant for the check, and the candidate carries the check whose answer rises once a
relationship fixes it. The escalations rest on who writes a relation, which only a write model
says, so with none they are not reported at all.

## Repeating a witness with zed

The finding says the writer can fix `user_ip`, and `zed validate` shows what that does. Write
Vic's relationship with the address set, which is the write the finding describes:

```
document:roadmap#viewer@user:vic[ip_allowlist:{"cidr":"10.0.0.0/8","user_ip":"10.1.2.3"}]
```

and run zed v1.2.1 on the file:

```
zed validate validation.yaml
```

zed now fails on two assertions: Vic is no longer refused from `192.168.0.1`, and the view is no
longer caveated, since the relationship settles the caveat whatever the check brings.

## In a pipeline

A match on a schema with a write model beside it is a finding, which fails a run by default. A
match with no write model is a candidate, which `-fail-on any` fails on:

```
petard analyze -quiet -fail-on any path/to/schemas
```

The exit codes are those of any run: 0 when nothing is above the threshold, 3 when something is,
1 when the analysis could not run, and 2 for a command line that is wrong.
