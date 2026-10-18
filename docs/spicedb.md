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

Those contexts, and the contexts the relationships carry, are what `PTD-ZAN-001` takes its
evidence from. Petard counts the expected relations of a file and does not read them.

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
`fixtures/vulnerable-spicedb/EXPECTED.md` says what an analysis has to find there. `petard demo`
analyzes it beside the policy fixture.

<!-- output of: petard analyze fixtures/vulnerable-spicedb -->
```
2 SpiceDB files
  fixtures/vulnerable-spicedb/schema.zed       3 definitions, 4 relations, 2 permissions, 2 caveats
  fixtures/vulnerable-spicedb/validation.yaml  validation file of fixtures/vulnerable-spicedb/schema.zed, 5 relationships, 9 assertions

Findings
  nothing

Candidates, which match a pattern and are not proven
    2  PTD-ZAN-001  A relationship fixes a caveat value the check was meant to supply

  document#editor, now of caveat not_expired  (PTD-ZAN-001)
    written on   document#editor at fixtures/vulnerable-spicedb/schema.zed:25:3, and whoever writes
                 it chooses the context of not_expired
    supplied by  2 checks of the file, the first at fixtures/vulnerable-spicedb/validation.yaml:15:7
    shown by     document:roadmap#edit@user:erin with {"now":"2026-12-01T00:00:00Z"}, at
                 fixtures/vulnerable-spicedb/validation.yaml:20:7, goes from no to yes once
                 document:roadmap#editor@user:erin carries
                 {"now":"2026-10-20T00:00:00Z","until":"2026-11-01T00:00:00Z"}

  document#viewer, user_ip of caveat ip_allowlist  (PTD-ZAN-001)
    written on   document#viewer at fixtures/vulnerable-spicedb/schema.zed:26:3, and whoever writes
                 it chooses the context of ip_allowlist
    supplied by  2 checks of the file, the first at fixtures/vulnerable-spicedb/validation.yaml:14:7
    shown by     document:roadmap#view@user:vic with {"user_ip":"192.168.0.1"}, at
                 fixtures/vulnerable-spicedb/validation.yaml:19:7, goes from no to yes once
                 document:roadmap#viewer@user:vic carries {"cidr":"10.0.0.0/8","user_ip":"10.1.2.3"}

Run petard explain <id> for what a pattern looks for and what it will not report.
```

The run lists what each file declares, then the matches. Each match names a relation, a
parameter and the caveat it belongs to, and under it:

- `written on` is where the schema lets the relation carry the caveat. Whoever writes a
  relationship of it writes the context too.
- `supplied by` counts the checks of the file that supply the parameter, which is the evidence it
  is meant for the check. Where no check supplies it, `left by` counts the relationships of the
  relation that leave it out instead.
- `written by`, when it is there, counts the relationships of the relation that write the
  parameter already, so a parameter meant to be written by some writers reads as that.
- `shown by` is the witness: a check of the file, the answer it has now, and the answer it has
  once the relationship carries the context given.

## Repeating a witness with zed

A witness is a change to the validation file, and `zed validate` checks it. Write Vic's
relationship the way `shown by` says:

```
document:roadmap#viewer@user:vic[ip_allowlist:{"cidr":"10.0.0.0/8","user_ip":"10.1.2.3"}]
```

and run zed v1.2.1 on the file:

```
zed validate validation.yaml
```

zed now fails on two assertions: Vic is no longer refused from `192.168.0.1`, the check `shown by`
names, and the view is no longer caveated, since the relationship settles the caveat whatever the
check brings.

## In a pipeline

Every match on a SpiceDB schema is a candidate, so `-fail-on any` is what fails a run on one:

```
petard analyze -quiet -fail-on any path/to/schemas
```

The exit codes are those of any run: 0 when nothing is above the threshold, 3 when something is,
1 when the analysis could not run, and 2 for a command line that is wrong.
