# Enforcement point registry

A policy reads `input.session.teams` and has no way to know where the teams came from. The
product that builds the request does: Spacelift puts the names of the user's GitHub teams there,
and the MCP Gateway of Kuadrant writes the name of the tool the client called into a header
before Authorino evaluates the policy. Whether a check on the request can be met by whoever sends
it or by whoever can make an identity provider say something depends on which of the two it is,
and that is written in the code or the documentation of the product.

Each file here declares one product: the decisions it asks the engine for, the part of the
request that names who is asking, and who puts each part of the request there. Every claim
carries where it was read, a file and a line at a tag when the product is open source, a page of
its documentation and the day it was consulted when it is not.

```
petard analyze -pep spacelift-login path/to/login.rego
petard analyze -pep path/to/your-gateway.yaml path/to/policy
```

`-pep` takes the id of a file in this directory, which the binary carries, or the path to a file
of your own in the same format. With it the decisions do not have to be declared one by one, the
subject is declared rather than recognized, and the patterns that ask who sets a part of the
request get an answer.

## The format

| Field | What |
|---|---|
| `schema_version` | `1` |
| `id` | the name `-pep` takes, and the name of the file |
| `title` | one readable line |
| `engine` | `opa` |
| `source` | `kind`, `source` or `documentation`, and a `note` saying at which version |
| `decisions` | the rules the product asks for, by `rule` name in whichever package the policy declares, each with the `side` its answering yes lands on, `grants` or `denies` |
| `subject` | the part of the request that names who is asking |
| `fields` | who puts each part of the request there, see below |

Each entry of `fields` has a `path` in the notation of the write model, `input.session.teams[_]`,
`input.request.headers["x-mcp-toolname"]`, or `input.auth.identity.*` for everything below, and
`set_by`:

| `set_by` | Means |
|---|---|
| `caller` | whoever sends the request chooses it: the body, the headers, the tool an MCP client calls |
| `enforcement-point` | the product computes or observes it: the time, the address the connection came from, a value it looks up |
| `issuer` | the product copies it from somebody it trusts to say it, named in `issuer`: the claims of a token, the teams of an identity provider |

A part an issuer sets can also say what kind of value it is, in `identifier`. A `name` is picked
by somebody, a team called "DevOps" or a username, so whoever can create or rename what it names
can make the issuer say it, and a name let go can be taken by somebody else. An `id` is assigned
by the issuer and never given to anything else. Where nothing verified says which, `identifier` is
left out.

The first entry that covers a part of the request is the one that answers for it, so the more
specific entries come first. A part no entry covers is one the declaration does not speak about,
and the patterns treat it as unknown rather than as safe.

`evidence` is mandatory on every field, and a declaration without it does not load.

## What is here

| Id | Product | Verified against |
|---|---|---|
| `kuadrant-mcp-gateway` | the MCP Gateway of Kuadrant, with the OPA authorization of Authorino | the source, mcp-gateway v0.9.0 and Authorino v0.28.0 |
| `spacelift-login` | the login policy of Spacelift | the documentation, since the product is closed source |
