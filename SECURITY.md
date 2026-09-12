# Security policy

## Reporting a vulnerability

Report privately through GitHub, with
[Report a vulnerability](https://github.com/saluc28/petard/security/advisories/new) in the
Security tab. Please do not open a public issue for something exploitable.

Include what you need to reproduce it: the Rego, the data, and the command. Petard reads
policies that somebody else wrote, so a crash or a hang on unusual input is in scope even
though nothing here is a network service.

## What is in scope

Petard analyzes policies. It does not evaluate them against real requests, and it makes no
network calls of its own except the ones you point it at.

Two consequences worth knowing, because both are choices rather than oversights:

- **Analyzing a policy never calls the endpoints that policy names.** Partial evaluation leaves
  a call to `http.send` in the residual condition instead of making it, which is OPA's default
  and is kept deliberately: analyzing somebody's policy must not send requests to the hosts
  written in it.
- **The upload path talks to the BloodHound instance you give it**, with credentials read from
  the environment. They are never accepted as command line flags, so they stay out of the shell
  history and the process list.

If either of those turns out not to hold, that is a vulnerability and worth reporting.

## Supported versions

There is no released version yet. Until there is, the supported version is the default branch.
