# Saved queries

Cypher queries for the graph Petard exports, one file per query in the format of the
[BloodHound Query Library](https://github.com/SpecterOps/BloodHoundQueryLibrary). Each pattern
has three or four, named after its id, and the queries named `Petard:` look at the graph as a
whole.

Every pattern leaves its id on the nodes and edges it reports on, in `patterns` for a finding and
in `candidate_patterns` for a candidate, and that is what the queries ask for. Which kind a
pattern marks, and with which properties, is declared in the `graph.marks` of its file in
`taxonomy-registry/opa`.

## Getting them into BloodHound

`export-opengraph -install` saves them for the owner of the token, next to the extension schema.
A query the owner already has under the same name is left as it is.

`queries.json` holds the same queries as one list, which is the form
[queries.specterops.io](https://queries.specterops.io) reads from a custom source.

After changing a file, regenerate the list with `go test ./queries -update`.
