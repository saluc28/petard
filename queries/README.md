# Saved queries

Cypher queries for the graph Petard exports, one file per query in the format of the
[BloodHound Query Library](https://github.com/SpecterOps/BloodHoundQueryLibrary). Each pattern
has two to four, named after its id, and the queries named `Petard:` look at the graph as a
whole. How many depends on what the pattern marks: a third query written to reach a quota is a
query that returns nothing.

Every pattern leaves its id on the nodes and edges it reports on, in `patterns` for a finding and
in `candidate_patterns` for a candidate, and that is what the queries ask for. Which kind a
pattern marks, and with which properties, is declared in the `graph.marks` of its file in
`taxonomy-registry/opa`.

## They all return a graph

A query here returns nodes, relationships or paths, never columns. BloodHound's Explore view
draws a graph and reads an answer with no nodes and no edges as no answer at all, so a query
that returns columns is shown as "No results match your criteria" even though the API answered
it. All fifty of BloodHound's own prebuilt queries return nodes for the same reason.

What a finding says in words stays on the entity, in the Entity Panel that opens when it is
selected: which documents a check misses, the collection an `every` passes empty, the position a
principal holds, the endpoint a write goes through. A query is there to put that entity on the
screen.

Two more things the backend decides. `UNWIND` works over a list written in the query and not
over a property: with the graph in PostgreSQL the property arrives as text and the query fails.
And ingest upper-cases `name` and `objectid`, so a literal compared against either is written in
upper case, the way BloodHound's own prebuilt queries write it.

## Getting them into BloodHound

`export-opengraph -install` saves them for the owner of the token, next to the extension schema.
A query the owner already has under the same name is left as it is.

BloodHound keys a saved query by its name, so a query renamed between two versions of Petard
arrives as a second query and the old one stays, with the old question in it.
`export-opengraph -prune-queries` deletes the ones this build no longer has, naming each as it
goes. It is a flag of its own because it removes what somebody may have come to rely on.

`queries.json` holds the same queries as one list, which is the form
[queries.specterops.io](https://queries.specterops.io) reads from a custom source.

After changing a file, regenerate the list with `go test ./queries -update`.
