# H-M0-127 — Runtime-v2 schema reference-node resource classification

Commit `1c62e0bd3b1a35261c1b4fa436d134e8dc488976` adds the fourth
deliberately narrow semantic classification over the runtime-v2 resource
census. The cumulative v4 manifest preserves and byte-binds v3, re-audits the
v2/v1 ancestor chain, and classifies only `MAX_SCHEMA_REF_NODES` as an
inclusive 4,096-key admission maximum before schema-reference cycle traversal.

The bounded quantity is exactly the valid root `$defs` owner keys materialized
in the verifier's `edges` map when graph-cardinality evaluation is reached
before diagnostic-budget exhaustion. It is not a bound on invalid names,
dangling targets, references, adjacency edges, schema objects, document bytes,
or work performed before the guard. The guard emits
`SCHEMA_REF_GRAPH_TOO_LARGE` and returns before cycle traversal above the
maximum. Earlier diagnostic saturation remains an independently fail-closed
short circuit.

The v4 manifest binds the exact definition and enforcement sites, the complete
normalized verifier source-module AST, the enclosing schema-safety function
AST, the ten raw source identities, both census digests, the fifteen schema
identities, an additive exact contract, and dedicated boundary-test bytes. Its
canonical self-digest is
`fece5b8fb2f53a92a3f92a32b27606be1354fa978fa5e891329bd13d13cddb4b`.

Boundary evidence distinguishes 4,095, 4,096, and 4,097 valid owner keys both
directly and through the public deny-only verifier. It also demonstrates that
invalid names and dangling targets do not inflate the owner-key count, that
diagnostic saturation may return before the guard, and that the oversized
branch returns before DFS sorting. Refreshed-binding attacks deny comparison
drift, dead guards, alternate collection counts, undercounting, finding or
return removal, traversal bypass, propagation removal, authority changes,
builtin shadowing, constant drift or extra reads, predecessor/ancestor
redirection, schema/evidence drift, census laundering, and hardlink aliases.

Initial final reviews found a stale blocker-count narrative and incoherent
expected failure codes after checker ordering was strengthened. Both were
repaired. The implementation, Skeptic, and independent diff rereviews then
returned ACCEPT. These are bounded engineering reviews, not authenticated
formal STOP-clearance authority.

Validation passed 76 focused tests normally and under `python -O`, 382 tests
across the 24-module fast tier, and 440 governed records before publication.
The readiness CLI still exits `1` with `BLOCKED / DENY`, writes no release
artifact, and retains all four blockers.

Only ten of 690 census sites are semantically classified; 680 remain
unclassified and coverage remains `INCOMPLETE`. No closure, carrier, public
verifier connection, STOP clearance, writer, database, selector cutover,
operational authority, or capital path was added. Capital remains LOCKED with
deployable USD 0 and the kill switch ENGAGED.
