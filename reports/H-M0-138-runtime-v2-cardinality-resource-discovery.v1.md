# H-M0-138 — Runtime-v2 cardinality resource discovery

Commit `1bc5e82` extends the deny-only runtime-v2 resource census without
changing runtime behavior. Discovery v3 preserves all 401 Discovery v2 source
sites and adds six exact branch-specific bindings behind the generic
`cardinalities` table comparator for `schema_documents`, `blobs`, `events`,
`table_snapshots`, `checkpoint_copies`, and `selector_history`.

Each new record binds the exact cardinality row, matching `tuple_fields` row,
both table assignments and loops, subject lookup, validity guard, chained
comparison, result write, invalid diagnostic/accounting branch, predecessor
comparator, and complete `inspect_runtime_image_host` function AST. The full
function identity closes inter-loop rebinding, validity-map mutation, and
built-in shadowing gaps found by the adversarial review.

Discovery v3 byte-binds its v2 manifest and schema. It reports 407 source sites
and 296 schema sites, for 703 discovered sites; six bindings are new in this
extension and thirteen are cumulative across v2 and v3. The source-census
digest is
`d38e35a0f2466735c0895b6bfb7f20c83b52834ccbc3995943f8147d8f664071`.
The v3 schema raw SHA-256 is
`60d8cb918f985308bdb5c7d477398066abc25d230642a266ff6836fa4f85f766`;
the manifest raw SHA-256 is
`39eb28b0e54cd4504a28d0ad3cae065aad185c4c5950ade74ceaf095b605a72d`;
and its domain-separated self-digest is
`831b4e0137fd7a3aaeb5cd91da66f2f16030f875d7998a4f03ac4fd2eb284c95`.

Classification v15 is a census-only rebase. It byte-binds v14 and preserves
all thirteen constraints and all thirty-eight classified sites exactly. Its
schema raw SHA-256 is
`2ca078ece22eaa8887184302110b727bfbf3ade49762a4be089c16628bd8378c`;
its manifest raw SHA-256 is
`cbadcd550071f29fe22ca002accd399df177dc03dafbf54980feeeb4f800eb22`;
and its self-digest is
`69f5d49e51e7f186fb90e32606002be684ac83060f379e921a6b0edf7cb5a90f`.

Adversarial tests reject row addition, deletion, duplication, reordering,
starred or dynamic construction, branch/subject substitution, equal-valued
bound aliases, comparator and flow changes, `_TABLE_SPECS` drift, source-level
shadowing, inter-loop `captured` rebinding, `tuple_valid` overwrite or clear,
predecessor evidence drift, refreshed ordinary census identities, and v15
constraint or classified-set changes. The first Skeptic pass rejected an
inter-loop flow gap; the repaired implementation was re-reviewed and accepted.
These are bounded engineering reviews, not authenticated STOP-clearance or
release acceptance.

Validation passed all 39 readiness tests, including the new adversarial cases,
normally; normal and optimized checker outputs were byte-identical and both
exited 1 with `BLOCKED / DENY`. Both new schemas validate under Draft 2020-12.
The complete fast tier passed 466 tests across 33 isolated modules. Before
governance publication, 473 governed records and published history validated.

All six new records remain `UNCLASSIFIED`. Only thirty-eight of 703 census
sites are semantically classified; 665 remain unclassified. Coverage remains
`INCOMPLETE`, generation remains `DENY`, and all four readiness blockers
remain. `STOP-M0-3A-002` remains OPEN. No closure, carrier, positive public
verifier result, writer, database, selector cutover, execution authority,
STOP clearance, or capital path was added. Capital remains LOCKED with USD 0
deployable and the kill switch ENGAGED.
