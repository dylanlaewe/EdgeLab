# H-M0-137 — Runtime-v2 schema-bundle resource classification

Commit `4efabea76ea14549acbcb3fc0cbdf689c26e24c6` classifies the
complete direct `MAX_SCHEMA_BUNDLE_BYTES` family. The shared numeric ceiling
has three explicitly separate enforcement subjects: the host-preflight
schema-registry/document-body aggregate, the verifier's corresponding
aggregate, and the verifier's standalone raw storage-descriptor field. The
descriptor is not part of either schema bundle merely because the same
2,097,152-byte ceiling is reused.

Classification v14 byte-binds its v13 predecessor and retains all twelve v13
constraints exactly. It adds both definitions and all three direct
comparisons, increasing the cumulative inventory to thirteen constraints and
thirty-eight classified sites. Its schema SHA-256 is
`43bcb30ab3ae233122acec3cc820559b53dfd3071d9441df0f4a799f12e9c509`,
manifest raw SHA-256 is
`14f31c3f9d5451b7fe42dc45c3de44f58cc5e992f26a3e70e87c99cbdded24f8`,
and domain-separated self-digest is
`855b694a556f4a6ad86ef43301101bc4c69ece5e36a1e310bed9e359514375e7`.

Dedicated evidence proves inclusive 2,097,151/2,097,152/2,097,153 boundaries
for both aggregates and the descriptor field. It separately exercises exact
record and byte inclusion, malformed-value exclusion, type and inventory guard
precedence, descriptor rejection before parsing, unrelated-input independence,
deterministic denial, immutable inputs, withheld invalid host images, and
absence of authorizing effect. The distributed aggregate fixtures remain
within the independent per-document ceiling.

Readiness attacks refresh ordinary discovery identities before challenging
the hard pins. They reject same-valued and changed definitions, comparator or
subject substitution, extra loads/stores, changed accumulator initialization
or body addition, altered type/inventory guards, bypassed or reordered
branches, changed diagnostics, and source-level `len`/`bytes` shadowing in
both modules. The checker pins all three enclosing function ASTs and both
complete module ASTs.

Independent bounded identity and Skeptic reviews reproduced the schema,
manifest, evidence, source sites, ASTs, predecessor, ancestry, and self-digest
identities and returned ACCEPT. These are engineering reviews only; they are
not authenticated formal STOP-clearance authority.

Validation passed 43 focused readiness and schema-bundle tests normally and
under optimized Python; 465 tests passed across the 33-module fast tier; and
470 governed records plus published history validated before evidence
publication. The readiness CLI still reports `BLOCKED / DENY`, writes no
release artifact, and retains all four blockers.

Only thirty-eight of 697 census sites are semantically classified; 659 remain
unclassified and coverage remains `INCOMPLETE`. `STOP-M0-3A-002` remains OPEN.
No schema canonicality, digest/pin equality, parsed validity, closure, carrier,
positive public-verifier result, STOP clearance, writer, database, selector
cutover, operational authority, or capital path was added. Capital remains
LOCKED with deployable USD 0 and the kill switch ENGAGED.
