# H-M0-124 — Runtime-v2 first semantic resource classification

Commit `b4d2bd299c304b93a864b0e4b1334664070e35dd` adds the first deliberately
narrow semantic classification over the runtime-v2 resource census. The
versioned closed manifest classifies only `MAX_DEPENDENCY_CLOSURE_BYTES` as an
inclusive 1,048,576-byte resource maximum and binds its exact definition and
enforcement site IDs.

The classification manifest binds all ten raw runtime source identities, the
394-source-site and 296-schema-site census digests, the fifteen-schema input
digest, its pinned closed schema identity, the complete normalized
`runtime_v2_closure.py` module AST, the enclosing validator-function AST, and
the exact contract and boundary-test evidence bytes. Its canonical self-digest
is `8ab916ec611ce6cb8b72aaaa5afb25fcec372fd28071364803b75ba9e1a4ded0`.

Adversarial tests deny removed or dead guards, a no-op rejection function,
global builtin shadowing, refreshed census-count laundering, source/schema
drift, missing or aliased evidence, schema weakening, constraint mutation,
and self-digest corruption. Boundary evidence distinguishes maximum-minus-one
and maximum inputs proceeding past the byte gate from maximum-plus-one failing
with `BYTE_LIMIT`.

Independent Skeptic and diff engineering rereviews initially blocked weak
control-flow, schema, evidence, transitive-callee, builtin, and cardinality
bindings. All reported defects were repaired, and both rereviews then returned
PASS. These are engineering reviews, not authenticated formal STOP-clearance
authority.

Validation passed 30 focused tests normally and under `python -O`, 370 tests
across the 22-module fast tier, and 431 governed records before publication.
The readiness CLI still exits `1` with `BLOCKED / DENY`, writes no release
artifact, and retains all four blockers.

Only two of 690 census sites are semantically classified; 688 remain
unclassified and coverage remains `INCOMPLETE`. No closure, carrier, public
verifier connection, STOP clearance, writer, database, selector cutover,
operational authority, or capital path was added. Capital remains LOCKED with
deployable USD 0 and the kill switch ENGAGED.
