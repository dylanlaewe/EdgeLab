# H-M0-147 — Runtime-v2 schema-documents row-cap classification

Commit `4f1e5f8` adds one narrow semantic classification to the deny-only
runtime-v2 resource inventory. Classification V24 preserves the exact
twenty-constraint V23 prefix and appends only `TABLE_SCHEMA_DOCUMENTS_ROWS`,
the positional host-preflight ceiling for the exact built-in `rows` tuple
paired by strict zip with `_TABLE_SPECS[10]`.

The inclusive maximum is nine. Zero through nine rows pass this resource
check; ten rows add `TABLE_ROW_LIMIT` at `/10/rows`, mark accounting
incomplete, skip downstream row inspection, and withhold the sanitized image.
Nine malformed rows can still fail later content validation. The supplied
table label is diagnostic-only and cannot select or bypass the cap.

The single composite Discovery V4 site
`58d10aa798de462fff673be3b991df4dbb9c05cc3c1f30b9adb4d2ffb59149e2`
appears in both definition and enforcement roles and counts once under set-
union accounting. The `_TABLE_SPECS` helper, aggregate, shared comparator, V3
outer-cardinality site, top-level exact-nine schema-document cardinality site,
and all nine sibling V4 row-cap sites remain outside the classified set.

Classification V24 has twenty-one constraints, forty-eight unique classified
sites, and 670 unclassified sites out of 718. Its closed schema raw SHA-256 is
`5ebd07a1f05b8f5d8180aa9330a8afddb7aa41ff23911e615d2d34f538f0fc5b`;
the manifest raw SHA-256 is
`fa06378132d31d828237354802e69959f6f6af63db1c60de6a7c0c916f6b151d`;
and its domain-separated self-digest is
`d4669a2151d044665db2950e58d8b99839185a50a9a8718fba0c033765007d07`.

Adversarial evidence covers zero, eight, nine, and ten rows; malformed nine-row
content falling through without a cap finding; ten rows failing before row
inspection; mismatched labels in both directions; missing and non-tuple rows
before length inspection; outer cardinality before strict zip; two-way
independence from the top-level exact-nine cardinality; hostile scope expansion;
attacker-refreshed census evidence; exact predecessor history; and unique-site
union accounting.

The first integrated run exposed stale V23 predecessor tests and narratives.
The Skeptic rejected that candidate. The tests were rewritten to bind V24 to
the complete V23 prefix and V23-to-V22 ancestor history, both narratives were
advanced to V24, and the independent Skeptic re-review accepted the repaired
engineering scope. That bounded review does not constitute formal project
acceptance or release authority.

The final complete fast tier passed 549 tests across 42 isolated modules,
including all 51 readiness tests and eight dedicated schema-documents row-cap
tests. Normal and optimized checker outputs were byte-identical with SHA-256
`8e03bc8be7075bc1e39bf1cde3361b7b52997ecc537d38f1814e4fcd8833d790`;
both exited 1, retained all four blockers, and reported `BLOCKED / DENY` with no
release artifacts. Before this governance publication, 500 governed records
and published history validated.

This work proves only an inclusive positional row maximum. It does not prove
exactly nine top-level schema documents, document validity, retained inventory
or ordering, per-document byte admissibility, registry equality, descriptor or
reducer correctness, supplied-label meaning, or public-verifier acceptance. It
grants no STOP, release, execution, wagering, or capital authority. Coverage
remains `INCOMPLETE`, generation remains `DENY`, `STOP-M0-3A-002` remains OPEN,
live capital remains LOCKED with USD 0 deployable, and the kill switch remains
ENGAGED.
