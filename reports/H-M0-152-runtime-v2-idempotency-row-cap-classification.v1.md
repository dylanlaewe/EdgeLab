# H-M0-152 — Runtime-v2 idempotency row-cap classification

Commit `24c83cf` adds one narrow semantic classification to the deny-only
runtime-v2 resource inventory. Classification V29 preserves the exact
twenty-five-constraint V28 prefix and appends only `TABLE_IDEMPOTENCY_ROWS`,
the positional host-preflight ceiling for the exact built-in `rows` tuple
paired by strict zip with `_TABLE_SPECS[4]`.

The inclusive maximum is 100,000 rows. Zero through 100,000 rows pass this
resource check; 100,001 rows add `TABLE_ROW_LIMIT` at `/4/rows`, mark accounting
incomplete, skip downstream row inspection, and withhold the sanitized image.
Malformed rows at the boundary can still fail later content validation. The
supplied table label is diagnostic-only and cannot select or bypass the cap.

The single composite Discovery V4 site
`1a228b50f30afae33f6a23bc125a8311cbeee1eb588bfa507a176b0087fbed72`
appears in both definition and enforcement roles and counts once under set-
union accounting. Its separate `_TableSpec` helper, aggregate, shared
comparator, outer-cardinality site, and all four sibling V4 row-cap sites
remain outside the classified set.

Classification V29 has twenty-six constraints, fifty-three unique classified
sites, and 665 unclassified sites out of 718. Its closed schema raw SHA-256 is
`6288fcbf2a5a23d710709533ba647b8b6838fe2c4bb365a89663846b8a7488b5`;
the manifest raw SHA-256 is
`af16e6b10fad1bf604f0c43457c5cc2cb2f1b183d67d317a4bd94901d850bb2e`;
and its domain-separated self-digest is
`6437ae3086076bafa2e732244b6cb8c4dddf03529c2a7c7d741d0392da383864`.

Adversarial evidence covers zero, 99,999, 100,000, and 100,001 rows; malformed
content at the boundary falling through without a cap finding; duplicated
full-width but semantically false rows remaining non-authorizing; over-cap
failure before row inspection; label mismatch in both directions against the
higher 300,000-row blobs cap; missing and non-tuple rows before length
inspection; outer cardinality before strict zip; hostile scope expansion;
attacker-refreshed census evidence; exact predecessor history; and unique-site
union accounting.

Independent inventory and Skeptic reviews selected idempotency as the smallest
complete next positional row-cap slice because it has the smallest remaining
row shape. The final Skeptic review accepted the implementation and its exact-
once/replay nonclaims. These bounded reviews do not constitute formal project
acceptance or release authority.

The final complete fast tier passed 601 tests across 47 isolated modules,
including all 61 readiness tests and eight dedicated idempotency row-cap tests.
Normal and optimized checker outputs were byte-identical with SHA-256
`4e0fe5658932915500cf48c9f39109cff72a25503a7fb57145baac9af603bdca`;
both exited 1, retained all four blockers, and reported `BLOCKED / DENY` with no
release artifacts. Before this governance publication, 515 governed records
and published history validated.

This work proves only an inclusive positional row maximum. It does not validate
operation-key uniqueness, deduplication or exactly-once execution, retry
safety, transaction identity, request/response digest correctness or
correspondence, commit-event existence, commit-sequence correctness, timestamp
validity, event/task linkage, replay semantics, storage atomicity, primary keys,
ordering, row content, descriptor meaning, reducer replay, transition or
execution correctness, or public-verifier acceptance. It grants no STOP,
release, execution, wagering, or capital authority. Coverage remains
`INCOMPLETE`, generation remains `DENY`, `STOP-M0-3A-002` remains OPEN, live
capital remains LOCKED with USD 0 deployable, and the kill switch remains
ENGAGED.
