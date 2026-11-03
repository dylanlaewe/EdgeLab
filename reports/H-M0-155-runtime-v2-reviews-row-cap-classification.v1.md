# H-M0-155 — Runtime-v2 reviews row-cap classification

Commit `997dc95` adds one narrow semantic classification to the deny-only
runtime-v2 resource inventory. Classification V32 preserves the exact
twenty-eight-constraint V31 prefix and appends only `TABLE_REVIEWS_ROWS`, the
positional host-preflight ceiling for the exact built-in `rows` tuple paired by
strict zip with `_TABLE_SPECS[9]`.

The inclusive maximum is 100,000 rows. Zero through 100,000 rows pass this
resource check; 100,001 rows add `TABLE_ROW_LIMIT` at `/9/rows`, mark accounting
incomplete, skip downstream row inspection, and withhold the sanitized image.
Malformed rows at the boundary still reach later content validation. The
supplied table label is diagnostic-only and cannot select or bypass the cap.

The single composite Discovery V4 site
`8f1e936be695ee430acb2d111c3ddbf7da8b2a5cce958f5dd34896730b20c2c0`
appears in both definition and enforcement roles and counts once under set-union
accounting. Its separate `_TableSpec` helper, aggregate, shared comparator,
outer-cardinality site, and the tasks sibling V4 row-cap site remain outside the
classified set.

Classification V32 has twenty-nine constraints, fifty-six unique classified
sites, and 662 unclassified sites out of 718. Its closed schema raw SHA-256 is
`4d76b86e196ebe7a83a732e2012049197a24d253424f16067617423645f8d29c`;
the manifest raw SHA-256 is
`b4c1826bf559bcaf9dbf8461ab6fbaabed8cbad44b677de73012092b8133132a`;
and its domain-separated self-digest is
`ad931b58ba062a97e2b94e68f2c00bce57e4eb26a5bf4e56989eb0e730b5b612`.

Adversarial evidence covers zero, 99,999, 100,000, and 100,001 rows; malformed
content at the boundary falling through without a cap finding; duplicated
full-width but semantically false review rows remaining non-authorizing;
over-cap failure before row inspection; label mismatch in both directions
against the higher 300,000-row blobs cap; missing and non-tuple rows before
length inspection; outer cardinality before strict zip; hostile scope
expansion; exact predecessor and ancestor history; and attacker-refreshed
census attacks against the maximum, row index, selection semantics, duplicate
tasks-site identity, and missing classified site.

Independent inventory and Skeptic reviews selected reviews before tasks because
the reviews cap is the smaller remaining semantic slice, while tasks carries the
broadest execution lifecycle. Skeptic required the reviews-specific refreshed-
census matrix and accepted the corrected bounded engineering evidence. This
acceptance does not authenticate reviewers, validate assignments or decisions,
approve task transitions, or constitute formal project acceptance or release
authority.

The complete fast tier passed 629 tests across 50 isolated modules. The final
focused reviews/readiness set passed 73 tests normally and under optimized
Python after the generic attacker-refreshed census fixture was retargeted from
the newly classified reviews site to the sole remaining unclassified tasks
site. Normal and optimized checker outputs were byte-identical with SHA-256
`489b4dfff39712d17f8a682175124958a4132c9f892de55bede2aa947a7c27f0`;
both exited 1, retained all four blockers, and reported `BLOCKED / DENY` with no
release artifacts. Before this governance publication, 524 governed records and
published history validated.

This work proves only an inclusive positional row maximum. It does not validate
reviewer identity or independence, assignment authority, status or decision
meaning, decision ancestry, source-task or attempt existence, uniqueness,
ordering, row content, routing, remediation authority, task state or lifecycle,
reducer replay, transition or execution correctness, or public-verifier
acceptance. It grants no STOP, release, execution, wagering, or capital
authority. Coverage remains `INCOMPLETE`, generation remains `DENY`,
`STOP-M0-3A-002` remains OPEN, live capital remains LOCKED with USD 0
deployable, and the kill switch remains ENGAGED.
