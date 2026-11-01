# H-M0-149 — Runtime-v2 claims row-cap classification

Commit `9cd81f5` adds one narrow semantic classification to the deny-only
runtime-v2 resource inventory. Classification V26 preserves the exact
twenty-two-constraint V25 prefix and appends only `TABLE_CLAIMS_ROWS`, the
positional host-preflight ceiling for the exact built-in `rows` tuple paired by
strict zip with `_TABLE_SPECS[2]`.

The inclusive maximum is 100,000 rows. Zero through 100,000 rows pass this
resource check; 100,001 rows add `TABLE_ROW_LIMIT` at `/2/rows`, mark accounting
incomplete, skip downstream row inspection, and withhold the sanitized image.
Malformed rows at the boundary can still fail later content validation. The
supplied table label is diagnostic-only and cannot select or bypass the cap.

The single composite Discovery V4 site
`4be3587c25022ecc89e1b9935c77fcbd36b19db59118701d09de06f46510e737`
appears in both definition and enforcement roles and counts once under set-
union accounting. Its separate `_TableSpec` helper, aggregate, shared
comparator, outer-cardinality site, and all seven sibling V4 row-cap sites
remain outside the classified set.

Classification V26 has twenty-three constraints, fifty unique classified
sites, and 668 unclassified sites out of 718. Its closed schema raw SHA-256 is
`344ec9d5dd2cc7254d0ab63dae07b6ddc98ea0de3fe4d2bef66eb416f5478743`;
the manifest raw SHA-256 is
`10aa0939a83899c7cade75e7aeeee9e46c6fcbea7743bd7964415e73aef5a62a`;
and its domain-separated self-digest is
`d2c2b022fc159720c610f63556a444135f4089cb444edc2d23c3e84efef8630d`.

Adversarial evidence covers zero, 99,999, 100,000, and 100,001 rows; malformed
content at the boundary falling through without a cap finding; a full-width but
contradictory open claim with a closed-event identifier remaining
non-authorizing; over-cap failure before row inspection; label mismatch in both
directions against the distinct 300,000-row blobs cap; missing and non-tuple
rows before length inspection; outer cardinality before strict zip; hostile
scope expansion; attacker-refreshed census evidence; exact predecessor
history; and unique-site union accounting.

Independent inventory and Skeptic reviews selected claims as the smallest
complete next positional row-cap slice. The final Skeptic review accepted the
implementation and its explicit nonclaims. These bounded reviews do not
constitute formal project acceptance or release authority.

The final complete fast tier passed 569 tests across 44 isolated modules,
including all 55 readiness tests and eight dedicated claims row-cap tests.
Normal and optimized checker outputs were byte-identical with SHA-256
`d902e604ae89836b5dc2cd0b6318cad8dcebd082ddcc158122a21d3a0330e5a6`;
both exited 1, retained all four blockers, and reported `BLOCKED / DENY` with no
release artifacts. Before this governance publication, 506 governed records
and published history validated.

This work proves only an inclusive positional row maximum. It is not a maximum
claim ordinal, a per-task or per-attempt claim limit, a uniqueness or
concurrency limit, a minimum, an exact population, or evidence that each claim
belongs to an observed attempt. It does not validate claim/task/attempt/fence
relationships, status transitions, actor identity or authorization,
opened/closed event existence, agreement between status and `closed_event_id`,
active-claim linkage, ownership, lease or fencing semantics, primary keys,
sorting, row content, descriptor meaning, reducer replay, transition or
execution correctness, or public-verifier acceptance. It grants no STOP,
release, execution, wagering, or capital authority. Coverage remains
`INCOMPLETE`, generation remains `DENY`, `STOP-M0-3A-002` remains OPEN, live
capital remains LOCKED with USD 0 deployable, and the kill switch remains
ENGAGED.
