# H-M0-154 — Runtime-v2 snapshots row-cap classification

Commit `b281d0e` adds one narrow semantic classification to the deny-only
runtime-v2 resource inventory. Classification V31 preserves the exact
twenty-seven-constraint V30 prefix and appends only `TABLE_SNAPSHOTS_ROWS`, the
positional host-preflight ceiling for the exact built-in `rows` tuple paired by
strict zip with `_TABLE_SPECS[13]`.

The inclusive maximum is 100,000 rows. Zero through 100,000 rows pass this
resource check; 100,001 rows add `TABLE_ROW_LIMIT` at `/13/rows`, mark
accounting incomplete, skip downstream row inspection, and withhold the
sanitized image. Malformed rows at the boundary still reach later content
validation. The supplied table label is diagnostic-only and cannot select or
bypass the cap.

The single composite Discovery V4 site
`ff2bb0a8c4e48b59f86fea74496f463a5dfbbb06cb62db33ea473cff4f8f627b`
appears in both definition and enforcement roles and counts once under
set-union accounting. Its separate `_TableSpec` helper, aggregate, shared
comparator, outer-cardinality site, and the reviews and tasks sibling V4
row-cap sites remain outside the classified set.

Classification V31 has twenty-eight constraints, fifty-five unique classified
sites, and 663 unclassified sites out of 718. Its closed schema raw SHA-256 is
`2d3cefd9a8143010660dc90fa983ba0fe6580ae5dbb3145d76fce8f6ecff4710`;
the manifest raw SHA-256 is
`40b94ef888a9f0a0cf3088d8bba72c8c5dbe7868cd7c110dbb4942f64e94ab56`;
and its domain-separated self-digest is
`7f966303fe66e1e0ba7f4a73e5c2d249ed7bf6b835ffc1bb9cda0d901180f28d`.

Adversarial evidence covers zero, 99,999, 100,000, and 100,001 rows; malformed
content at the boundary falling through without a cap finding; duplicated
full-width but semantically false snapshot rows remaining non-authorizing;
over-cap failure before row inspection; label mismatch in both directions
against the higher 300,000-row blobs cap; missing and non-tuple rows before
length inspection; outer cardinality before strict zip; hostile scope
expansion; exact predecessor and ancestor history; and attacker-refreshed
census attacks against the maximum, row index, selection semantics, duplicate
site identity, and missing classified site.

Independent inventory and Skeptic reviews selected snapshots over reviews and
tasks because reviews directly encodes independent actor/status closure and
tasks encodes the broadest execution lifecycle. Skeptic required the
snapshots-specific refreshed-census matrix before acceptance; the exact site
shape was then pinned and the final review accepted the bounded engineering
evidence. These reviews do not constitute formal project acceptance or
release authority.

The complete fast tier passed 620 tests across 49 isolated modules. The final
focused snapshot/readiness set passed 72 tests normally and under optimized
Python after the census fix. Normal and optimized checker outputs were
byte-identical with SHA-256
`21ad1d31225c236cf9a984e32077a21f44bbac73589437b495a37a2fb2bb84d3`;
both exited 1, retained all four blockers, and reported `BLOCKED / DENY` with
no release artifacts. Before this governance publication, 521 governed
records and published history validated.

This work proves only an inclusive positional row maximum. It does not
validate snapshot-ID uniqueness, kind, sequence ordering or continuity,
event/document/blob/head existence, cut correctness, digest correctness or
authenticity, prior-document lineage, timestamps, checkpoint/export validity,
state reconstruction, primary keys, ordering, row content, descriptor meaning,
reducer replay, transition or execution correctness, review independence,
task lifecycle, or public-verifier acceptance. It grants no STOP, release,
execution, wagering, or capital authority. Coverage remains `INCOMPLETE`,
generation remains `DENY`, `STOP-M0-3A-002` remains OPEN, live capital remains
LOCKED with USD 0 deployable, and the kill switch remains ENGAGED.
