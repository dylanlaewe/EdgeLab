# H-M0-156 — Runtime-v2 tasks row-cap classification

Commit `9e939fa` adds the final positional table-row semantic classification to
the deny-only runtime-v2 resource inventory. Classification V33 preserves the
exact twenty-nine-constraint V32 prefix and appends only `TABLE_TASKS_ROWS`,
the positional host-preflight ceiling for the exact built-in `rows` tuple
paired by strict zip with `_TABLE_SPECS[14]`.

The inclusive maximum is 100,000 rows. Zero through 100,000 rows pass this
resource check; 100,001 rows add `TABLE_ROW_LIMIT` at `/14/rows`, mark
accounting incomplete, skip downstream row inspection, and withhold the
sanitized image. Malformed rows at the boundary still reach later content
validation. The supplied table label is diagnostic-only and cannot select or
bypass the cap.

The single composite Discovery V4 site
`d6a859d8b9df13389c46ea59c62011e44c95085620ace3af223c97a74faf485b`
appears in both definition and enforcement roles and counts once under
set-union accounting. Its separate `_TableSpec` helper, aggregate, shared
comparator, and outer-cardinality site remain outside the classified set.

Classification V33 has thirty constraints, fifty-seven unique classified
sites, and 661 unclassified sites out of 718. All fifteen positional table-row
composites are now semantically classified, but that does not make the overall
inventory complete. The 661 remaining source/schema sites retain the
unconditional `RESOURCE_INVENTORY_INCOMPLETE` blocker. The closed schema raw
SHA-256 is
`d5ade9fcb04db8028c5ad5eb0e3df3b45136ffe392630b68b7dafe68e0f260bb`;
the manifest raw SHA-256 is
`64c07727fa802d875d8c189630b5a0538aa423e395e33f5cb8442e4d3648fde7`;
and its domain-separated self-digest is
`c44eb57db828fb99af908da0945a70952f63ded016b897ee344ea7458ebfe7be`.

Adversarial evidence covers zero, 99,999, 100,000, and 100,001 rows;
malformed content at the boundary falling through without a cap finding;
duplicated full-width but semantically impossible task rows remaining
non-authorizing; over-cap failure before row inspection; label mismatch in both
directions against the higher 300,000-row blobs cap; missing and non-tuple rows
before length inspection; outer cardinality before strict zip; hostile scope
expansion to the real tasks helper; exact predecessor and ancestor history;
and attacker-refreshed census attacks against the maximum, row index,
selection semantics, duplicate reviews-site identity, and missing classified
site. The pre-existing generic V4 attacker continues to mutate the real tasks
discovery binding and now fails closed at the classification-site check rather
than inventing an unclassified sibling.

The complete fast tier passed 639 tests across 51 isolated modules. After an
outer-cardinality fixture IndexError and the generic attacker expectation were
corrected, and predecessor reviews scope-expansion coverage was restored, the
final focused tasks/readiness set passed 75 tests normally and under optimized
Python. Normal and optimized checker outputs were byte-identical with SHA-256
`e920ec26ee6982c6a78eb05ee217c34a25461f90164537ae8ef2ec5aff8e8e46`;
both exited 1, retained all four blockers, and reported `BLOCKED / DENY` with
no release artifacts. Before this governance publication, 527 governed
records and published history validated. Independent Skeptic review returned
`ACCEPT` for this bounded engineering slice; it grants no formal project,
release, execution, STOP-clearance, or capital authority.

This work proves only an inclusive positional row maximum. It does not
validate task identity, attempt validity or continuity, workflow/execution/
review state, scheduler/dispatch/repository generations, fencing, active
claims, reviewer assignments, continuation counts, receipts, scheduling,
ownership, roles, reviewer identity or independence, predecessor/successor
existence, distinction, reciprocity, acyclicity or lineage, primary keys,
ordering, row content, reducer replay, transition or lifecycle correctness,
currentness, settlement, wagering, or public-verifier acceptance. It grants
no STOP, release, execution, wagering, or capital authority. Coverage remains
`INCOMPLETE`, generation remains `DENY`, `STOP-M0-3A-002` remains OPEN, live
capital remains LOCKED with USD 0 deployable, `live_enabled` remains false,
and the kill switch remains ENGAGED.
