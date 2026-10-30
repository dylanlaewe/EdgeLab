# H-M0-146 — Runtime-v2 seals row-cap classification

Commit `d206f30` adds one narrow semantic classification to the deny-only
runtime-v2 resource inventory. Classification V23 preserves the exact
nineteen-constraint V22 prefix and appends only `TABLE_SEALS_ROWS`, the
positional host-preflight ceiling for the exact built-in `rows` tuple paired by
strict zip with `_TABLE_SPECS[12]`.

The inclusive maximum is one. Zero or one row passes this resource check; two
rows add `TABLE_ROW_LIMIT` at `/12/rows`, mark accounting incomplete, skip
downstream row inspection, and withhold the sanitized image. A malformed or
contradictory full-width one-row seal can still fail later content and cross-
table checks. The supplied table label is diagnostic-only and cannot select or
bypass the cap.

The single composite Discovery V4 site
`048a59b25e61ebb2a06be28dcaad6cb344db1347b43665b8c8a51ca74f12437b`
appears in both definition and enforcement roles and counts once under set-
union accounting. Its helper, the `_TABLE_SPECS` aggregate, shared comparator,
V3 outer-cardinality site, and all ten sibling V4 row-cap sites remain outside
the classified set.

Classification V23 has twenty constraints, forty-seven unique classified
sites, and 671 unclassified sites out of 718. Its closed schema raw SHA-256 is
`d4219dbdcf440a2c019ca5df6ee68d209295d058620e9d561040efdb525f0ec5`;
the manifest raw SHA-256 is
`f56a03624186e0fa6643de0f0ce0044d89df1f307f3e840bbb87a948af698728`;
and its domain-separated self-digest is
`fd21be2d20715f8c96b3396a40a196706600f0e1c3ac1cf9c5f923ce3b00b4eb`.

Adversarial evidence covers zero, one, and two rows; malformed and full-width
contradictory one-row content falling through without a cap finding; two rows
failing before row inspection; mismatched labels in both directions; missing
and non-tuple rows before length inspection; outer cardinality before strict
zip; helper/order/equivalent-expression changes; comparator/diagnostic/
accounting/continuation drift; hostile scope expansion; attacker-refreshed
census evidence; exact predecessor history; and unique-site union accounting.
The complete fast tier initially exposed a stale positional fixture that had
begun mutating the newly classified seals site; the test now explicitly targets
the still-unclassified attempts site and the full tier passes. Independent
inventory and Skeptic reviews accepted both the bounded implementation and the
test correction. They do not constitute formal project acceptance or release
authority.

The final complete fast tier passed 540 tests across 41 isolated modules,
including all 50 readiness tests. Normal and optimized checker outputs were
byte-identical, both exited 1, retained all four blockers, and reported
`BLOCKED / DENY` with no release artifacts. Before this governance publication,
497 governed records and published history validated.

This work proves only an inclusive positional row maximum. It does not require
or validate exactly one seal, deterministic `RUNTIME_GENESIS_IDENTITY`, seal
authenticity, purpose, content, freshness, cross-table identity, descriptor or
reducer correctness, supplied-label or diagnostic meaning, or public-verifier
acceptance. It grants no STOP, release, execution, wagering, or capital
authority. Coverage remains `INCOMPLETE`, generation remains `DENY`,
`STOP-M0-3A-002` remains OPEN, live capital remains LOCKED with USD 0
deployable, and the kill switch remains ENGAGED.
