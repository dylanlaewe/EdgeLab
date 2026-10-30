# H-M0-144 — Runtime-v2 metadata row-cap classification

Commit `89dfc5d` adds one narrow semantic classification to the deny-only
runtime-v2 resource inventory. Classification V21 preserves the exact
seventeen-constraint V20 prefix and appends only `TABLE_METADATA_ROWS`, the
positional host-preflight ceiling for the exact built-in `rows` tuple paired by
strict zip with `_TABLE_SPECS[6]`.

The inclusive maximum is one. Zero or one row passes this resource check; two
rows add `TABLE_ROW_LIMIT` at `/6/rows`, mark accounting incomplete, skip
downstream row inspection, and withhold the sanitized image. A one-row input
can still fail later content checks. The supplied table label is diagnostic-
only and cannot select or bypass the cap.

The single composite Discovery V4 site
`badbd3a475028cf7a3166768a9d403c651f5ceffab899ddd7d6fa460b5e2f96e`
appears in both definition and enforcement roles and counts once under set-
union accounting. Its helper, the `_TABLE_SPECS` aggregate, shared comparator,
V3 outer-cardinality site, and all twelve sibling V4 row-cap sites remain
outside the classified set. The equal-valued schema-registry and seals caps
remain distinct and unclassified.

Classification V21 has eighteen constraints, forty-five unique classified
sites, and 673 unclassified sites out of 718. Its closed schema raw SHA-256 is
`10ebe1d8aeb72c1cb69f2d6f3da0b7e3716d53a1f75c4c43e4d20b146d22eec9`;
the manifest raw SHA-256 is
`903ce2b2bc63498bc18adfd43c03518bddd1c4d41e1c5fd94b82e2276416e9b1`;
and its domain-separated self-digest is
`44929d4058538e354d09940a671ac78306d2d03a0b101bd2ba55035c5814ff8a`.

Adversarial evidence covers zero, one, and two rows; invalid one-row content
falling through without a cap finding; two rows failing before row inspection;
mismatched labels in both directions; missing and non-tuple rows before length
inspection; outer cardinality before strict zip; equal-valued sibling
isolation; helper/order/equivalent-expression changes; comparator/diagnostic/
accounting/continuation drift; hostile scope expansion; attacker-refreshed
census evidence; exact predecessor history; and unique-site union accounting.
Independent inventory and Skeptic reviews accepted this bounded engineering
slice. They do not constitute formal project acceptance or release authority.

The complete fast tier passed 524 tests across 39 isolated modules, including
all 48 readiness tests. The dedicated metadata row-cap tests passed normally
and under optimized Python. Normal and optimized checker outputs were byte-
identical, both exited 1, retained all four blockers, and reported
`BLOCKED / DENY` with no release artifacts. Before this governance publication,
491 governed records and published history validated.

This work proves only an inclusive positional resource maximum. It does not
prove metadata exists, require exactly one row, validate the singleton key or
any of the 26 fields, establish currentness, anchoring, or authorization from
field names or values, or classify descriptor/schema, reducer, supplied-label,
diagnostic, public-verifier, STOP, execution, wagering, or capital semantics.
Coverage remains `INCOMPLETE`, generation remains `DENY`,
`STOP-M0-3A-002` remains OPEN, live capital remains LOCKED with USD 0
deployable, and the kill switch remains ENGAGED.
