# H-M0-143 — Runtime-v2 legacy-archive row-cap classification

Commit `be9b635` adds one narrow semantic classification to the deny-only
runtime-v2 resource inventory. Classification V20 preserves the exact sixteen-
constraint V19 prefix and appends only `TABLE_LEGACY_ARCHIVE_ROWS`, the
positional host-preflight ceiling for the exact built-in `rows` tuple paired by
strict zip with `_TABLE_SPECS[5]`.

The inclusive maximum is one. Zero or one row passes this resource check; two
rows add `TABLE_ROW_LIMIT` at `/5/rows`, mark accounting incomplete, skip
downstream row inspection, and withhold the sanitized image. Passing this one
check does not make any row valid. The supplied table label is diagnostic-only
and cannot select or bypass the cap.

The single composite Discovery V4 site
`da67d5943016f6af5f024dbac99959ad526f513565305cfdcdf0df960a4cba18`
appears in both definition and enforcement roles and counts once under set-
union accounting. The helper, aggregate `_TABLE_SPECS`, shared comparator, V3
outer-cardinality site, and all thirteen sibling V4 row-cap sites remain
outside the classified set. The equal-valued metadata, schema-registry, and
seals caps remain distinct and unclassified.

Classification V20 has seventeen constraints, forty-four unique classified
sites, and 674 unclassified sites out of 718. Its closed schema raw SHA-256 is
`faecaead5bc49e60dea73e51ba2f0e1d41de417b267dc2906208d6bc8a8b57ad`;
the manifest raw SHA-256 is
`4f178d854d7ae2ed43cb10dfbbc08376307318deb73a71d23dbb9a98483e8f6a`;
and its domain-separated self-digest is
`6119e639cbc9604ce8a9014a66f3e63a568747d07e42eaa22f9e5f1bf65323d5`.

Adversarial evidence covers zero, one, and two rows; one invalid row falling
through to row-content findings without a row-limit finding; two rows failing
before row inspection; mismatched labels in both directions; missing and non-
tuple rows before length inspection; outer cardinality before strict zip;
equal-valued sibling isolation; helper/order/equivalent-expression changes;
comparator/diagnostic/accounting/continuation drift; hostile scope expansion;
attacker-refreshed census evidence; exact predecessor history; and unique-site
union accounting. Independent inventory and Skeptic reviews accepted the final
bounded engineering slice after one stale narrative count was corrected. These
reviews do not constitute formal project acceptance or release authority.

The complete readiness module passed 47 tests after the correction. The
dedicated legacy-archive module passed seven tests normally and under optimized
Python. Normal and optimized checker outputs were byte-identical, both exited
1, retained all four blockers, and reported `BLOCKED / DENY` with no release
artifacts. The complete fast tier passed 516 tests across 38 isolated modules.
Before this governance publication, 488 governed records and published history
validated.

This work proves only an inclusive positional resource maximum. It does not
classify a minimum, exact cardinality, the conditional `NEW`/`V1_MIGRATION`
descriptor rule, row validity, physical storage, reducer derivation, supplied-
label meaning, diagnostic semantics, public-verifier acceptance, bridge or
migration authority, successor-format authority, closure, carrier, STOP
clearance, execution, or capital. `V1_BRIDGE_UNSUPPORTED` remains a blocker.
Coverage remains `INCOMPLETE`, generation remains `DENY`,
`STOP-M0-3A-002` remains OPEN, live capital remains LOCKED with USD 0
deployable, and the kill switch remains ENGAGED.
