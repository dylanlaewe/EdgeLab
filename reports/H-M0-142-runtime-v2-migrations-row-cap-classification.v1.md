# H-M0-142 — Runtime-v2 migrations row-cap classification

Commit `6383c33` adds one narrow semantic classification to the deny-only
runtime-v2 resource inventory. Classification V19 preserves the exact fifteen-
constraint V18 prefix and appends only `TABLE_MIGRATIONS_ROWS`, the positional
host-preflight ceiling for the exact built-in `rows` tuple paired by strict zip
with `_TABLE_SPECS[7]`.

The inclusive maximum is zero. An empty tuple passes this resource check; one
row adds `TABLE_ROW_LIMIT` at `/7/rows`, marks accounting incomplete, skips
downstream row inspection, and withholds the sanitized image. The supplied
table label is diagnostic-only and cannot select or bypass the cap. A wrong
label at position seven still receives the zero cap, while a `migrations` label
at another position does not acquire it.

The single composite Discovery V4 site
`8049eeb8f33f5337042577cfb67d005307c6e9354e64851a345f55efa3a13c5a`
appears in both definition and enforcement roles. Classified-site accounting
uses set union, so the overlap adds one census site, not two. The helper site,
aggregate `_TABLE_SPECS` site, shared comparator, V3 outer-cardinality site,
and all fourteen sibling V4 row-cap sites remain outside the classified set.

Classification V19 has sixteen constraints, forty-three unique classified
sites, and 675 unclassified sites out of 718. Its closed schema raw SHA-256 is
`928e254e59d8dac8d82c6c6dc2fc0dd7598be5c1bd33bb5a543e09fe318f87ac`;
the manifest raw SHA-256 is
`0f74476dbb2e6747542a6a2f52b8c525f1d6cb43ef4a1898b8fca6a974b3938e`;
and its domain-separated self-digest is
`ccf08c2b484131ef04231d44beba0e82f04e27a6f97a67e5cbd32db742faba2c`.

Adversarial evidence covers the zero/one boundary, mismatched labels in both
directions, missing and non-tuple rows before length inspection, outer
cardinality before strict zip, sibling-cap isolation, helper/order/equivalent-
expression changes, comparator/diagnostic/accounting/continuation drift,
shadowing and rebinding, hostile classification expansion, attacker-refreshed
census evidence, exact predecessor history, and unique-site union accounting.
Independent inventory and Skeptic reviews accepted this bounded engineering
slice. They do not constitute formal project acceptance or release authority.

The complete readiness module passed 46 tests. The dedicated migrations row-
cap module passed seven tests normally and under optimized Python. Normal and
optimized checker outputs were byte-identical, both exited 1, retained all
four blockers, and reported `BLOCKED / DENY` with no release artifacts. The
complete fast tier passed 508 tests across 37 isolated modules. Before this
governance publication, 485 governed records and published history validated.

This work does not classify descriptor/schema exactness, the physical
migrations table, reducer-derived emptiness, row content or order, the supplied
label, diagnostic semantics, public-verifier acceptance, migration authority,
successor-format authority, closure, carrier, STOP clearance, execution, or
capital. Coverage remains `INCOMPLETE`, generation remains `DENY`,
`STOP-M0-3A-002` remains OPEN, live capital remains LOCKED with USD 0
deployable, and the kill switch remains ENGAGED.
