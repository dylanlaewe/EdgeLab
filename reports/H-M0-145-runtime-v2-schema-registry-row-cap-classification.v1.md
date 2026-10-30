# H-M0-145 — Runtime-v2 schema-registry row-cap classification

Commit `f733cfd` adds one narrow semantic classification to the deny-only
runtime-v2 resource inventory. Classification V22 preserves the exact
eighteen-constraint V21 prefix and appends only
`TABLE_SCHEMA_REGISTRY_ROWS`, the positional host-preflight ceiling for the
exact built-in `rows` tuple paired by strict zip with `_TABLE_SPECS[11]`.

The inclusive maximum is one. Zero or one row passes this resource check; two
rows add `TABLE_ROW_LIMIT` at `/11/rows`, mark accounting incomplete, skip
downstream row inspection, and withhold the sanitized image. A malformed one-
row input can still fail later content checks. The supplied table label is
diagnostic-only and cannot select or bypass the cap.

The single composite Discovery V4 site
`fda4fc6a03e3b64d2d398e1c8658acb7788ecfe8b3d2512036e4ac9b14b84793`
appears in both definition and enforcement roles and counts once under set-
union accounting. Its helper, the `_TABLE_SPECS` aggregate, shared comparator,
V3 outer-cardinality site, and all eleven sibling V4 row-cap sites remain
outside the classified set. The equal-valued seals cap remains distinct and
unclassified.

Classification V22 has nineteen constraints, forty-six unique classified
sites, and 672 unclassified sites out of 718. Its closed schema raw SHA-256 is
`128144d02fcaaf399881a817b6b25b065d160b8af7b9f89feeda87c1129a73bf`;
the manifest raw SHA-256 is
`37a6dd62c2c6486189f56b5b4a56091aa5539591a10b07ff5d08350fddfff962`;
and its domain-separated self-digest is
`d801a1368aa36a86d9a77de079f35aa4f082b2063dc54862a34642059ab4053a`.

Adversarial evidence covers zero, one, and two rows; malformed one-row content
falling through without a cap finding; two rows failing before row inspection;
mismatched labels in both directions; missing and non-tuple rows before length
inspection; outer cardinality before strict zip; equal-valued seals isolation;
helper/order/equivalent-expression changes; comparator/diagnostic/accounting/
continuation drift; hostile scope expansion; attacker-refreshed census
evidence; exact predecessor history; and unique-site union accounting.
Independent inventory and Skeptic reviews accepted this bounded engineering
slice. They do not constitute formal project acceptance or release authority.

The complete fast tier passed 532 tests across 40 isolated modules, including
all 49 readiness tests. Normal and optimized checker outputs were byte-
identical, both exited 1, retained all four blockers, and reported
`BLOCKED / DENY` with no release artifacts. Before this governance publication,
494 governed records and published history validated.

This work proves only an inclusive positional row maximum in `ITEMS`. It is
separate from the top-level schema-registry and schema-bundle byte limits,
schema-document counts and byte limits, exact singleton and pinned-registry
requirements, row content, descriptor/schema and reducer semantics, supplied-
label and diagnostic meaning, and public-verifier acceptance. It grants no
STOP, release, execution, wagering, or capital authority. Coverage remains
`INCOMPLETE`, generation remains `DENY`, `STOP-M0-3A-002` remains OPEN, live
capital remains LOCKED with USD 0 deployable, and the kill switch remains
ENGAGED.
