# H-M0-148 — Runtime-v2 attempts row-cap classification

Commit `1534eef` adds one narrow semantic classification to the deny-only
runtime-v2 resource inventory. Classification V25 preserves the exact
twenty-one-constraint V24 prefix and appends only `TABLE_ATTEMPTS_ROWS`, the
positional host-preflight ceiling for the exact built-in `rows` tuple paired by
strict zip with `_TABLE_SPECS[0]`.

The inclusive maximum is 100,000 rows. Zero through 100,000 rows pass this
resource check; 100,001 rows add `TABLE_ROW_LIMIT` at `/0/rows`, mark accounting
incomplete, skip downstream row inspection, and withhold the sanitized image.
Malformed rows at the boundary can still fail later content validation. The
supplied table label is diagnostic-only and cannot select or bypass the cap.

The single composite Discovery V4 site
`a315c994088f9880d6ccbc36147e178f0603a63333f7c47a59e176203997d990`
appears in both definition and enforcement roles and counts once under set-
union accounting. Its separate `_TableSpec` helper, aggregate, shared
comparator, V3 outer-cardinality site, and all eight sibling V4 row-cap sites
remain outside the classified set.

Classification V25 has twenty-two constraints, forty-nine unique classified
sites, and 669 unclassified sites out of 718. Its closed schema raw SHA-256 is
`9b9919868e8f8eebc378e355fb8fb63cdd48b8f59e190dc68eb1c9912d900ee8`;
the manifest raw SHA-256 is
`406384b64c63e5bad8319ab2c0929376b428beec13ea82d879807a7634bb5b27`;
and its domain-separated self-digest is
`2284b168a3d25c5c9fdff21424cccce2dbc4252549a7829d4e55aadec7e28d48`.

Adversarial evidence covers zero, 99,999, 100,000, and 100,001 rows; malformed
content at the boundary falling through without a cap finding; a well-typed but
semantically unsupported attempt remaining non-authorizing; over-cap failure
before row inspection; label mismatch in both directions against the distinct
300,000-row blobs cap; missing and non-tuple rows before length inspection;
outer cardinality before strict zip; hostile scope expansion; attacker-refreshed
census evidence; exact predecessor history; and unique-site union accounting.

Independent inventory and Skeptic reviews initially preferred different
equal-valued tables. After removing test-fixture convenience from the decision,
both selected attempts because it carries less authority-bearing state than
claims. The final Skeptic review accepted the implementation and its explicit
nonclaims. These bounded reviews do not constitute formal project acceptance or
release authority.

The final complete fast tier passed 559 tests across 43 isolated modules,
including all 53 readiness tests and eight dedicated attempts row-cap tests.
Normal and optimized checker outputs were byte-identical with SHA-256
`0e97dc3f131fb510ce93a2d3f5d205665afad6951136376d7a3c7580f8d7f7f6`;
both exited 1, retained all four blockers, and reported `BLOCKED / DENY` with no
release artifacts. Before this governance publication, 503 governed records
and published history validated.

This work proves only an inclusive positional row maximum. It is not a maximum
attempt ordinal, retry or continuation limit, exact or minimum population, or
evidence of one row per observed attempt. It does not validate task/attempt
pairs, predecessor continuity, origin or head correctness, retry history,
task/event existence, primary keys, sorting, row content, descriptor meaning,
reducer replay, transition or execution correctness, or public-verifier
acceptance. It grants no STOP, release, execution, wagering, or capital
authority. Coverage remains `INCOMPLETE`, generation remains `DENY`,
`STOP-M0-3A-002` remains OPEN, live capital remains LOCKED with USD 0
deployable, and the kill switch remains ENGAGED.
