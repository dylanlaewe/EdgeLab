# H-M0-151 — Runtime-v2 events row-cap classification

Commit `d9365c1` adds one narrow semantic classification to the deny-only
runtime-v2 resource inventory. Classification V28 preserves the exact
twenty-four-constraint V27 prefix and appends only `TABLE_EVENTS_ROWS`, the
positional host-preflight ceiling for the exact built-in `rows` tuple paired by
strict zip with `_TABLE_SPECS[3]`.

The inclusive maximum is 100,000 rows. Zero through 100,000 rows pass this
resource check; 100,001 rows add `TABLE_ROW_LIMIT` at `/3/rows`, mark accounting
incomplete, skip downstream row inspection, and withhold the sanitized image.
Malformed rows at the boundary can still fail later content validation. The
supplied table label is diagnostic-only and cannot select or bypass the cap.

The single composite Discovery V4 site
`9138c0111059d3e29b19bcacd451fa8cedf572d56ea6f4d04fdbc405cf8b00ed`
appears in both definition and enforcement roles and counts once under set-
union accounting. Its separate `_TableSpec` helper, aggregate, shared
comparator, outer-cardinality site, top-level event ceiling, and all five
sibling V4 row-cap sites remain outside the classified set.

Classification V28 has twenty-five constraints, fifty-two unique classified
sites, and 666 unclassified sites out of 718. Its closed schema raw SHA-256 is
`812f396cdf5d6a995e0df624c9c313ec72da1c16283e4d2a9a0f79ae42e85332`;
the manifest raw SHA-256 is
`77b39852f3e0f25ec6ae59838f1e910043ffd03e14eee66d1e56afbdc60a1353`;
and its domain-separated self-digest is
`248cf2774c60af1c3bb8d23149e923491f0e6e22da8f09c38718d8fc7e57ede2`.

Adversarial evidence covers zero, 99,999, 100,000, and 100,001 rows; malformed
content at the boundary falling through without a cap finding; a full-width but
semantically false event row remaining non-authorizing; over-cap failure before
row inspection; label mismatch in both directions against the higher 300,000-
row blobs cap; missing and non-tuple rows before length inspection; outer
cardinality before strict zip; hostile scope expansion; attacker-refreshed
census evidence; exact predecessor history; unique-site union accounting; and
two-way independence from the equal-valued top-level `RuntimeImage.events`
cardinality ceiling.

Independent inventory and Skeptic reviews selected events as the smallest
complete next positional row-cap slice because it has the smallest remaining
row shape. The final Skeptic review accepted the implementation and its
explicit audit-chain nonclaims. These bounded reviews do not constitute formal
project acceptance or release authority.

The final complete fast tier passed 591 tests across 46 isolated modules,
including all 59 readiness tests and nine dedicated events row-cap tests.
Normal and optimized checker outputs were byte-identical with SHA-256
`fdb9bc91f32b3b1f9ea5441f3458b0ae0fb3ca1b70ea867d348dce8dfdee8efb`;
both exited 1, retained all four blockers, and reported `BLOCKED / DENY` with no
release artifacts. Before this governance publication, 512 governed records
and published history validated.

This work proves only an inclusive positional row maximum. It is not the
top-level `MAX_EVENTS` constraint even though both maxima equal 100,000. It
does not validate event sequence or continuity, event identity or digest,
canonical JSON, envelope/payload/schema meaning, global or task chains, head
consistency, uniqueness, primary keys, ordering, top-level/table
correspondence, byte-size limits, reachability, row content, descriptor
meaning, reducer replay, transition or execution correctness, audit acceptance,
or public-verifier acceptance. It grants no STOP, release, execution, wagering,
or capital authority. Coverage remains `INCOMPLETE`, generation remains
`DENY`, `STOP-M0-3A-002` remains OPEN, live capital remains LOCKED with USD 0
deployable, and the kill switch remains ENGAGED.
