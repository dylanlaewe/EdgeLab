# H-M0-150 — Runtime-v2 blobs row-cap classification

Commit `5b18237` adds one narrow semantic classification to the deny-only
runtime-v2 resource inventory. Classification V27 preserves the exact
twenty-three-constraint V26 prefix and appends only `TABLE_BLOBS_ROWS`, the
positional host-preflight ceiling for the exact built-in `rows` tuple paired by
strict zip with `_TABLE_SPECS[1]`.

The inclusive maximum is 300,000 rows. Zero through 300,000 rows pass this
resource check; 300,001 rows add `TABLE_ROW_LIMIT` at `/1/rows`, mark accounting
incomplete, skip downstream row inspection, and withhold the sanitized image.
Malformed rows at the boundary can still fail later content validation. The
supplied table label is diagnostic-only and cannot select or bypass the cap.

The single composite Discovery V4 site
`3403f4586733a9541140f3d4ec7590a7466ba3de8fb7ed599661cfb1cd20d428`
appears in both definition and enforcement roles and counts once under set-
union accounting. Its separate `_TableSpec` helper, aggregate, shared
comparator, outer-cardinality site, and all six sibling V4 row-cap sites remain
outside the classified set.

Classification V27 has twenty-four constraints, fifty-one unique classified
sites, and 667 unclassified sites out of 718. Its closed schema raw SHA-256 is
`9e58b2729fc9d24565a426c128c3cf20c2b1e853844105cb627197ee584ebbfa`;
the manifest raw SHA-256 is
`b9ef8ebf2d5698c2b7bb37634aae26f56534ca28caeae8480fc1c1b9948bbda3`;
and its domain-separated self-digest is
`8c01543438e9a6c61d0b29d4fab44ead41a62558521e28529069badda6c550b3`.

Adversarial evidence covers zero, 299,999, 300,000, and 300,001 rows;
malformed content at the boundary falling through without a cap finding; a
full-width but semantically false blob row remaining non-authorizing; over-cap
failure before row inspection; label mismatch in both directions against the
lower 100,000-row claims cap; missing and non-tuple rows before length
inspection; outer cardinality before strict zip; hostile scope expansion;
attacker-refreshed census evidence; exact predecessor history; unique-site
union accounting; and two-way independence from the equal-valued top-level
`RuntimeImage.blobs` cardinality ceiling.

Independent inventory and Skeptic reviews selected blobs as the smallest
complete next positional row-cap slice because it has the least workflow and
approval authority surface among the remaining tables. The final Skeptic
review accepted the implementation and its explicit nonclaims. These bounded
reviews do not constitute formal project acceptance or release authority.

The final complete fast tier passed 580 tests across 45 isolated modules,
including all 57 readiness tests and nine dedicated blobs row-cap tests. Normal
and optimized checker outputs were byte-identical with SHA-256
`ed08df1c684ce95c45b4f0639d315e53f1e89ba9369e4c5ac6adc6d157929e4e`;
both exited 1, retained all four blockers, and reported `BLOCKED / DENY` with no
release artifacts. Before this governance publication, 509 governed records
and published history validated.

This work proves only an inclusive positional row maximum. It is not the
top-level `MAX_BLOBS` constraint even though both maxima equal 300,000. It does
not validate blob digests, schema identifiers, canonical JSON, UTF-8 or body-
byte limits, uniqueness, primary keys, ordering, reachability, top-level/table
correspondence, storage meaning, row content, descriptor meaning, reducer
replay, transition or execution correctness, or public-verifier acceptance.
It grants no STOP, release, execution, wagering, or capital authority. Coverage
remains `INCOMPLETE`, generation remains `DENY`, `STOP-M0-3A-002` remains OPEN,
live capital remains LOCKED with USD 0 deployable, and the kill switch remains
ENGAGED.
