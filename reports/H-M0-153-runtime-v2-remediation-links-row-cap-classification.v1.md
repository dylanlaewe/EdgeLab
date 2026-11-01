# H-M0-153 — Runtime-v2 remediation-links row-cap classification

Commit `4599b18` adds one narrow semantic classification to the deny-only
runtime-v2 resource inventory. Classification V30 preserves the exact
twenty-six-constraint V29 prefix and appends only
`TABLE_REMEDIATION_LINKS_ROWS`, the positional host-preflight ceiling for the
exact built-in `rows` tuple paired by strict zip with `_TABLE_SPECS[8]`.

The inclusive maximum is 100,000 rows. Zero through 100,000 rows pass this
resource check; 100,001 rows add `TABLE_ROW_LIMIT` at `/8/rows`, mark accounting
incomplete, skip downstream row inspection, and withhold the sanitized image.
Malformed rows at the boundary can still fail later content validation. The
supplied table label is diagnostic-only and cannot select or bypass the cap.

The single composite Discovery V4 site
`6eb1e8475a75168cb60283d4b97c37c5a037e377b6f06c30c386678136d1d03a`
appears in both definition and enforcement roles and counts once under set-
union accounting. Its separate `_TableSpec` helper, aggregate, shared
comparator, outer-cardinality site, and all three sibling V4 row-cap sites
remain outside the classified set.

Classification V30 has twenty-seven constraints, fifty-four unique classified
sites, and 664 unclassified sites out of 718. Its closed schema raw SHA-256 is
`4b0e2f6897d0abccf045ce54f91539d5b690c1d6ed1fc3d7c9a5bad6f34b06f3`;
the manifest raw SHA-256 is
`5c5185aeb00edbc1adcd7153fc920af2183d5d69edba9d717988719cf5435d34`;
and its domain-separated self-digest is
`b61a3b8067f8be692a100198febe5dcaf3d38cbe77003e6f10bf854a95d1cd37`.

Adversarial evidence covers zero, 99,999, 100,000, and 100,001 rows; malformed
content at the boundary falling through without a cap finding; duplicated
full-width but semantically false self-links remaining non-authorizing;
over-cap failure before row inspection; label mismatch in both directions
against the higher 300,000-row blobs cap; missing and non-tuple rows before
length inspection; outer cardinality before strict zip; hostile scope
expansion; attacker-refreshed census evidence; exact predecessor history; and
unique-site union accounting.

Independent inventory and Skeptic reviews selected remediation links over the
smaller review row because review directly encodes independent actor, role,
status, and closure semantics. The final Skeptic review accepted the
implementation and its corrective-lineage nonclaims. These bounded reviews do
not constitute formal project acceptance or release authority.

The final complete fast tier passed 611 tests across 48 isolated modules,
including all 63 readiness tests and eight dedicated remediation-links row-cap
tests. Normal and optimized checker outputs were byte-identical with SHA-256
`33efdba0c7065d3eafa00b37b9fced6bee6fa2a78e254e938cb36920bebdff6b`;
both exited 1, retained all four blockers, and reported `BLOCKED / DENY` with no
release artifacts. Before this governance publication, 518 governed records
and published history validated.

This work proves only an inclusive positional row maximum. It does not validate
link-ID uniqueness, source/child task, attempt, or event existence or
distinction, decision/link digest correctness or authenticity, reciprocal
lineage, one-successor rules, acyclicity, remediation authorization, retained
REJECT/REMEDIATE ancestry, review/routing validity, task-head consistency,
primary keys, ordering, row content, descriptor meaning, reducer replay,
transition or execution correctness, or public-verifier acceptance. It grants
no STOP, release, execution, wagering, or capital authority. Coverage remains
`INCOMPLETE`, generation remains `DENY`, `STOP-M0-3A-002` remains OPEN, live
capital remains LOCKED with USD 0 deployable, and the kill switch remains
ENGAGED.
