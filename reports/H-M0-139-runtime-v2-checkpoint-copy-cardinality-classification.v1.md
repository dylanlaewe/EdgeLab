# H-M0-139 — Runtime-v2 checkpoint-copy cardinality classification

Commit `dbb751f` extends the cumulative deny-only runtime-v2 semantic resource
classification without changing runtime behavior. Classification v16
byte-binds v15, preserves all thirteen predecessor constraints and all
thirty-eight predecessor-classified sites exactly, and appends one narrow
classification for `MAX_CHECKPOINT_COPIES`.

The new constraint classifies exactly two Discovery v3 sites: the sole
49,999-item scalar definition and the branch-specific `checkpoint_copies`
cardinality binding. The binding closes the exact tuple subject, table row and
assignment, matching tuple-fields row, both loops, subject lookup, chained
comparison, validity result, rejection diagnostic and accounting branch,
complete host-preflight function, and source module. It does not classify the
shared generic comparator, the dynamic reducer relationship, any sibling
cardinality row, or the separately classified per-member byte ceiling.

The governing boundary contract is
`M0.3A_RUNTIME_CHECKPOINT_COPY_CARDINALITY_LIMIT.v1.md`. Dedicated evidence
proves zero, maximum-minus-one, the inclusive maximum, and maximum-plus-one;
exact built-in tuple guards; tuple-subclass rejection; collection-before-member
ordering; immutability; selector independence; accounting; fixed `DENY` and
non-Boolean reports; and the two combined cases required by adversarial review.
At exactly 49,999 items an oversized final member produces only its exact
per-member byte finding and is included in accounted input. At 50,000 items the
same oversized member is not inspected, only the cardinality finding is
reported, and accounted totals are withheld.

Attacker-refreshed census tests reject same-valued and off-by-one scalar
definitions, alternate or literal table maxima, subject substitution, extra
loads or stores, comparison and diagnostic bypasses, and module-level `len` or
`type` shadowing. The first bounded Skeptic pass rejected the evidence because
the two combined rows were promised but not executed. The repaired evidence
was independently re-run and accepted. This is bounded engineering review,
not authenticated STOP clearance, public-verifier acceptance, or release
authority.

The v16 schema is 38,710 bytes with raw SHA-256
`51e5e3e319eaeee34fdb5f592568868381c2c2752b386be80fdd57741c5c1d00`.
The manifest is 35,018 bytes with raw SHA-256
`95cfa3ba2949277a2572da116aa1267bd7d1b77a039338fb2084fe770a9eb407`
and domain-separated self-digest
`52772284683ac1ce1dbbf39e7e2858c35de3feb7c9b10afe7ce3537b75a26dc8`.
The dedicated evidence file is 9,906 bytes with raw SHA-256
`2e287d493f1d11451107a05d30a19ac6d25617629fb7a04f53155de866e576e0`.

Validation passed all 41 readiness tests, including attacker-refreshed
classification tests, and all 10 dedicated boundary tests both normally and
under optimized Python. Normal and optimized checker outputs were
byte-identical and both exited 1 with `BLOCKED / DENY`. The complete fast tier
passed 478 tests across 34 isolated modules. Before governance publication,
476 governed records and published history validated.

Classification v16 contains fourteen constraints and forty classified sites.
Of 703 census sites, 663 remain unclassified. Coverage remains `INCOMPLETE`,
generation remains `DENY`, all four readiness blockers remain, and
`STOP-M0-3A-002` remains OPEN. No closure, carrier, positive public-verifier
result, writer, database, selector cutover, execution authority, STOP
clearance, or capital path was added. Capital remains LOCKED with USD 0
deployable and the kill switch ENGAGED.
