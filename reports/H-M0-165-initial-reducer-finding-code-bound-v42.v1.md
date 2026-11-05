# H-M0-165 — Initial-reducer finding-code bound V42

Engineering commit `7af6d55` advances the deny-only runtime-v2 semantic
classification from V41 to V42 without changing Discovery V7 or runtime
source. Independent inventory and bounded Skeptic review selected the private
initial reducer's ordinary-finding `code` transformation as the smallest
complete low-authority slice.

V42 adds exactly one constraint,
`INITIAL_REDUCER_FINDING_CODE_CHARACTER_MAXIMUM`, at the subject-bound
`bounded(code, 128)` call
`299a4bc525cdfbb8139236046ee5d4c4d9a54daf151405c3e130f8c09831e0d8`.
For the first `InitialViolation.code` constructed by `_Sink.add`, strings of at
most 128 Python characters pass unchanged. Longer strings become their first
56 characters followed by `#sha256=` and the lowercase SHA-256 hexadecimal
digest of the full original UTF-8 bytes, producing exactly 128 characters.

The shared helper comparison and slice, the artifact and coordinate callers,
the equal-valued `MAX_FINDINGS` cardinality, and the synthetic
`FINDINGS_TRUNCATED` constructor remain unclassified. This transformation is
not input rejection and does not establish diagnostic correctness, code
authenticity, collision resistance, deduplication, report completeness,
private-reducer validity, public-verifier acceptance, STOP clearance,
execution authority, or capital authority.

Classification V42 contains 38 constraints and 71 unique classified sites.
Discovery remains 425 source sites plus 296 schema sites, 721 total; 650 sites
remain unclassified. Coverage remains `INCOMPLETE`, authorizing use remains
`DENY`, and the same four unconditional blockers remain.

The V42 manifest raw SHA-256 is
`9fda39bf5f1227d99ce2018411b78481a273d56dd18f28cde193d001fe295c3e`;
its domain-separated self-digest is
`dc855a01cd87e9e4eb3c81739d29451c373a1226ecd4347e80b7a97a8544ed51`;
and its schema raw SHA-256 is
`b2cdb38ef8bfab74dcaf6bfa55d9e70170680a1d214dc15a3044f3a3e176187d`.

V42 preserves every V41 semantic field and site set. Exactly seven historical
constraints receive enumerated evidence-only refreshes because their tests
assert the current classification census: the previous six successor-aware
constraints plus the V41 private codec depth constraint. Historical records
are byte-pinned and any eighth or broader rewrite is rejected.

The complete fast tier passed 711 tests across 60 isolated modules in
1065.815 seconds. Its embedded release-readiness module passed 77 tests in
996.999 seconds. Dedicated tests passed normally and under optimized Python.
Normal and optimized checker outputs were byte-identical with current-tree
SHA-256
`103a72d9507d007da4047c0ca905241a76525e10cd2a65eeb6dfdfa9b9cce11a`;
both exited 1, retained the same four blockers, and wrote no release artifacts.
Before governance publication, 554 governed records and published history
validated.

Independent bounded Skeptic review returned `PASS` with no mandatory fixes
after reproducing dedicated, related, readiness, schema, checker-parity, exact
seven-rebase, exclusion, and no-runtime-change checks. This is engineering
review, not trusted formal acceptance.

A parallel read-only M0 completion audit found a prerequisite architectural
blocker: all 296 schema-bound census records currently lack stable `site_id`
values, while classification membership is built only from source-bound
sites. Complete 721-site classification is therefore impossible until a
versioned discovery/classification successor assigns domain-separated schema
site identities and validates schema-specific proofs. This finding does not
weaken the V42 result; it changes the next safe assignment from another
one-site classification to repairing schema-site classification support.

`STOP-M0-3A-002` remains OPEN, live capital remains LOCKED with USD 0
deployable, `live_enabled` remains false, and the kill switch remains ENGAGED.
