# H-M0-159 — Runtime-v2 finding-artifact discovery V6

Engineering commit `45fd17f` advances the deny-only runtime-v2 resource
discovery from V5 to V6. Independent inventory rejected a duplicate direct
classification of already represented `MAX_EVENTS` primitives and instead
selected the smallest new complete semantic unit: the verifier finding
artifact character-bound and truncation flow.

Discovery V6 preserves all 423 V5 source sites and adds exactly one
`UNCLASSIFIED` composite,
`BOUND_FINDING_ARTIFACT_CHARACTER_MAXIMUM_BINDING`, at site
`a445402743f72d03a718bc0d56e45291c02e63bf4df74d8b424bb3c9e73b744e`.
It binds only `VerificationFinding.artifact` to the 256-character definition,
artifact caller, shared comparison and slice predecessors, nested helper,
full-original UTF-8 digest input, fixed `#sha256=` suffix, and truncating
return. Inputs of 256 characters or fewer are unchanged; longer inputs become
the first 184 characters plus the 72-character suffix and lowercase SHA-256
hex digest, producing exactly 256 characters. Coordinate truncation, generic
shared-helper meanings, finding-count limits, diagnostic correctness, and
public-verifier authority remain explicitly excluded.

Classification V36 is a census-only rebase. It preserves all 31 V35
constraint semantics and all 58 classified site IDs. Its only constraint-byte
change refreshes the H158 test evidence from the V35-aware test identity to the
successor-aware V36 identity. The checker requires the exact historical V35
evidence record and denies any broader predecessor rewrite. The census is now
424 source sites plus 296 schema sites, 720 total, with 662 unclassified.
Coverage remains `INCOMPLETE` and generation remains `DENY`.

The Discovery V6 manifest raw SHA-256 is
`6830ac8083e46bce74f535423aafba2fc82c40732c7544e71d301e3fe63aa6e5`;
its domain-separated self-digest is
`9df58a944adcb004a4b5eb3add0910f8e356573cff2636d7053d66ff0ab1456b`;
and its schema raw SHA-256 is
`fa748f5ed12cde22aa0a23e1c4261a27954abb05fc87169c5385838aebfac9e9`.
The Classification V36 manifest raw SHA-256 is
`e933ffac21b652352819c35e9eb3cf31afb5b49b920f9256006c430587907e1e`;
its domain-separated self-digest is
`ba9d0d49cf7c201db9b62ee15ae1d88193553047c6e017e95a401782ee2a24e6`;
and its schema raw SHA-256 is
`5ae8b3e1b2f71e5934d6a4d83529db6c0ae212e13fc0288384ad3d5ff3b66283`.

Adversarial evidence covers 0, 255, 256, and 257 characters; multibyte Unicode;
full-original versus truncated digest input; alternate encodings, algorithms,
comparators, prefixes, slices, coercions, and construction order; coordinate
and shared-helper conflation; missing, duplicated, substituted, or stale
predecessors; attacker-refreshed census data; and semantic or evidence-only
rewrites of the V35 predecessor. The final fast tier passed 660 tests across
54 isolated modules in 742.322 seconds. Focused H158/H159 and predecessor-
rewrite checks also passed normally and under `-O`. Normal and optimized
readiness outputs were byte-identical with SHA-256
`9d9e7a844c86eb5ff6cebda2b8890e4725b2223f244ae16eb253f80d827d1075`;
both exited 1, retained the same four blockers, and wrote no release artifacts.
Before governance publication, 536 governed records and published history
validated.

Fresh independent Skeptic review returned `ACCEPT` for this bounded engineering
milestone only. It is not formal project or release acceptance. No runtime
source changed. `STOP-M0-3A-002` remains OPEN, live capital remains LOCKED with
USD 0 deployable, `live_enabled` remains false, and the kill switch remains
ENGAGED.
