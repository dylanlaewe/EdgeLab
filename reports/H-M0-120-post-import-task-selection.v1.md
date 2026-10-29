# H-M0-120 — Post-import task selection

Commit `24a73073681f08ec1012dc752859d59bc47ee8b4` compiles explicit
single-task selection after `IMPORT_REPOSITORY` in the private runtime-v2
replay. The exact retained request subject selects the task and current
attempt; semantic task context, before/after states, response projections, and
the retained task head are then independently cross-bound.

The replay no longer assumes a single-task workspace or even global-sequence
parity. It supports remediation source/child selection, odd-width imports,
snapshot-interleaved ordinary groups, and repeated imports while preserving
all unrelated task and auxiliary history. Imported current tasks may take only
state-legal transitions. Unlisted optional tasks remain stale, and
`GOVERNANCE_BLOCK` remains their sole consumer, including exact active-claim
invalidation.

Validation passed 65 focused initial/snapshot/post-import tests normally and
under `python -O`, all 213 runtime-v2 tests, and 342 tests across the isolated
fast tier. Independent Skeptic, contract, and engineering reviews found no
blocker. An additional stale active-review case confirmed exact
`GOVERNANCE_REVOKED` closure in both modes.

Later-position `INITIALIZE`, exact generated closure identity/carrier, the
unsupported legacy bridge, and the remaining A-J acceptance cases remain
unfinished. Valid images remain `UNSUPPORTED/CLOSURE_NOT_COMPILED/DENY`;
STOP-M0-3A-002 remains OPEN and capital remains LOCKED.
