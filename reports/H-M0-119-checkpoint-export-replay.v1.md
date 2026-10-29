# H-M0-119 — Checkpoint and export replay

Commit `945ed35e3b1e038449b78085eefa19c5c2ec0a6d` compiles private
`CHECKPOINT` and `EXPORT_SNAPSHOT` replay. Each group binds the exact
pre-registration cut across all fifteen descriptor tables, independently
recomputes the document-domain and blob digests, and excludes every artifact
created by its own registering command.

Checkpoint and export sequences now advance independently from zero with exact
prior chains. Exports bind the latest checkpoint at their cut, including null
before the first checkpoint. Checkpoints derive the next selector and
cumulative selector-history digest; exports do not alter selector state.
Snapshot rows use descriptor order, optional checkpoint copies remain
comparison-only, and cumulative root work includes every historical cut plus
the supplied final cut.

The replay accepts snapshot-first export and snapshot tails after repository
import. The narrower import boundary still denies later ordinary task groups
until explicit post-import task selection is separately compiled. Snapshot
identifiers and document digests are retained and rejected atomically on
reuse.

Validation passed 57 focused initial/snapshot tests normally and under
`python -O`, all 205 runtime-v2 tests, and 334 tests across the isolated fast
tier. Independent Skeptic, contract, and engineering reviews found no blocker
after repairs for descriptor snapshot ordering, import-tail fencing,
snapshot-first dispatch, and derived identity uniqueness.

Exact closure generation, explicit post-import task selection, and the
remaining A-J acceptance matrix remain unfinished. Valid images remain
`UNSUPPORTED/CLOSURE_NOT_COMPILED/DENY`; STOP-M0-3A-002 remains OPEN and
capital remains LOCKED.
