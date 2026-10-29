# H-M0-118 — Repository-import replay

Commit `9c8241174e94bd015af9e5abdd5fe96f4ab1bb30` compiles private
`IMPORT_REPOSITORY` replay for zero through bounded many affected tasks. It
validates sorted task semantics, the final repository-advancement semantic,
the commit envelope, repository coordinates, exact before/after states,
claim/review fencing, task heads, runtime metadata, idempotency, and blob
reachability before one atomic workspace/cursor update.

The slice supports a terminal import after remediation, including the
mandatory source and optional child. Import itself is terminal until explicit
post-import task selection is separately compiled. The frozen retained-content
contract's reason pattern and candidate-bundle equality semantics are preserved
without importing narrower historical prose into the exact replay boundary.

Validation passed 83 focused tests normally and under `python -O`, all 198
runtime-v2 tests, and 327 tests across the isolated fast tier. Independent
Skeptic and engineering reviews found no blocker after repairs to runtime-event
identity retention, metadata advancement, hostile event-type handling, and the
terminal boundary.

Checkpoint/export cuts, explicit post-import task selection, cumulative root
work, closure generation, and A-J acceptance remain unfinished. Valid images
remain `UNSUPPORTED/CLOSURE_NOT_COMPILED/DENY`; STOP-M0-3A-002 remains OPEN and
capital remains LOCKED.
