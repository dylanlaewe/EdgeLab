# H-M0-090 — Task tuple replay closure hardening

## Outcome

Commit `1628573d8679ac1c814df75756742bd3d0d70722` closes a bounded
M0.3A replay-integrity gap. Scheduler startup now requires exact agreement
between the materialized task inventory and task-event streams, verifies every
task history's before/after continuity and attempt binding, requires a valid
initial event, and rejects an initial tuple that starts beyond N0.

This is task **tuple** replay hardening, not complete task materialization or
M0.3A acceptance. It adds no receipt/currentness semantics and grants no
execution authority.

## Reproduced failure classes

Before the repair, startup could accept locally corrupted state in which:

- a task event's `task_id` or `attempt` column was substituted;
- a materialized task was deleted while its events remained;
- a valid-looking task row was inserted without any event history;
- a rehashed event's `before_json` no longer matched the preceding `after_json`;
  or
- a rehashed first event and matching materialized row began directly in
  `DIRECTOR_GATE_READY / EXECUTION_COMPLETED / APPROVED` with an arbitrary
  generation.

Those cases now fail closed during `startup()` and before scheduler use.

## Implemented invariants

- Materialized task IDs equal the distinct task IDs represented by events.
- Every task has a non-empty, contiguous task-event stream.
- The first event has `before_json: null`; each later `before_json` equals the
  exact prior `after_json`.
- Every `after_json` has the exact scheduler tuple field set and a valid tuple.
- The event's attempt equals the positive integer `after_json.attempt_no`.
- Only `TASK_INITIALIZED` or `TASK_CREATED_FROM_REMEDIATION` may originate a
  task; neither may occur later in its stream.
- N0 is exactly `ACTIVE / CLAIMABLE / NOT_REQUIRED`, attempt 1, with zero
  scheduler/dispatch/fence/continuation counters and no active claim/reviewer.
- The final replayed tuple equals the materialized scheduler tuple.

## Executed evidence

- Focused scheduler suite: 17/17 tests passed in 3.158 seconds.
- Fast tier: 66/66 tests passed across 7 isolated modules in 11.933 seconds.
- Production validator after evidence publication: 339 records and published
  history validated; M0 capital remained LOCKED and no scientific or
  operational approval was granted.
- `git diff --check`: passed.
- A separate read-only engineering review reproduced the original bypasses,
  verified the repair across legitimate retry/import/remediation/review flows,
  and required the N0 origin-shape check before commit.

## Explicit residual gaps

This milestone does not claim complete replay-derived materialization:

- task `owner`, `reviewer`, `predecessor_task`, and `successor_task` metadata are
  not all reconstructed from events;
- attempts, claims, reviews, idempotency results, seals, snapshots, migration
  rows, and all relevant metadata are not yet fully reconstructed or
  integrity-bound;
- `task_id` and `attempt` are checked structurally but remain absent from the
  current task-event digest body;
- no authentic M0.2 decision evidence, authoritative currentness record, or
  composed R-gate is persisted or consumed; and
- caller-provided `receipt_digest` remains non-authoritative.

The next locally safe currentness step is a locked, diagnostic, DENY-only read
substrate over actual Git/attachment/SQLite authority. It must not define a
positive `CURRENT/ALLOW` path until every field mapping and generation rule is
separately reviewed.

`STOP-M0-001` and `STOP-M0-3A-001` remain OPEN. H-M0-041 remains BLOCKED and
H-M0-086 still lacks distinct trusted Skeptic authority. M0.3A is not accepted,
M1 is not released, no executor exists, live remains LOCKED, the kill switch
remains ENGAGED, deployable capital remains USD 0, and no edge has been
demonstrated.
