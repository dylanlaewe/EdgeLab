# H-M0-087 repository-import replay repair — v1

## Disposition

**ENGINEERING DEFECT REPAIRED; NO M0.3A RELEASE OR CONTROL APPROVAL.**

The M0.3A scheduler remains a local synthetic runtime. `STOP-M0-001` and
`STOP-M0-3A-001` remain OPEN, M0 remains blocked, M1 remains unreleased, the
executor remains `MOCK_ONLY`, live remains `LOCKED`, the kill switch remains
`ENGAGED`, and deployable capital remains USD 0.

## Reproduced defect

`Scheduler.import_repository()` changed each affected task's materialized
repository and scheduler generations but emitted only the global
`REPOSITORY_GENERATION_ADVANCED` runtime event. On the next `startup()`, replay
compared the changed task tuple to the last task event and denied the runtime
with `RuntimeUnavailable: replay/materialized tuple mismatch`.

This was a correctness defect in the non-operational scheduler. It did not
create execution or capital authority. Failing closed on restart prevented use
of the inconsistent runtime, but it also made a legitimate repository import
unrecoverable.

## Repair

Commit `e113de8e424c580b62ceb988c9d3e9df75cf52a6` records a
`REPOSITORY_GENERATION_APPLIED` task event for every affected task in the same
SQLite transaction as the task mutation and global generation event. The task
event binds the before/after tuple, old/new generation, repository bundle,
source commit and import reason. Replay can therefore verify the new
materialized tuple after restart.

Duplicate affected-task identities now deny before mutation. This prevents one
import request from incrementing the same task more than once while claiming a
single repository generation.

The repair covers both paths:

- a claimable task whose repository generation advances in place; and
- a non-claimable task that is fenced into `GOVERNANCE_BLOCKED /
  EXECUTION_BLOCKED`.

## Verification

- `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest
  tests.test_transactional_scheduler tests.test_alpha tests.test_web -v`:
  27 tests passed in 6.240 seconds.
- `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m src.edgelab.validate`:
  331 records and published history validated; M0 capital remained LOCKED; no
  scientific or operational approval was granted.
- `git diff --check`: passed before commit.
- The focused scheduler module alone passed 13 tests in 3.425 seconds.

Two full-suite discovery runs were started concurrently during the audit. The
legacy corpus is not concurrency-safe and the overlapping runs produced
unreliable fixture errors; both were stopped and are not claimed as validation.
No failing result was hidden or converted to a pass. Test tiering and isolated
full-suite execution remain follow-up engineering work.

## Remaining boundaries

This repair does not authenticate receipt digests, reviewers, liveness,
retryability or routing evidence. It does not extend replay verification to
every auxiliary table. It does not resolve the authoritative M0.2
receipt/currentness/R-gate contract identified by `STOP-M0-3A-001`, and it does
not clear any prior finding. Independent review remains required before any
M0.3A release claim.
