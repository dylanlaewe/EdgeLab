# H-M0-105 — Runtime-v2 CLAIM transaction group

## Outcome

Commit `942f1bc6815806071e05d87159f151b2c315ee8c` publishes the second
private ordinary runtime-format-2 transaction slice. A validated NEW genesis
and `INITIALIZE` prefix may now be followed by exactly one `CLAIM` group
containing `CLAIM_ISSUED` and a final `COMMAND_COMMITTED` event. The reducer
validates the retained prefix and complete claim group, independently derives
the resulting task and claim through the immutable transition kernel, and
compares all 15 supplied table snapshots.

The result remains opaque as `UNSUPPORTED / CLOSURE_NOT_COMPILED / DENY`.
The public verifier remains statically disconnected. No writer, database,
selector cutover, currentness claim, execution permission, or capital path was
added.

## Closed boundary

- The five-event profile replays the complete genesis and `INITIALIZE` prefix
  before the `CLAIM` group can be considered.
- Global and task-local predecessor chains, event sequence, transaction
  positions, repository coordinates, and command heads are exact.
- Event IDs, event digests, transaction IDs, and operation keys cannot collide
  with the retained prefix or within the new group.
- Closed request, response, semantic payload, commit payload, envelope,
  before-state, and after-state alternatives are compiled without runtime JSON
  Schema execution.
- Runtime, chain, repository, operation, operation key, subject, actor, request,
  response, payload, state, claim identity, and commit coordinates are
  cross-bound.
- The validated prefix state, not a supplied table or state document, drives
  replay. The supplied before-state must match that prefix exactly.
- `reduce_transition` independently derives the post-state and OPEN claim; the
  supplied after-state and generated reference must compare exactly.
- Typed reachability is the exact union of genesis, initialization, and claim
  artifacts; extra blobs fail closed.
- Attempts, claims, events, idempotency, tasks, metadata, bootstrap, schema,
  and seal rows are derived before comparison with all supplied tables.

## Adversarial coverage

The deterministic fixture assembles the full five-event image from canonical
request, response, payload, state, event, reachability, and table equations.
Tests reject global- or task-predecessor substitution, reused transaction or
operation identity, generated-claim disagreement, self-consistent hostile
post-state rehashing, and forged attempt, claim, idempotency, or task rows.
All preceding genesis and initialization attacks remain active.

This is a bounded Director engineering milestone. It does not claim formal
independent Skeptic acceptance, clear a STOP, or expand operational authority.

## Executed evidence

- Focused initial reducer, transition, image, and public-verifier suite: 89
  tests passed.
- The same 89 tests passed under optimized Python (`-O`).
- Final fast tier after evidence publication: 281 tests passed across 17
  isolated modules.
- Python compile checks and `git diff --check` passed.
- Production validator before evidence publication: 374 records and published
  history validated; capital remained locked and no approval was granted.
- Production validator after evidence publication: 377 records and published
  history validated with the same locked, non-authorizing result.
- Alpha/observatory regression: 18 tests passed after the new STOP provenance
  record was added.

## Residual boundary

`STOP-M0-3A-002.v8` remains OPEN. Only `INITIALIZE` and its first following
`CLAIM` are compiled through the retained ordinary-group layer. `START`,
`YIELD`, review, completion, retry, recovery, later task operations,
remediation, repository import, checkpoint/export cuts, checkpoint copies,
cumulative root-work accounting, exact closure generation, and the complete
A-J matrix remain unfinished.

`STOP-M0-001` and `STOP-M0-3A-001` remain OPEN; H-M0-041 remains BLOCKED;
H-M0-086 still lacks a genuinely distinct trusted Skeptic; live remains
LOCKED; kill remains ENGAGED; deployable capital remains USD 0; and no edge
has been demonstrated.
