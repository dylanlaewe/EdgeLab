# H-M0-104 — Runtime-v2 INITIALIZE transaction group

## Outcome

Commit `96aedef9abed9d367232e168a472bd1005033a0d` publishes the first
private ordinary runtime-format-2 transaction slice. A NEW genesis may now be
followed by exactly one `INITIALIZE` group containing `TASK_INITIALIZED` and a
final `COMMAND_COMMITTED` event. The slice validates the complete retained
group, recomputes the resulting task through the immutable transition kernel,
derives its materialized rows, and compares all 15 supplied table snapshots.

The result remains opaque as `UNSUPPORTED / CLOSURE_NOT_COMPILED / DENY`.
The public verifier remains statically disconnected. No writer, database,
selector cutover, currentness claim, execution permission, or capital path was
added.

## Closed boundary

- The genesis reducer now resolves its three typed blobs from a global,
  canonical, digest-indexed supplied catalog without trusting the final blob
  inventory as derived reachability.
- The ordinary group requires exact global and task-local predecessor chains,
  unique event and transaction identities, shared transaction coordinates,
  semantic-then-commit ordering, and one UTC-second timestamp.
- Closed request, response, payload, commit payload, envelope, and task-state
  alternatives are compiled without runtime JSON Schema execution.
- Runtime, chain, repository, operation, operation-key, subject, request,
  response, payload, state, task-predecessor, and commit coordinates are
  cross-bound.
- The supplied after-state never drives replay. `reduce_transition` derives the
  task independently and the supplied document must compare exactly.
- Typed reachability requires the precise genesis and group request, response,
  payload, and task-state blobs and rejects extras.
- Attempts, events, idempotency, tasks, metadata, bootstrap, schema, and seal
  rows are derived before comparison with all supplied tables.
- Public-verifier regression locks explicitly forbid imports of the initial
  reducer, group planner, closure validator, and transition kernel.

## Adversarial coverage

The deterministic integration fixture is independently assembled from
canonical request, response, state, semantic payload, commit payload, event,
and table equations. Tests reject shared-group mutation, malformed commit
binding, reused event or transaction identity, self-consistent hostile
after-state rehashing, unreachable blobs, forged materialized task rows,
noncanonical content, role substitution, and all pre-existing genesis attacks.

The implementation was manually reread against the frozen content-reducer,
successor-format, and runtime-image contracts after resumption. Earlier
read-only contract mapping independently recommended this exact first slice;
final delegated diff rereviews were unavailable, so this milestone does not
claim independent formal acceptance.

## Executed evidence

- Focused initial reducer, transition, image, and public-verifier suite: 83
  tests passed.
- The same 83 tests passed under optimized Python (`-O`).
- Final fast tier: 275 tests passed across 17 isolated modules.
- Python compile checks and `git diff --check` passed.
- Production validator before evidence publication: 371 records and published
  history validated; capital remained locked and no approval was granted.
- Production validator after evidence publication: 374 records and published
  history validated with the same locked, non-authorizing result.
- Alpha/observatory regression: 18 tests passed after the new STOP provenance
  record was added.

## Residual boundary

`STOP-M0-3A-002.v7` remains OPEN. Only `INITIALIZE` is compiled through the
retained ordinary-group layer. Later single-semantic task operations,
remediation, repository import, checkpoint/export cuts, checkpoint copies,
cumulative root-work accounting, exact closure generation, and the complete
A-J matrix remain unfinished.

`STOP-M0-001` and `STOP-M0-3A-001` remain OPEN; H-M0-041 remains BLOCKED;
H-M0-086 still lacks a genuinely distinct trusted Skeptic; live remains
LOCKED; kill remains ENGAGED; deployable capital remains USD 0; and no edge
has been demonstrated.
