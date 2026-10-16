# H-M0-092 — Bounded scheduler semantic replay closure

## Outcome

Commit `30befe07f34832c2cf5ebde3ebcd0b4060ec35c7` closes the
task-history and auxiliary-lifecycle replay scope defined by M0.3A v16. The
synthetic scheduler now reconstructs exact task transitions, task ownership and
lineage, attempts, every claim, every review assignment, and remediation links
from task events, then compares those derived row sets to SQLite materialization.
Any difference makes the runtime unavailable.

This is an engineering hardening milestone, not M0.3A acceptance. It does not
resolve either open STOP, implement positive currentness, authenticate the
caller-supplied receipt string, create an R-gate, invoke an executor, or grant
paper, live, or capital authority.

## Implemented boundary

- Each normal task event binds an exact-typed task ID, operation, expected tuple,
  task-local repository generation, and receipt string. Boolean/integer aliasing
  and other Python equality substitutions deny.
- Writer request types and replay types now match. Empty identities, numeric
  retry flags, untyped liveness evidence, non-boolean completion modes, empty
  import reasons, malformed review decision digests, and extra initialization
  fields deny before mutation.
- `COMPLETE` is restricted to N2. Governance block and repository invalidation
  are restricted to N0 through N4.
- Repository task events record global `old`, task-local `task_old`, and global
  `new` generations. A task omitted from one import can be imported later, while
  any ordinary transition from a stale task generation denies.
- Attempt rows, current and historical claims, review rows, owner, the unused
  task reviewer field, predecessor/successor links, and remediation-link rows
  are reconstructed and compared exactly.
- Review outcomes carry a lowercase SHA-256 decision digest. Remediation source,
  child, and link records must bind that exact preceding REJECT or REMEDIATE
  decision, one relationship, child owner/receipt, adjacent global events, and
  an acyclic one-successor lineage.
- The existing v1 misspelled wire event names remain unchanged to avoid an
  unversioned storage migration.

## Adversarial review

A separate read-only reviewer found and reproduced several initially accepted
histories that later failed startup or carried weaker semantics:

- truthy numeric retry flags, empty import reasons, and empty child task IDs;
- untyped completion and liveness fields;
- boolean/integer compare-and-swap substitutions;
- remediation decisions not bound to the actual review event;
- multi-task repository imports that confused global and task-local generations;
- a stale unaffected task that could transition against a newer global
  generation; and
- extra initialization request fields accepted by the writer but rejected by
  replay.

All were repaired with negative and positive tests. The reviewer reran the
reproductions, tested a coherent source/child/link decision rehash, and reported
no remaining material findings inside the declared semantic-replay scope.

## Executed evidence

- Focused scheduler/locked-authority suite: 42/42 tests passed.
- Fast tier: 91/91 tests passed across seven isolated modules in 23.475 seconds.
- Domain tier: 98/98 tests passed across four isolated modules in 660.430
  seconds. This run preceded only scheduler-local repairs; the domain modules do
  not exercise the changed scheduler files.
- Production validator before evidence publication: 341 records and published
  history validated; M0 capital remained LOCKED and no scientific or operational
  approval was granted.
- Production validator after evidence publication: 343 records and published
  history validated with the same locked and non-authorizing result.
- Reviewed historical outcome verifier matched the preserved non-green
  43-module, 484-test, 18-nonzero-module baseline. This is not a green test result
  or approval.
- Independent final review: no remaining material findings in scope.
- Python compilation and `git diff --check`: passed.

## Explicit residual gaps

The v1 event/runtime format still does not reconstruct or independently seal:

- idempotency request and response rows;
- runtime metadata, repository-global advancement semantics, and genesis fields;
- runtime seals;
- migration-ledger rows;
- snapshot roots; or
- a task event's global predecessor ID inside its own digest.

A hostile actor able to rewrite the complete event chain and all mutable heads
is outside this bounded closure. Those controls require an explicit versioned
format milestone, not an unannounced reinterpretation of v1.

`STOP-M0-001` and `STOP-M0-3A-001` remain OPEN. H-M0-041 remains BLOCKED and
H-M0-086 still lacks a genuinely distinct trusted Skeptic authority. M0.3A is
not accepted, M1 is not released, no executor exists, live remains LOCKED, the
kill switch remains ENGAGED, deployable capital remains USD 0, and no edge has
been demonstrated.
