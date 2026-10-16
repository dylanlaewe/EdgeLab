# H-M0-091 — Locked actual-authority diagnostic substrate

## Outcome

Commit `702a48eadaecacac11b82de89ba1e144fbc9a8aa` adds a read-only,
DENY-only authority substrate over the actual repository, runtime attachment,
and scheduler database. It accepts only a `Scheduler` and task ID, acquires the
shared scheduler lock, reads SQLite through an immutable connection, verifies
the attachment/seal/event replay, checks task and auxiliary consistency, and
re-reads both repository and runtime authority before returning.

The result is diagnostic. It always embeds a schema-v3-valid verification
result with historical input unavailable for gate use, currentness `UNKNOWN`,
verifier `FAIL`, generation match false, and `authorizing_use: DENY`. There is
no `CURRENT/ALLOW` branch and no scheduler, paper, live, executor, or capital
action.

## Implemented boundary

- The public API cannot accept caller snapshots, source roots, bindings,
  receipts, race flags, or authorization policy.
- The actual Git bundle is read three times while the cooperative scheduler
  lock is held; any commit or selected-content change denies.
- SQLite is opened with `mode=ro&immutable=1`. Existing WAL/SHM sidecars deny,
  and the read creates no sidecars or runtime content.
- Runtime permissions are checked without creating or repairing files.
- Attachment bytes are digest-checked after capture, preventing a verified-read
  versus returned-read substitution.
- Runtime metadata is type-checked; schema-invalid authority is converted to a
  typed `AUTHORITY_INVALID` denial inside the API and revalidated by the CLI.
- Task event replay, materialized tuple, repository generation, active claim,
  attempt chain, and active review assignment are checked.
- Active claim and review actors are bound back to their digest-protected task
  events.
- Governance blocking and repository import now mark cleared active claims and
  reviews `GOVERNANCE_BLOCKED` in the same transaction.
- The returned authority object has its own SHA-256 digest. Every failure path
  returns `UNAVAILABLE` and the same closed denial envelope.

## Adversarial review

A separate read-only engineering review reproduced and required repairs for:

- attachment time-of-check/time-of-use substitution;
- permission repair and lock-file creation during a nominal read;
- mutable denial state that could be changed into a schema-valid `ALLOW`;
- unchecked metadata yielding schema-invalid coherent records;
- ordinary read-only SQLite creation of WAL/SHM sidecars;
- empty attachment/actor fields yielding schema-invalid coherent records;
- orphaned attempts and active claim/review materializations; and
- accepted governance transitions that cleared task pointers without fencing
  the corresponding auxiliary rows.

After repair, the reviewer reported no remaining material findings and directly
verified immutable no-sidecar reads, schema-valid denials, malformed metadata,
governance fencing, repository-import fencing, races, permissions, lock
contention, and denial immutability.

## Executed evidence

- Focused scheduler/locked-authority suite: 33/33 tests passed.
- Fast tier: 82/82 tests passed across 7 isolated modules in 25.879 seconds.
- Independent final review: 16/16 locked-authority tests and 17/17 legacy
  scheduler tests passed, plus direct adversarial probes.
- Production validator before evidence publication: 339 records and published
  history validated; M0 capital remained LOCKED and no scientific or
  operational approval was granted.
- Production validator after evidence publication: 341 records and published
  history validated with the same locked/non-authorizing result.
- The reviewed historical outcome verifier still matched the preserved
  non-green 43-module, 484-test baseline; this is not a green test result.
- `git diff --check`: passed.

## Explicit residual gaps

This milestone does not implement authoritative currentness or an R-gate:

- the stored `decision_receipt_digest` remains caller supplied and
  non-authoritative;
- historical decision evidence is neither composed nor verified by this
  reader; v3 `historical_status: INVALID` means unavailable gate input, not a
  finding that preserved historical evidence is false;
- authoritative runtime, assignment, handoff, claim, project, STOP,
  capability, dependency, inventory, and Git reachability mappings/generation
  rules remain undefined;
- attempt, closed claim/review, idempotency, seal, snapshot, migration, and
  metadata history is not yet fully reconstructed from digest-bound events;
- a runtime with any SQLite sidecar fails closed instead of attempting recovery;
  and
- no scheduler transition consumes this diagnostic result.

The next safe step is a versioned, independently reviewed source-mapping and
generation contract plus sealed historical subject/decision binding. A
positive currentness result and atomic R-gated scheduler transitions must wait
for that contract.

`STOP-M0-001` and `STOP-M0-3A-001` remain OPEN. H-M0-041 remains BLOCKED and
H-M0-086 still lacks distinct trusted Skeptic authority. M0.3A is not accepted,
M1 is not released, no executor exists, live remains LOCKED, the kill switch
remains ENGAGED, deployable capital remains USD 0, and no edge has been
demonstrated.
