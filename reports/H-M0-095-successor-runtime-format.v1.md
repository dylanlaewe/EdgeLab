# H-M0-095 — Successor runtime and event format specification

## Outcome

Commit `fa70c124a54bbb942921bfaa4583b4f70086f132` specifies EdgeLab runtime
format 2 and event format 2 without constructing, activating, or migrating a
runtime. The format remains synthetic and structurally
`UNANCHORED / UNKNOWN / DENY`. It cannot accept M0.3A, clear a STOP, establish
positive currentness, authenticate a receipt, create an R-gate, attach an
executor, authorize paper/live activity, or move capital.

The specification closes the representation contract for canonical events,
global and task predecessors, command transactions, idempotency replay,
manifests, selectors, checkpoints, schema registries, and legacy format-1
archive/projection. It explicitly preserves the residual fact that coordinated
rewrite or rollback of every local copy cannot be detected without a future
external anchor.

## Defined boundary

- The only supported runtime/event pair is `(2, 2)`; unknown or mixed versions
  deny rather than downgrade.
- Every event binds its runtime, chain, global and task coordinates,
  predecessors, transaction, request/response digests, schema-tagged blobs,
  repository generation/bundle, and null authority binding.
- Genesis and first-task predecessor roots have exact domain-separated
  constructions. Task/global sequence and transaction grouping are closed.
- Replay must derive and exactly compare metadata, both heads, task state,
  attempts, claims, reviews, remediation links, idempotency, seals, migrations,
  snapshots, blobs, schemas, and checkpoints.
- Active-runtime selection is a retained one-way chain: generation zero is
  format 1, later generations are format 2, and rollback remains locally
  unanchored and non-authorizing.
- Format-1 evidence remains immutable and archive-only. Migration begins with
  no active v2 tasks, never backfills receipts or idempotency, requires a
  sidecar-free verified source, and crosses a fail-closed cutover boundary.
- The exact storage-schema descriptor, its schema and fixtures are a mandatory
  prerequisite. Until published, no format-2 database, manifest, migration,
  selector cutover, or verifier result is constructible or valid.

## Adversarial review

Two delegated read-only reviewers independently examined the existing runtime,
migration/cutover design, and integrity threat model. Their findings led to
explicit closure of:

- a manifest/genesis digest cycle;
- selector history, recovery classifications, and one-way cutover semantics;
- arbitrary first-task predecessor roots;
- format-dispatched v1/v2 negotiation and WAL recovery boundaries;
- incomplete legacy row widths, tagged SQLite cells, storage inventory, and
  canonical base64;
- contradictory v1 sidecar migration behavior and incomplete pending-v2
  checkpoint handling;
- ambiguous response/event digest ordering, schema registry closure, and local
  checkpoint claims; and
- an underdefined SQLite DDL-normalization digest.

After remediation, both reviewers reported no remaining freeze blocker in
their reviewed scopes. Their review was advisory engineering evidence, not the
distinct trusted 05 Skeptic authority still required by H-M0-086.

## Executed evidence

- Successor contract suite: 16/16 tests passed.
- Final fast tier: 118/118 tests passed across eight isolated modules in
  24.439 seconds.
- All new schemas parsed and passed Draft 2020-12 meta-validation and bounded
  positive/negative examples.
- Python compilation and `git diff --check` passed.
- Production validator before evidence publication: 347 records and published
  history validated; capital remained LOCKED and no scientific or operational
  approval was granted.
- Production validator after evidence publication: 349 records and published
  history validated with the same blocked, locked, and non-authorizing result.
- Specification commit `fa70c12` was pushed to `origin/main` without rewriting
  history.

## Explicit residual gaps

No format-2 encoder, pure verifier, storage descriptor, database, writer,
migration builder, selector cutover, or crash-injection implementation exists.
The active scheduler remains format 1. The next bounded milestone is the exact
storage-schema descriptor plus a pure read-only encoder/verifier; it must remain
disconnected from the active runtime.

Positive currentness, an authenticated M0.2-to-M0.3A receipt/R-gate, and an
external history anchor remain separate design and review problems.
`STOP-M0-001` and `STOP-M0-3A-001` remain OPEN. H-M0-041 remains BLOCKED and
H-M0-086 still lacks a genuinely distinct trusted Skeptic authority. M0.3A is
not accepted, M1 is not released, live remains LOCKED, the kill switch remains
ENGAGED, deployable capital remains USD 0, and no edge has been demonstrated.
