# H-M0-097 — Retained content and pure reducer contract

## Outcome

Commit `4da5aa6d830a51b7efedf791fab1476e40b3ce0d` publishes and pins the
runtime-format-2 retained content bundle and the deterministic contract for the
pure reducer that may be implemented next. It does not implement that reducer,
a writer, a format-2 database, migration, selector cutover, recovery action, or
any authority-bearing path.

The exact bundle contains nine schema documents and 25 event bindings. Request,
response, payload, task-state, attachment, checkpoint, export, legacy archive,
and legacy projection content is closed and reproducibly registered. The
verifier accepts only the exact descriptor and schema bundle; it still returns
only `INVALID` or `UNSUPPORTED` under `UNANCHORED / UNKNOWN / DENY`.

## Closed contract

- Twenty-two operations map to an exact semantic-event grammar, including
  transaction positions, commit rules, system exceptions, retry attempts,
  repository imports, remediation pairs, checkpoints, and exports.
- Task transitions define exact before/after tuples, counters, claim/review row
  effects, repository-currentness behavior, remediation lineage, and two-axis
  owner/reviewer independence.
- Whole-image derivation closes all 15 materialized tables, typed blob
  reachability, singleton values, timestamps, snapshot chains, selector
  evolution, and the empty format-2 migrations table.
- The genesis/manifest and response/event digest cycles are excluded by
  construction. System request and response blobs remain reachable through
  transaction-group typed edges.
- Integer, identifier, event, blob, task, and accounted-input limits are
  explicit. Legacy retained integers are signed-64-bit bounded.
- Schema verification performs no I/O or remote resolution, rejects duplicate
  keys and unsafe schema features, bounds bundle size and findings, hashes
  oversized diagnostic coordinates, and stops diagnostic work at the unique
  finding budget.

## Independent review

Three delegated read-only reviews separately attacked retained-content closure,
reducer determinism, and schema-resolution/resource safety. Findings included a
genesis/manifest hash cycle, unreachable system blobs, incomplete CAS and
repository rules, repeatable remediation lineage, missing review-role identity,
ambiguous import behavior, schema-ID and diagnostic amplification, duplicate
definition traversal, and pin drift. Each issue was repaired and every reviewer
returned a final no-findings result.

These are engineering reviews only. They do not provide the genuinely distinct
trusted 05 Skeptic authority required by H-M0-086.

## Executed evidence

- Focused successor contract/codec/verifier/storage suite: 73/73 tests passed.
- Final fast tier: 174 tests passed across 11 isolated modules.
- Registry generation check, descriptor structural reproduction, Python
  compilation, and `git diff --check` passed.
- Production validator before evidence publication: 351 records and published
  history validated; capital remained locked and no approval was granted.
- Production validator after evidence publication: 353 records and published
  history validated with the same locked and non-authorizing result.
- Commit `4da5aa6` was pushed to `origin/main` without rewriting history.

## Explicit residual gaps

The pure whole-transaction reducer is still unimplemented, so the verifier
cannot validate nonempty events/blobs or report consistency. The next bounded
milestone is an in-memory reducer with adversarial fixtures that independently
derives every table and rejects malformed groups. A writer, SQLite
initialization, migration, selector cutover, positive consistency result, or
authority expansion remains prohibited.

`STOP-M0-001` and `STOP-M0-3A-001` remain OPEN; H-M0-041 remains BLOCKED;
H-M0-086 still lacks a genuinely distinct trusted Skeptic; M0.3A is not
accepted; live remains LOCKED; kill remains ENGAGED; deployable capital remains
USD 0; and no edge has been demonstrated.
