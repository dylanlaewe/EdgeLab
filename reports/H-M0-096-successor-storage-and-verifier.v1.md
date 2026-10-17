# H-M0-096 — Successor storage descriptor and deny-only verifier boundary

## Outcome

Commit `4fe9420a7cb8c436e1830f99795c636bd2bb4b74` freezes the exact
runtime-format-2 SQLite storage descriptor, canonical digest codec, and a pure
read-only verification boundary. No format-2 database, writer, migration,
selector cutover, recovery action, or active-runtime integration was created.

The verifier can return only `INVALID` or `UNSUPPORTED`. Its result is always
`UNANCHORED / UNKNOWN / DENY`; success and `ALLOW` are unrepresentable. Until
the retained content schemas and reducer semantics are published, every
runtime-image input other than the exact compiled-in storage descriptor must be
empty.

## Frozen boundary

- The descriptor closes 15 `STRICT, WITHOUT ROWID` tables, 29 explicit
  indexes, 15 checkpoint roots, exact DDL, columns, foreign keys, indexes, root
  ordering, forbidden objects, and semantic predicates.
- The supported SQLite compatibility tuple binds reported version `3.50.0`,
  `sqlite_source_id()`, and the sorted compile-options digest. It is not a
  claim of binary or distribution provenance.
- The structural observation covers all main and temp schema objects, the full
  raw `table_list`, exact PRAGMAs, and complete per-table `table_xinfo`,
  `foreign_key_list`, `index_list`, and `index_xinfo`, including implicit
  indexes.
- Canonical JSON rejects floats, non-finite values, aliases, duplicate keys,
  unpaired surrogates, unsupported host types, cycles, excessive nesting, and
  host integer-conversion failures.
- Domain-separated digests cover blobs, events, checkpoints, manifests,
  selectors, selector history, schema documents and registries, storage,
  SQLite structure/options, roots, task predecessors, and the immutable legacy
  archive/projection domains.
- Checkpoint roots now separately bind retained schema documents; NEW runtimes
  hash an empty legacy archive rather than using null. Snapshot chains,
  latest-checkpoint identity, and legacy migration archive/projection
  cross-bindings are exact semantic predicates.

## Independent review

Three delegated read-only reviews attacked storage inventory closure,
migration semantics, and the hostile-input boundary. Findings included temp
schema omission, ambiguous legacy roots, incomplete snapshot cross-kind rules,
projection self-digest binding, SQLite provenance overclaim, ignored-field
callbacks, unwrapped huge integers, and a result count that could not represent
“not evaluated.” All were repaired. Each reviewer returned a final CLEAN
verdict for this bounded freeze boundary.

These reviews are engineering evidence only. They do not supply the genuinely
distinct trusted 05 Skeptic authority required by H-M0-086.

## Executed evidence

- Focused successor storage/codec/verifier/contract suite: 49/49 tests passed.
- Final fast tier: 151 tests passed across 11 isolated modules in 24.040
  seconds.
- Production validator before evidence publication: 349 records and published
  history validated; M0 capital remained LOCKED and no scientific or
  operational approval was granted.
- Production validator after evidence publication: 351 records and published
  history validated with the same locked and non-authorizing result.
- Python compilation, JSON parsing/schema validation, pin reproduction, and
  `git diff --check` passed.
- Commit `4fe9420` was pushed to `origin/main` without rewriting history.

## Explicit residual gaps

The verifier intentionally cannot validate a runtime image or report
consistency yet. Event payload/state/request/response schemas, the complete
retained schema registry, replay reducer, materialization equations, positive
and negative runtime-image fixtures, and full pure semantic verification remain
future milestones. A writer remains prohibited until those contracts are
published and independently reviewed.

There is still no external anchor, positive currentness, authenticated
M0.2-to-M0.3A receipt/R-gate, format-2 runtime, migration, cutover, execution,
or capital authority. `STOP-M0-001` and `STOP-M0-3A-001` remain OPEN;
H-M0-041 remains BLOCKED; H-M0-086 still lacks a genuinely distinct trusted
Skeptic; M0.3A is not accepted; live remains LOCKED; kill remains ENGAGED;
deployable capital remains USD 0; and no edge has been demonstrated.
