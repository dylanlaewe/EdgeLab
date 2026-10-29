# H-M0-111 — Private atomic transition workspace

## Outcome

Commit `cb33bc85d9c0724a94bab0e6b00847ceaed58a84` adds the private transition
workspace required before compiling repeated claims and attempts. The current
NEW-image replay now validates its initial immutable state once, stages each
already compiled task/claim operation as an atomic delta, commits only after
the complete event group validates, and freezes through the full immutable
`ReducerState` invariant backstop once at trace end.

The immutable `reduce_transition` API uses the same operation planner, so the
workspace is not a second lifecycle implementation. Candidate rows remain
comparison-only and the existing closed event grammar is unchanged.

## Adversarial assurance

Revision-bound exact-plan checks reject foreign, stale, double, and forged
deltas without writes. The workspace rejects shallow and deep copies so
mutable maps cannot alias across divergent revisions. Group patches bind the
exact semantic and commit event identities before workspace mutation. Tests
also cover stage-without-state-mutation, task/claim atomicity, retained event
reuse, immutable/workspace parity, corrupt-final-state rejection, closed
operation scope, cross-pair rejection, and one final freeze across a long
worker trace.

A delegated read-only engineering reviewer found two real alias/forgery
defects during development. Both were reproduced, repaired, regression-tested,
and re-reviewed. The reviewer found no remaining in-scope blocker, but this is
not formal independent Skeptic acceptance.

## Validation

- 114 focused transition, workspace, image, reducer, and public-verifier tests
  passed under normal Python.
- The same 114 focused tests passed under optimized Python (`-O`).
- 306 fast-tier tests passed across 18 isolated modules.
- Python compile checks and Git whitespace checks passed.
- Before governance publication, 392 governed records and published history
  validated; M0 capital remained LOCKED and no approval was granted.
- After governance publication, 395 governed records and published history
  validated with the same locked and non-authorizing result.
- The alpha/observatory regression passed all 18 tests after STOP provenance
  was extended.

## Residual boundary

The image grammar still permits only the first CLAIM and does not dispatch
`RETRY`; attempt projection is still the current single-attempt row. The next
slice must implement cumulative immutable attempt history and exact
attempt-boundary cursor semantics, then compile repeated re-CLAIM/RETRY cycles.

`STOP-M0-3A-002` remains OPEN. Governance/review/routing, remediation, import,
snapshot/export cuts, cumulative root work, exact closure identity, and the
full A-J matrix also remain unfinished. The public verifier continues to
return only `INVALID` or opaque `UNSUPPORTED` under `DENY`.
