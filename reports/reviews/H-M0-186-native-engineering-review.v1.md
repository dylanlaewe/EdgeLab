# H-M0-186 read-only engineering review

## Boundary

This owner-authorized AI engineering review is internal and non-authorizing.
It is not formal 05 Skeptic approval, governance acceptance, STOP clearance,
scientific promotion, or operational release. The reviewer made no repository
changes.

## Initial verdict: CHANGES_REQUIRED

The reviewer reproduced the 12/12 focused suite, the 92/92 preservation suite,
and a real two-command Quant recovery. Inspection identified one concrete
authority defect: the candidate automatically invoked Scheduler v1 `RECOVER`
for every replay-valid `CLAIMED` task using a self-generated digest labeled as
liveness evidence. That digest established neither lease expiry nor process
death and could fence a legitimately active claim.

Required correction: H-M0-186 has no authenticated liveness source, so a
`CLAIMED` task must fail closed without recovery, reclaim, fencing, or mutation.
The required after-Research, after-Quant, active-review, and Risk-created paths
can continue because they use exact replayed identities rather than replacing
an active claim.

## Correction and re-review: PASS

The implementation no longer synthesizes liveness evidence or calls `RECOVER`.
Pipeline, Risk, and Director `CLAIMED` states now fail with
`CLAIMED_WITHOUT_AUTHENTICATED_LIVENESS`. A regression proves the event count
and persisted state do not change.

Reproduced evidence:

- corrected focused H-M0-186 suite: 12/12 passed in 25.722 seconds;
- corrected claimed-state denial plus actual cold-process Quant recovery: 2/2
  passed in 4.828 seconds;
- full preservation suite: 92/92 passed in 76.767 seconds before the isolated
  correction; the corrected focused suite and decisive cases passed afterward;
- actual recovery reopened persisted SQLite through startup/replay, resumed
  from Quant, produced `INSUFFICIENT_DATA`, retained DENY/LOCKED/ENGAGED/$0,
  and recorded exactly 18 non-duplicated task events;
- corrupt, missing, altered, stale-claim, and incompatible-generation cases
  fail closed;
- `git diff --check` passed.

The reviewer confirmed replay-derived progress, exact evidence/history
receipts, active claim/reviewer identities, deterministic H-M0-184 equivalence,
and no Scheduler schema, operation vocabulary, runtime format, or H-M0-185
authority-boundary change. No remaining implementation defect was demonstrated.
