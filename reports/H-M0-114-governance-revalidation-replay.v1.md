# H-M0-114 — Governance block and revalidation replay

## Outcome

Commit `05844e9dc1d4b7e7d530f2f3118207c09aaac8b7` extends private
runtime-v2 NEW-image replay through exact `GOVERNANCE_BLOCK` and `REVALIDATE`
groups. Both operations use the same immutable planner and revision-bound
transition workspace as ordinary replay, and valid images remain opaque
`UNSUPPORTED/CLOSURE_NOT_COMPILED/DENY`.

`GOVERNANCE_BLOCK` is the sole stale-task exception. It derives the blocked
tuple, advances scheduler/dispatch/fence counters, adopts current repository
generation, preserves the prior decision receipt, and atomically invalidates
an active claim or revokes an active review. `REVALIDATE` accepts only B0/B1,
advances scheduler generation only, never resurrects auxiliary work, and binds
the new decision receipt exactly to the request evidence digest.

## Adversarial assurance

The workspace delta now includes task, claim, and review writes under one CAS,
resource, retained-event identity, stale/foreign-plan, and freeze boundary.
Whole-image tests cover N0, N1, N2, and N3 governance paths, B0/B1
revalidation, claim invalidation, reclaim after revalidation, exact receipt
replacement, wrong source states, repeated block, malformed arguments,
dispatcher cross-types, cumulative attempt heads, and forged claim-table
history. Direct workspace parity covers N4 review revocation and the exact
stale-task exception until review assignment and repository import make those
branches reachable end to end.

A delegated read-only review found no blocking defect. That review is
engineering feedback, not formal independent Skeptic acceptance.

## Validation

- 91 focused transition/workspace/image tests passed normally.
- The same 91 focused tests passed under optimized Python (`-O`).
- 317 fast-tier tests passed across 18 isolated modules.
- The delegated reviewer independently reran both 91-test modes and found no
  remaining blocker.
- Python compile and Git whitespace checks passed.
- Before governance publication, 401 governed records and published history
  validated; M0 capital remained LOCKED and no approval was granted.
- A stale STOP-v16 alpha digest introduced by the prior evidence publication's
  newline cleanup was corrected and the fail-closed alpha regression passed.
- After governance publication, 404 governed records and published history
  validated with the same locked and non-authorizing result.
- The 18-test alpha/observatory regression passed after extending current STOP
  provenance.

## Residual boundary

N4 governance is not yet reachable in whole-image replay because review
assignment remains uncompiled. Stale-task governance is not yet reachable
there because repository import remains uncompiled. Review/routing,
remediation/import, checkpoint/export cuts, cumulative root work, exact
generated closure identity, and the complete A-J matrix remain unfinished.
`STOP-M0-3A-002` remains OPEN and no currentness or receipt authenticity is
asserted.
