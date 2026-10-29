# H-M0-112 — Cumulative immutable attempt projection

## Outcome

Commit `c4946e36c3e4352307f6c81683a7d04fb39237d7` replaces the
runtime-v2 NEW-image reducer's final-attempt-row patch output with a cumulative
attempt projection owned by the accepted replay cursor. Every retained attempt
now preserves its predecessor, origin event, and current semantic-event head,
and the derived `attempts` table contains all accepted attempts in primary-key
order.

This is a private deny-only prerequisite. `RETRY` and repeated `CLAIM` remain
uncompiled, candidate rows remain comparison-only, and the public verifier is
unchanged.

## Adversarial assurance

Attempt opening requires task sequence 1, an absent current key, and either the
null predecessor for attempt 1 or the exact retained `n - 1` predecessor for a
later attempt. Same-attempt advancement requires the next task sequence and
exact retained semantic-event predecessor. The commit owner validates the
attempt mutation before the transition workspace is changed, so forged,
skipped, duplicate, stale, and cross-head metadata cannot partially advance
either owner.

Tests demonstrate multiple cumulative attempts without rewriting the closed
prior attempt head, origin/head separation, skipped predecessor rejection, and
zero cursor/workspace mutation on a late projection mismatch. A delegated
read-only reviewer found no in-scope blocker. That review is engineering
feedback, not formal independent Skeptic acceptance.

## Validation

- 49 focused workspace and initial-image tests passed under normal Python.
- The same 49 focused tests passed under optimized Python (`-O`).
- 308 fast-tier tests passed across 18 isolated modules.
- A delegated reviewer additionally ran 82 focused tests normally and under
  optimized Python; both runs passed.
- Python compile checks and Git whitespace checks passed.
- Before governance publication, 395 governed records and published history
  validated; M0 capital remained LOCKED and no approval was granted.
- After governance publication, 398 governed records and published history
  validated with the same locked and non-authorizing result.
- The 18-test alpha/observatory regression passed after extending current STOP
  provenance, and the live loopback observatory exposed STOP v15, LOCKED, and
  ENGAGED from the refreshed governed snapshot.

## Residual boundary

Because retry dispatch remains uncompiled, the multi-attempt positive test
drives the private cursor directly. The next slice must add exact RETRY to the
shared workspace planner, compile the old-attempt/new-attempt boundary, admit
repeated CLAIM only from N0, and add end-to-end historical attempt/claim
tampering tests.

`STOP-M0-3A-002` remains OPEN. Governance/review/routing, remediation, import,
snapshot/export cuts, cumulative root work, exact closure identity, and the
full A-J matrix also remain unfinished. The public verifier continues to
return only `INVALID` or opaque `UNSUPPORTED` under `DENY`.
