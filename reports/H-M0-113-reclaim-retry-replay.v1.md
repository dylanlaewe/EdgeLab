# H-M0-113 — Repeated claim and exact retry replay

## Outcome

Commit `cfdef6a26849e48dd53dd5645d940149bce4523b` extends the
private runtime-v2 NEW-image reducer through closed repeated `CLAIM` and exact
`RETRY` transaction groups. Recovery or yield may return a task to `N0` for a
new claim, while failure may open only the contiguous next attempt through the
shared immutable/workspace retry planner.

This is private deny-only engineering. Valid images still return opaque
`UNSUPPORTED/CLOSURE_NOT_COMPILED/DENY`; the public verifier, execution, and
capital paths are unchanged.

## Attempt-boundary assurance

A retry request and before-state bind the failed attempt `n`. Its semantic
task context, after-state, and response bind attempt `n + 1`, task sequence 1,
and the exact domain-separated root for that new attempt. The planner requires
literal `retryable: true`, advances scheduler and dispatch generations plus
task fence, clears task-local assignments, and creates no claim row. The
cursor keeps attempt `n` headed by the accepted failure and opens `n + 1` only
after the complete group validates.

Repeated claims advance the retained head of the current attempt and derive a
fresh exact claim row only from `N0`. Historical attempt and claim rows are
projected cumulatively from accepted cursor state. Candidate omissions,
reordering, rewritten heads, altered fences/status, and cross-attempt
substitutions fail closed.

The post-initialize dispatcher admits only exact string event types assigned to
the compiled claim or worker profiles. Unknown and hostile non-string values
return `INVALID` rather than escaping through host-language membership errors.

## Validation

- 87 focused transition/workspace/image tests passed under normal Python.
- The same 87 focused tests passed under optimized Python (`-O`).
- 313 fast-tier tests passed across 18 isolated modules.
- A delegated read-only reviewer independently reran both 87-test modes,
  reproduced and challenged the dispatcher boundary, and found no remaining
  blocker after the fix.
- Python compile checks and Git whitespace checks passed.
- Before governance publication, 398 governed records and published history
  validated; M0 capital remained LOCKED and no approval was granted.
- After governance publication, 401 governed records and published history
  validated with the same locked and non-authorizing result.
- The 18-test alpha/observatory regression passed after extending current STOP
  provenance.

The delegated review is engineering feedback, not formal independent Skeptic
acceptance.

## Residual boundary

`STOP-M0-3A-002` remains OPEN. Governance/revalidation, review and routing,
remediation, repository import, checkpoint/export cuts, cumulative root work,
exact generated closure identity, and the complete A-J matrix remain
unfinished. The next bounded slice should compile exact governance block and
revalidation groups before review/routing can be trusted.
