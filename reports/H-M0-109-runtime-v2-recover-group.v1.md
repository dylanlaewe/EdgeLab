# H-M0-109 — Runtime-v2 RECOVER group

## Outcome

Commit `5c1626e4c38d9ac7a011a729b2ff95362daf4974` extends the private
runtime-format-2 replay prefix through one synthetic `RECOVER` transaction
after `CLAIM`. The shared reducer validates the exact closed argument profile,
active-claim compare-and-swap, independently derived state and claim history,
typed reachability, idempotency, and all 15 supplied table snapshots.

Passing candidates remain `UNSUPPORTED / CLOSURE_NOT_COMPILED / DENY`. The
public verifier remains disconnected. No writer, database, selector cutover,
currentness, execution, or capital authority was added. The bound liveness
digest is syntax and provenance only; it is not proof that the evidence exists,
is true, or is current.

## Compiled path

`RECOVER` is compiled only from `CLAIMED` before work reaches `IN_PROGRESS`.
It returns the task to `CLAIMABLE`, advances scheduler and dispatch generations
and the task fence, clears the active claim, and closes that claim as
`RECOVERED`. Recovery from `IN_PROGRESS` is denied because external effects
cannot be inferred or cancelled safely.

The slice is deliberately bounded to `INITIALIZE → CLAIM → RECOVER`. It does
not claim reclaim, retry, or arbitrary lifecycle-history replay.

## Evidence

- 101 focused reducer, transition, image, and public-verifier tests passed.
- The same 101 tests passed under optimized Python (`-O`).
- 293 fast-tier tests passed across 17 isolated modules.
- Compile and whitespace validation passed.
- Before evidence publication, 386 governed records and published history
  validated with M0 capital LOCKED and no approval.
- After evidence publication, 389 governed records and published history
  validated with the same locked, non-authorizing result.
- The alpha/observatory regression passed all 18 tests with the new STOP
  provenance.

Adversarial cases cover stale claims, malformed liveness digests, forbidden
fence input, recovery after work started, fully rehashed hostile after-state,
forged claim closure, and table-projection changes. Two delegated read-only
engineering rereviews found no in-scope blocker; neither constitutes formal
independent acceptance.

## Residual boundary

`STOP-M0-3A-002.v12` remains OPEN. `RETRY`, repeated continuation, repeated
claims and attempts, governance, review, route, remediation, import,
checkpoints, exports, cumulative root work, exact closure identity, and full
A-J acceptance remain unfinished. Live remains LOCKED, kill remains ENGAGED,
deployable capital is USD 0, and no market edge has been demonstrated.
