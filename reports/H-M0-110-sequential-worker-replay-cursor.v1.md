# H-M0-110 — Sequential worker replay cursor

## Outcome

Commit `0d43a8ee596591d092f4bb3f04552b53b83459dd` replaces the private
runtime-format-2 reducer's enumerated event depths and repeated full-prefix
scans with a locally derived sequential cursor for the compiled one-task,
one-attempt, one-claim worker lifecycle.

The result is deliberately not a general lifecycle dispatcher. NEW genesis,
`INITIALIZE`, and the first `CLAIM` remain fixed, while every later complete
pair is dispatched only through the closed compiled worker/recovery profile.
A later `CLAIM_ISSUED` or `TASK_RETRIED` is denied.

Passing candidates remain `UNSUPPORTED / CLOSURE_NOT_COMPILED / DENY`. The
public verifier remains disconnected. No writer, database, selector cutover,
currentness, execution, or capital authority was added.

## Compiled depth and derivation

Any complete odd event count within the existing 100,000-event host cap can be
replayed. A 39-event fixture exercises `START` followed by 16 `CONTINUE`
groups. The cursor retains exact global and per-attempt heads plus event-ID,
event-digest, transaction-ID, and operation-key indexes. It advances only
after the whole group validates.

Typed blob reachability is accumulated and compared once against the final
catalog. Idempotency rows accumulate once, while final task and claim rows are
projected from immutable reducer state. Supplied tables remain comparison-only.

The event-index work is linear only for this one-claim scope. Repeated claims
and attempts remain disabled because the current immutable transition state
would rebuild growing historical collections and reintroduce quadratic work.

## Evidence

- 103 focused reducer, transition, image, and public-verifier tests passed.
- The same 103 tests passed under optimized Python (`-O`).
- 295 fast-tier tests passed across 17 isolated modules.
- Compile and whitespace validation passed.
- Before evidence publication, 389 governed records and published history
  validated with M0 capital LOCKED and no approval.
- After evidence publication, 392 governed records and published history
  validated with the same locked, non-authorizing result.
- The alpha/observatory regression passed all 18 tests with the new STOP
  provenance.

Adversarial coverage includes a non-enumerated 13-event trace, a 39-event
trace, even/truncated tails, late duplicate event IDs, transaction IDs and
operation keys, late task-sequence drift, explicit re-CLAIM/RETRY exclusion,
hostile projections, typed reachability, and unchanged normal/optimized
behavior for every earlier compiled fixture. Two delegated read-only
engineering rereviews found no in-scope runtime blocker; neither constitutes
formal independent acceptance.

## Residual boundary

`STOP-M0-3A-002.v13` remains OPEN. A transition workspace/delta design,
re-claim, `RETRY`, historical multi-attempt projection, governance, review,
route, remediation, import, checkpoints, exports, cumulative root work, exact
closure identity, and full A-J acceptance remain unfinished. Live remains
LOCKED, kill remains ENGAGED, deployable capital is USD 0, and no market edge
has been demonstrated.
