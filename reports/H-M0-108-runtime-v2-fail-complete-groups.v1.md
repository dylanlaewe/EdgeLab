# H-M0-108 — Runtime-v2 FAIL and COMPLETE groups

## Outcome

Commit `145bb9955e12c1f6da6ad34a5b0a1c9402502452` extends the private
runtime-format-2 replay prefix through worker `FAIL` and both `COMPLETE`
outcomes. The shared worker reducer validates their exact closed argument
profiles, source states, claim/fence compare-and-swap, independently derived
terminal state and claim history, typed reachability, idempotency, and all 15
supplied table snapshots.

Passing candidates remain `UNSUPPORTED / CLOSURE_NOT_COMPILED / DENY`. The
public verifier remains disconnected. No writer, database, selector cutover,
currentness, execution, or capital authority was added. Syntactically bound
evidence codes and digests are not treated as proof that evidence is true,
available, or current.

## Compiled paths

- `FAIL` from `CLAIMED` and from `IN_PROGRESS`;
- `FAIL` after one `CONTINUE`;
- `COMPLETE(close=false)` from `IN_PROGRESS`, with or without one `CONTINUE`;
- `COMPLETE(close=true)` from `IN_PROGRESS`, with or without one `CONTINUE`;
- rejection of `COMPLETE` directly from `CLAIMED`.

The slice remains deliberately depth-bounded to the existing 11-event image
limit. It does not claim arbitrary worker-history replay.

## Evidence

- 100 focused reducer, transition, image, and public-verifier tests passed.
- The same 100 tests passed under optimized Python (`-O`).
- 292 fast-tier tests passed across 17 isolated modules.
- Compile and whitespace validation passed.
- Before evidence publication, 383 governed records and published history
  validated with M0 capital LOCKED and no approval.
- After evidence publication, 386 governed records and published history
  validated with the same locked, non-authorizing result.
- The alpha/observatory regression passed all 18 tests with the new STOP
  provenance.

Adversarial cases cover every compiled terminal path, stale claims and fences,
Boolean/integer aliases, malformed failure codes and evidence digests,
event/request operation swaps, fully rehashed hostile after-states, forged
claim closure, and table-projection changes. Two delegated read-only
engineering rereviews found no in-scope blocker; neither constitutes formal
independent acceptance.

## Residual boundary

`STOP-M0-3A-002.v11` remains OPEN. `RECOVER`, `RETRY`, repeated continuation,
repeated claims and attempts, governance, review, route, remediation, import,
checkpoints, exports, cumulative root work, exact closure identity, and full
A-J acceptance remain unfinished. Live remains LOCKED, kill remains ENGAGED,
deployable capital is USD 0, and no market edge has been demonstrated.
