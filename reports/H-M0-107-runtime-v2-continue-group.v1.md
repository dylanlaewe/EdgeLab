# H-M0-107 — Runtime-v2 CONTINUE group

## Outcome

Commit `c3f1747655101356b814df29bf98b34f55fad17c` extends the private
runtime-format-2 replay prefix through one bounded worker `CONTINUE` group
after `START`. The shared worker reducer now validates its exact argument
profile, claim/fence compare-and-swap, retained content, independently derived
continuation count, typed reachability, idempotency, and all 15 supplied table
snapshots.

Passing candidates remain `UNSUPPORTED / CLOSURE_NOT_COMPILED / DENY`. The
public verifier remains disconnected. No writer, database, selector cutover,
currentness, execution, or capital authority was added.

## Evidence

- 94 focused reducer, transition, image, and public-verifier tests passed.
- The same 94 tests passed under optimized Python (`-O`).
- 286 fast-tier tests passed across 17 isolated modules.
- Compile and whitespace validation passed.
- Before evidence publication, 380 governed records and published history
  validated with M0 capital LOCKED and no approval.
- After evidence publication, 383 governed records and published history
  validated with the same locked, non-authorizing result.
- The alpha/observatory regression passed all 18 tests with the new STOP
  provenance.

Adversarial cases reject stale claim IDs, stale fences, hostile continuation
counts in retained state, and forged continuation counts in the task table.
Existing chain, payload, reachability, genesis, initialization, claim, START,
and YIELD attacks remain active.

## Residual boundary

`STOP-M0-3A-002.v10` remains OPEN. Repeated continuation, `FAIL`, `COMPLETE`,
`RECOVER`, `RETRY`, repeated claims, governance, review, route, remediation,
import, checkpoints, exports, cumulative root work, exact closure identity,
and full A-J acceptance remain unfinished. Live remains LOCKED, kill remains
ENGAGED, deployable capital is USD 0, and no market edge has been demonstrated.
