# H-M0-106 — Runtime-v2 START and YIELD groups

## Outcome

Commit `ce6d92192555146a4d7e9700a096a6d90b6cfff3` extends the private
runtime-format-2 replay prefix through worker `START` and `YIELD` groups. The
new shared worker reducer validates complete prefix continuity, claim/fence
compare-and-swap, retained content, independently derived task and claim state,
typed reachability, idempotency, and all 15 supplied table snapshots.

Passing candidates remain `UNSUPPORTED / CLOSURE_NOT_COMPILED / DENY`. The
public verifier remains disconnected. No writer, database, selector cutover,
currentness, execution, or capital authority was added.

## Evidence

- 93 focused reducer, transition, image, and public-verifier tests passed.
- The same 93 tests passed under optimized Python (`-O`).
- 285 fast-tier tests passed across 17 isolated modules.
- Compile and whitespace validation passed.
- Before evidence publication, 377 governed records and published history
  validated with M0 capital LOCKED and no approval.
- After evidence publication, 380 governed records and published history
  validated with the same locked, non-authorizing result.
- The alpha/observatory regression passed all 18 tests with the new STOP
  provenance.

Adversarial cases reject stale claim IDs, stale fences, task-predecessor
substitution, invented worker payload data, hostile after-state rehashes, and
forged historical claim closure. Existing genesis, initialization, and claim
attacks remain active.

## Residual boundary

`STOP-M0-3A-002.v9` remains OPEN. `CONTINUE`, `FAIL`, `COMPLETE`, `RECOVER`,
`RETRY`, governance, review, route, remediation, import, checkpoints, exports,
cumulative root work, exact closure identity, and full A-J acceptance remain
unfinished. Live remains LOCKED, kill remains ENGAGED, deployable capital is
USD 0, and no market edge has been demonstrated.
