# H-M0-098 — Private runtime-v2 transition kernel

## Outcome

Commit `a1debc3571b9cb796420ca89c2cd6f33f2db3492` adds the first executable,
pure in-memory component of the future runtime-format-2 reducer: an immutable
task-transition kernel for task, claim, review, remediation, and repository-
import state. It is private, does no I/O, is not imported by the public
runtime-v2 verifier, and cannot report whole-image consistency or authority.

The same milestone records `STOP-M0-3A-002`. Pre-implementation review found
that the frozen whole-image contract does not yet bind the verifier dependency
closure, immutable bootstrap validators, the complete runtime-image transport
shape, or the exact `REVALIDATE` receipt equation. The STOP prevents those
gaps from being guessed into a positive reducer path.

## Implemented boundary

- All task-state transitions in the frozen state table are implemented,
  including both yield/fail branches, both completion branches, recovery,
  retry, both governance revalidation paths, review decisions, routing, and
  both remediation-source states.
- Repository import derives the mandatory affected set, rejects unsorted or
  duplicate input, handles every stable and fencing state branch, preserves
  omitted optional tasks as stale, excludes C0, and advances only to the exact
  next signed-64-bit generation.
- Claims, reviews, decisions, remediation links, task lineage, and retained
  event identities are cross-validated. Self-review on either identity axis,
  orphan open/closed records, forged link digests, impossible creation
  attempts, future claims, duplicate events, lineage cycles, and counter
  overflow fail closed with stable violations.
- Reduction stages all effects in local maps and constructs a new immutable
  state only after the entire intent succeeds. Late import and remediation
  failures prove that no partial claim, task, or link effect escapes.
- Validation work for decision/review closure and lineage traversal is linear
  apart from deterministic sorting under explicit task/event limits.

## Adversarial review

Three delegated read-only reviews separately covered reducer design, fixture
coverage, and hostile-input/resource behavior. Early reviews found forged
active claims/reviews, unvalidated decision/link records, boolean integer
aliases, duplicate event IDs, quadratic validation, remediation-child retry
rejection, retained self-review, raw host-type crashes, orphan outcome reviews,
and historical claim/link foreign-key gaps. Each was repaired and regression-
tested. All three final rereviews reported no blocker for this explicitly
private, non-accepting foundation.

These are engineering reviews only. They do not satisfy the genuinely distinct
trusted 05 Skeptic authority required by H-M0-086 and do not accept M0.3A.

## Executed evidence

- Focused transition suite: 33/33 tests passed.
- Final fast tier: 207 tests passed across 12 isolated modules.
- Independent operation-by-13-state matrix matched the frozen transition table.
- Python compilation, JSON parsing, staged whitespace checks, and the static
  no-I/O/no-authority import audit passed.
- Production validator before this evidence publication: 354 records and
  published history validated; M0 capital remained LOCKED and no scientific or
  operational approval was granted.
- Production validator after evidence publication: 356 records and published
  history validated with the same locked and non-authorizing result.
- An initial fast-tier attempt with the system Python stopped at import because
  that interpreter lacks `jsonschema`; the exact tier was rerun successfully
  with the repository `.venv` interpreter.

## Explicit residual gaps

The whole-image reducer, transaction/event parser, bootstrap closure, schema
embedding, global/task hash-chain verification, response derivation, blob
reachability, 15-table materialization, checkpoints, exports, selector history,
and both genesis kinds remain unimplemented. The public verifier deliberately
continues to return only `INVALID` or `UNSUPPORTED` under
`UNANCHORED / UNKNOWN / DENY`.

`STOP-M0-001`, `STOP-M0-3A-001`, and `STOP-M0-3A-002` remain OPEN;
H-M0-041 remains BLOCKED; H-M0-086 still lacks a genuinely distinct trusted
Skeptic; live remains LOCKED; kill remains ENGAGED; deployable capital remains
USD 0; and no edge has been demonstrated.
