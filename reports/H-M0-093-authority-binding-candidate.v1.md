# H-M0-093 — DENY-only historical authority binding candidate

## Outcome

Commit `da009e04900e47b00831cb24d046df74425fdb4c` implements the
first fixed-source composition of a trusted M0.2 historical decision and an
observed M0.3A scheduler subject. The result is deliberately a diagnostic
candidate: every outcome is structurally `DENY`, and no scheduler transition,
executor, paper process, live process, STOP clearance, or capital control
consumes it.

This milestone does not implement positive currentness, generation equality,
an authenticated receipt, or an R-gate. The `R_GATE_CANDIDATE_EVIDENCE` label
means only that a historically valid retained DISPATCH has been bound to the
same task ID and attempt observed in the locked runtime. It is not authorization.

## Implemented boundary

- The public composer accepts only a scheduler, task ID, and capture ID. It
  accepts no caller path, trust root, source snapshot, receipt, generation,
  result, seal, or policy.
- The mapping contract, M0.2 trusted root, and historical capture root are
  fixed to canonical repository paths and exact file-byte SHA-256 pins. An
  alternate scheduler root, dirty pinned source, symlink, non-regular source,
  traversal, or alias fails closed.
- The legacy stage-one trust root now has a closed schema in this composition
  path in addition to its canonical self-digest and dependency-closure checks.
- The retained historical verifier must report historical validity, completed
  replay, exact raw-result agreement, the trusted frozen commit and persisted
  graph, and a DENY-only authorization projection.
- Captured intent/result task ID and positive integer attempt must match the
  requested and locked runtime subject. The runtime is read twice under its
  existing lock boundary, and source bytes plus parsed/loaded trust objects
  must agree across the composition window.
- DISPATCH is classified only as `R_GATE_CANDIDATE_EVIDENCE`; DENY is classified
  as `NON_AUTHORIZING_EVIDENCE`. Both embed `currentness_status: UNKNOWN`,
  `verifier_status: FAIL`, `generation_match: false`, and `authorizing_use: DENY`.
- `verify_binding_integrity` recomputes the candidate, seal, stable projection,
  source projection, seal ID, and raw decision digests and checks all locally
  derivable cross-field equations against the embedded fixed-source projections.
  JSON Schema alone is explicitly insufficient.
- Composition is read-only: it does not initialize, repair, migrate, persist,
  transition, execute, call a network, or mutate repository/runtime state.

## Adversarial review

A separate read-only reviewer initially reproduced two material weaknesses:

- consistently substituted mapping/trust sources could still obtain a bound
  label because source identity depended on caller-selected scheduler root and
  mutable local bytes; and
- schema-valid, rehashed artifacts could misstate task/capture/attempt bindings
  because schemas describe shape rather than digest equations.

The first repair introduced canonical-root enforcement, exact source-byte pins,
non-alias file checks, a closed trust-root schema, and semantic verification.
The reviewer then reproduced a split-read race where pinned capture-root bytes
and the independently loaded capture-root object could disagree. The second
repair binds initial and final byte parses to both loaded trust objects and
embeds the accepted root projections in semantic verification.

The reviewer reran mapping substitution, alternate-root, cross-field forgery,
arbitrary digest, split-read, and coordinated alternate-root rehash probes and
reported no remaining actionable findings. No candidate consumer or positive
authorization branch exists.

## Executed evidence

- Focused scheduler, locked-authority, and binding suite: 49/49 tests passed.
- Final fast tier: 98/98 tests passed across seven isolated modules in 27.985
  seconds.
- Domain tier: 98/98 tests passed across four isolated modules in 772.647
  seconds.
- Independent final review: 27/27 focused probes passed plus 7/7 authority-
  binding tests; no actionable findings remained.
- Production validator before evidence publication: 343 records and published
  history validated; M0 capital remained LOCKED and no scientific or
  operational approval was granted.
- Production validator after evidence publication: 345 records and published
  history validated with the same locked and non-authorizing result.
- Python compilation, JSON Schema meta-validation, source-pin comparison, and
  `git diff --check`: passed.
- Remote synchronization was exact before final validation; code commit
  `da009e0` was pushed to `origin/main` without rewriting history.

## Explicit residual gaps

The candidate does not establish that the active repository equals the frozen
repository, that project/STOP/assignment/handoff/dependency/capability state is
current, that scheduler generations match, or that a receipt is authenticated.
It is neither persisted nor accepted by a transition. A stored candidate must
never be treated as authority; the composer must re-observe its sources and
runtime, and a future positive currentness/R-gate design requires separate
specification, implementation, and independent review.

The local process and loaded verification code remain inside the local trust
boundary. An actor able to replace the running composer, its pins, and its
verifier together is outside this diagnostic's proof.

`STOP-M0-001` and `STOP-M0-3A-001` remain OPEN. H-M0-041 remains BLOCKED and
H-M0-086 still lacks a genuinely distinct trusted Skeptic authority. M0.3A is
not accepted, M1 is not released, no executor exists, live remains LOCKED, the
kill switch remains ENGAGED, deployable capital remains USD 0, and no edge has
been demonstrated.
