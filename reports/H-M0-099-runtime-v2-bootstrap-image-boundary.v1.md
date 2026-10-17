# H-M0-099 — Runtime-v2 bootstrap and image boundary

## Outcome

Commit `069241de5ffd19dd54a16f0a89f75f4edd330b04` publishes the versioned
runtime-format-2 bootstrap/image successor contract and the first pure
bootstrap enforcement layer. The milestone closes the specification
ambiguities recorded by `STOP-M0-3A-002.v1`; it does not close the STOP or
create a positive whole-image verifier.

The contract fixes the exact host transport, both genesis kinds, selector
bootstrap and checkpoint succession, optional checkpoint-copy semantics,
archive-only legacy behavior, all 15 table snapshots, strict scalar and row
ordering, typed reachability, the `REVALIDATE` receipt equation, and separate
1 GiB transport and cumulative table-root work budgets.

## Dependency and bootstrap boundary

- A closed dependency-closure schema now distinguishes raw file SHA-256,
  schema-document/domain digests, retained documents, bootstrap schemas,
  exact content assets, executable modules, digest domains, resource limits,
  standard-library/external dependencies, runtime assumptions, and a fixed
  deny-only result boundary.
- `verifier_dependency_closure_digest` implements the domain-separated
  canonical digest with only the record's self-digest field excluded.
- The public entrypoint and generated pin carrier are fixed to distinct paths.
  The carrier is the sole `PIN_CARRIER` and sole elided artifact; the entrypoint
  is never elided. `PIN_BLOCK_ELIDED_V1` breaks the source/self-pin cycle while
  retaining every carrier byte outside the generated block.
- Attachment, manifest, and selector validation is implemented as
  `EDGELAB_RUNTIME_V2_BOOTSTRAP_STRICT_V1`: exact host JSON types,
  whole-string patterns, closed keys/conditionals, and asserted Gregorian
  UTC-second timestamps. It is pure, no-I/O, non-authorizing, and not imported
  by the public verifier.
- The contract explicitly defers the exact generated closure artifact until
  the whole-image reducer sources are frozen. Publishing it earlier would make
  the next semantic source change invalidate the artifact.

## Adversarial review

Three delegated read-only reviews separately examined the contract, closure
schema/digest, and strict bootstrap validators. Initial review found an
uncross-bound pin carrier and an incorrect claim that host JSON Schema pattern
and format defaults were equivalent to the strict validator. Both were
repaired: schema/contract/tests now fix the carrier and entrypoint roles, and
the stricter validation profile plus its deliberate raw-schema deltas are
versioned and regression-tested.

All three final rereviews returned `ACCEPT BOUNDED MILESTONE`. They explicitly
excluded the future generated closure, remaining two compiled validators,
closed RuntimeImage implementation, complete reducer, and STOP resolution.
Those exclusions are next-stage blockers, not implied completion.

## Executed evidence

- Focused bootstrap/codec suite: 32 tests passed.
- Final fast tier: 224 tests passed across 13 isolated modules.
- The closure schema passed Draft 2020-12 meta-validation; closed-role,
  path-alias, carrier mismatch, extra-field, missing-role, and double-elision
  mutations denied.
- Raw attachment, manifest, and selector schema pins reproduced exactly.
- Canonical-parser composition, final-newline pattern aliases, invalid calendar
  times, boolean/integer aliases, hostile objects, and direct no-I/O imports
  were tested.
- Production validator before evidence publication validated 356 records and
  published history; M0 capital remained LOCKED and no approval was granted.
- Production validator after evidence publication validated 359 records and
  published history with the same locked and non-authorizing result.
- `git diff --check` passed.

## Residual boundary

`STOP-M0-3A-002.v2` remains OPEN. The actual generated dependency closure and
carrier, registry/descriptor compiled validators, new RuntimeImage transport,
system genesis/bridge reducer, event grouping, typed blob fixed point,
checkpoint/export reconstruction, and exact 15-table materialization remain
unimplemented. The public verifier continues to return only `INVALID` or
`UNSUPPORTED` under `UNANCHORED / UNKNOWN / DENY`.

`STOP-M0-001` and `STOP-M0-3A-001` also remain OPEN; H-M0-041 remains BLOCKED;
H-M0-086 still lacks a genuinely distinct trusted Skeptic; live remains
LOCKED; kill remains ENGAGED; deployable capital remains USD 0; and no edge
has been demonstrated.
