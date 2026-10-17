# H-M0-102 — Legacy-bridge assurance amendment

## Outcome

Commit `5b302ed5af81103d79aef91223ad3826d20d0f4f` publishes the
runtime-format-2 legacy-bridge assurance amendment. It closes the ambiguity in
the existing contracts without changing any retained schema, registry,
storage descriptor, writer, selector, verifier result, currentness claim, or
capital authority.

The disposition is fail-closed: `V1_MIGRATION` is unconditionally
`UNSUPPORTED` under the current schemas and `RuntimeImage` carrier. A supplied
archive and projection cannot substitute for the absent source database,
consistent backup, migration plan, frozen verifier closure/commit content, or
repository-bundle content required by the controlling migration contract.

## Closed boundary

- Strict attachment decoding, canonical byte equality, duplicate-free parsing,
  and the raw source-attachment digest equation are explicit.
- A complete successor-capture profile fixes all 12 legacy table column
  sequences, SQLite storage classes, nullability, and total row orders.
  `tasks.reviewer` is SQL `NULL` only; exactly one seal and zero snapshots are
  bridge-eligible.
- Successor eligibility is explicitly stricter than historical v16 startup.
  Unchecked null/blob operation keys and migration artifact digests, extra
  seals, and snapshots deny capture even where frozen startup accepts them.
- Legacy archive/projection domain digests are separated from format-2 blob
  digests through four complete cross-record equations.
- The missing database, backup, plan, verifier, commit/tree, and repository
  preimages are unverified archival coordinates, not typed reachability edges.
  `V16_BOUNDED_REPLAY_ONLY` is a scope/producer-claim label, not proof of
  authenticity, currentness, authority, or historical verification.
- The acyclic build order now names archive/projection, request, response,
  payload, event, manifest, metadata, seal, and selectors exactly.

## Adversarial review

Three independent read-only reviews examined contract assurance, the compiled
legacy table profile, and test durability. Initial review found an incorrect
nullable-text allowance for `tasks.reviewer`, incomplete missing-preimage
classification, a conditional policy loophole, conflated digest-domain prose,
an incomplete dependency order, and self-referential tests.

The amendment and tests were revised before acceptance. All reviewers accepted
the final bounded amendment with no remaining blocking issue. Tests now pin
literal raw and domain digests for all nine retained schema documents, registry
and storage documents, plus all five bootstrap schema raw hashes; they also
freeze the complete table profile and all four equality chains.

## Executed evidence

- Focused amendment and test-tier suites: 15 tests passed.
- Successor-contract plus amendment review suite: 33 tests passed in
  independent review.
- Final fast tier: 258 tests passed across 16 isolated modules.
- Production validator before evidence publication: 365 records and published
  history validated; capital remained locked and no approval was granted.
- Production validator after evidence publication: 368 records and published
  history validated with the same locked, non-authorizing result.
- Alpha/observatory regression: 18 tests passed after the new STOP provenance
  record was added.
- Three independent read-only reviews accepted the final amendment.
- `git diff --check` passed.

## Residual boundary

`STOP-M0-3A-002.v5` remains OPEN. This amendment deliberately does not create a
legacy projector or relax migration evidence. Any future migration support
requires a new versioned evidence carrier and all corresponding registry,
request/payload, manifest, storage, and runtime-format treatment.

The exact generated verifier dependency closure/carrier, closure-shape
validator, ordinary transaction groups, checkpoint/export cuts, cumulative
root-work enforcement, and the remainder of the A-J matrix remain unfinished.
The public verifier remains disconnected and cannot report positive local
consistency.

`STOP-M0-001` and `STOP-M0-3A-001` remain OPEN; H-M0-041 remains BLOCKED;
H-M0-086 still lacks a genuinely distinct trusted Skeptic; live remains
LOCKED; kill remains ENGAGED; deployable capital remains USD 0; and no edge
has been demonstrated.
