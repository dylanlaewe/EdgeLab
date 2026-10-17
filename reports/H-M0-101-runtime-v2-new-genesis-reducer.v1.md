# H-M0-101 — Runtime-v2 NEW genesis reducer

## Outcome

Commit `bd89da129ac62595759846d755a19779c4186b5f` implements a private,
pure reducer for the runtime-format-2 `NEW` genesis slice. It compiles strict
validators for the exact `SYSTEM_GENESIS` request/response and
`RUNTIME_GENESIS` payload/envelope branches, consumes only the detached image
returned by host preflight, and derives the two-selector genesis chain plus all
15 initial tables for exact comparison.

This is a bounded deny-only engineering milestone. The generated verifier
dependency closure does not yet exist, so the reducer cannot validate its
complete shape or exact compiled identity. Its result type can expose only
`INVALID` or `UNSUPPORTED`, sorted bounded violations, and immutable `DENY`.
It cannot expose candidate runtime identity, head, roots, consistency, or
authority. The public verifier remains disconnected.

## Closed boundary

- Request, response, payload, and event validation uses exact built-in types,
  closed keys, whole-string UUID/digest matching, strict Gregorian UTC seconds,
  and hard-coded NEW-genesis branches. No runtime JSON Schema engine executes.
- The exact storage and registry singleton identities and nine retained schema
  document identities are re-established from canonical bytes and
  domain-separated digests.
- Reachability is exactly three typed blobs: request, response, and payload.
  Role relabeling, removal, duplication, extra blobs, ordinary digest mismatch,
  and transaction/payload-reference mismatch deny.
- Runtime, chain, repository, attachment, storage, registry, closure,
  event/manifest, and common-time coordinates are cross-bound independently of
  ordinary hashes.
- Selector generation zero remains opaque schema-valid pre-cutover evidence;
  its digest is recomputed. Generation one is derived exactly from the new
  manifest/runtime, prior selector, and genesis timestamp.
- All 15 tables are derived without using supplied rows as transition input.
  The initial materialization contains three blob rows, one event, one metadata
  row, nine schema-document rows, one registry row, and one seal; all other
  tables are empty. Every supplied cell must match.
- V1 migration is explicitly `UNSUPPORTED`. No legacy source coordinate is
  inferred, repaired, or treated as verified.

## Adversarial review

Three independent read-only reviews examined safety, contract equations, and
test adequacy. The material finding was that a merely self-consistent but
schema-incomplete placeholder closure initially reached an unsupported report
that exposed derived identity and table roots. The result surface was repaired
to expose no derived state at all until the exact generated closure is compiled.
A security rereview accepted the remediation and exercised 402 hostile
validator mutations without an uncaught exception.

The contract review also identified an incorrect selector timestamp diagnostic
coordinate; it now reports `/written_at`. The test review requested broader
role/digest/time/table/finding-bound attacks. Those cases were added before the
final fast-tier run.

## Executed evidence

- Focused initial-reducer suite: 11 tests passed.
- Final fast tier: 252 tests passed across 15 isolated modules.
- Production validator before evidence publication: 362 records and published
  history validated; capital remained locked and no approval was granted.
- Production validator after evidence publication: 365 records and published
  history validated with the same locked, non-authorizing result.
- Three read-only reviews completed; the material closure-output defect was
  repaired, security rereview accepted, and no blocking implementation defect
  remained in the bounded slice.
- Independent review executed 402 hostile strict-validator mutations with no
  uncaught exception.
- Python compilation and `git diff --check` passed.

## Residual boundary

`STOP-M0-3A-002.v4` remains OPEN. The exact generated closure/carrier is absent,
so even a semantically coherent NEW candidate returns only opaque
`UNSUPPORTED / DENY`. Closure-shape compilation, ordinary event groups,
checkpoint/export cuts, cumulative root-work enforcement, and the remainder of
the A-J matrix are unfinished.

The legacy bridge also remains unsupported. Its current contracts transport
no backup, migration-plan, or frozen-v1-closure preimages; those three digests
must be treated only as unverified archival reference coordinates unless a new
versioned transport supplies the bytes. `V16_BOUNDED_REPLAY_ONLY` is not proof
of authenticity, currentness, authority, or historical v16 verification.

`STOP-M0-001` and `STOP-M0-3A-001` remain OPEN; H-M0-041 remains BLOCKED;
H-M0-086 still lacks a genuinely distinct trusted Skeptic; live remains
LOCKED; kill remains ENGAGED; deployable capital remains USD 0; and no edge
has been demonstrated.
