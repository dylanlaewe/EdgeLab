# H-M0-103 — Runtime-v2 dependency-closure shape

## Outcome

Commit `82981c156e14d5a042ce85586f3d2d432a34a643` publishes the
private runtime-v2 dependency-closure shape validator. It accepts only exact
canonical bytes in the closed version-1 record language, validates the
self-digest and conservative alias-free inventory semantics, then leaves every
shape-valid candidate opaque as `UNSUPPORTED / CLOSURE_NOT_COMPILED`.

This milestone does not publish generated closure bytes, compile an exact
release identity, create `_runtime_v2_release.py`, connect the public verifier,
claim currentness, permit execution, or change capital authority.

## Closed boundary

- A 1 MiB pre-parse byte limit and deterministic 19-digit integer-token limit
  bound canonical parsing independently of ambient interpreter settings.
- Exact closed objects, JSON types, constants, five bootstrap roles, nine
  retained roles, schema namespaces, inventory ordering, and self-digest are
  compiled without runtime JSON Schema evaluation.
- Already-published bootstrap and retained schema roles are bound to their
  exact schema IDs and repository paths.
- Local import roots are portable, case-safe, non-overlapping proper directory
  ancestors, and every local artifact has exactly one root owner.
- Paths reject trailing-dot and Windows-device aliases. Distribution names use
  one normalized identity. Standard-library and external import namespaces
  reject exact and ancestor/descendant reuse.
- The validator performs no filesystem, Git, package-metadata, environment,
  clock, network, subprocess, or dynamic-import access.
- The public verifier is statically regression-locked against importing either
  the private initial reducer or closure validator.

## Adversarial review

Three independent read-only reviews examined contract consistency, hostile
candidate handling, and test durability. Initial reviews found the wrong
active-selector fixture ID, missing role-to-ID-to-path bindings, root paths
unbound to artifacts, order-dependent root overlap, portable path aliases,
distribution-name aliases, ambient huge-integer parsing, module namespace
prefix aliases, and file paths accepted as import roots.

The implementation and tests were revised until all reviewers accepted the
final bounded result. Demonstrated hostile candidates were converted to
regressions. The positive fixture is explicitly synthetic, incomplete,
non-release, and authority-free.

## Executed evidence

- Focused closure, initial reducer, public verifier, and image suite: 57 tests
  passed.
- Optimized closure, initial reducer, and public verifier suite: 43 tests
  passed under `python -O`.
- Final fast tier: 270 tests passed across 17 isolated modules.
- Production validator before evidence publication: 368 records and published
  history validated; capital remained locked and no approval was granted.
- Production validator after evidence publication: 371 records and published
  history validated with the same locked, non-authorizing result.
- Alpha/observatory regression: 18 tests passed after the new STOP provenance
  record was added.
- Three independent read-only reviews accepted the final bounded milestone.
- Python compile checks and `git diff --check` passed.

## Residual boundary

`STOP-M0-3A-002.v6` remains OPEN. Shape validation and a self-digest do not
prove exact release identity, transitive dependency completeness, source
authenticity, external anchoring, or currentness. Import-edge representation,
pin-carrier byte-length semantics, external metadata digest semantics, exact
marker literals, and the mandatory runtime-assumption inventory remain
unfrozen.

Ordinary transaction groups, checkpoint/export cuts, cumulative root-work
enforcement, and the remainder of the A-J matrix are unfinished. The exact
closure and carrier may be generated only after those semantic sources freeze
and deterministic regeneration is independently accepted.

`STOP-M0-001` and `STOP-M0-3A-001` remain OPEN; H-M0-041 remains BLOCKED;
H-M0-086 still lacks a genuinely distinct trusted Skeptic; live remains
LOCKED; kill remains ENGAGED; deployable capital remains USD 0; and no edge
has been demonstrated.
