# H-M0-168 — First schema declarative bound V45

Engineering commit `dd73b58` classifies the first real addressed JSON Schema
site under the closed `SCHEMA_DECLARATIVE_KEYWORD_V1` proof contract. The
selected site is
`schemas/m0-3a-active-runtime-selector.v2.schema.json` at
`/properties/active_runtime_id/minLength`, site ID
`685812b87027cea3e8fc9ce370fd21377b11fc6459c06bf2151261260cd178ea`,
with the location-scoped equation `UNICODE_CODE_POINT_COUNT >= 1` for a
string evaluated at that exact pinned location.

The proof binds the 4,708-byte schema, raw SHA-256
`5398ccf55ce90159d9da34f9a29863a856f1e6e38fdb9ab498b8bd71bb5badf9`,
Draft 2020-12 dialect, root ID, containing pointer, containing-subschema
digest, ordered root-to-parent context, instance domain, equation, unit,
non-domain behavior, and two distinct byte-pinned evidence inputs. Empty and
one-code-point strings, combining sequences, emoji, and non-string values are
tested without importing sibling `type`, UUID, selector, cutover, or runtime
meaning.

Classification V45 preserves every V44 semantic field and source-site set,
then appends exactly one schema proof. A zero-evidence-rebase append was not
truthful because seven historical evidence-test paths asserted the former live
census. V45 therefore permits exactly eight evidence-only constraint-record
refreshes across those seven paths, plus one separately identified
non-constraint schema-identity test refresh. The checker rejects any ninth
refresh, any other evidence difference, and any semantic or site-set change.

The resulting census is 39 constraints, 71 classified source sites, exactly
one classified schema site, 72 classified sites total, and 649 unclassified
sites out of 721. Coverage remains `INCOMPLETE`, authorizing use remains
`DENY`, and all four release-readiness blockers remain.

Artifact identities:

- selected proof raw SHA-256:
  `e6b5b765964d96736e1cc66fcf917e84382694928a44b792ca118f34b370f88f`
- selected proof design raw SHA-256:
  `b5b900ea23e8c54b5667510f21900ea81592f9ea893e169716593937457eb593`
- dedicated adversarial test raw SHA-256:
  `911aceadc6b1cd28b9120c21ec77a173ff0348cc06a71de0bcbfe9a973690708`
- V45 manifest raw SHA-256:
  `85945a0ffc253ce53f39bd12c2ebb7c5c1029f62ca5dabbd3ebd9d1b3663b57e`
- V45 manifest self-digest:
  `e9983c8d5531ad786b4a97a0792f9662503b2e2f1fe4dc3d4cfe601bf0cf21c5`
- V45 schema raw SHA-256:
  `2201776e26829ddd1702d01731a467fc6f5621a45cf7330c9324047bdc9f60b9`

The complete fast tier passed 737 tests across 63 isolated modules in
1078.921 seconds. Its release-readiness module passed 80 tests in 1007.533
seconds. Normal and optimized checker outputs were byte-identical with
SHA-256
`22a0587aa67f8f235acb3774855acb6c1d52a3732b05648981ce9576bd5a5306`;
both exited 1, remained `BLOCKED` / `DENY`, retained the same four blockers,
and wrote no release artifacts. Independent bounded inventory and Skeptic
reviews returned `PASS` after the bounded evidence-rebase and audit-wording
remediations. Before governance publication, 563 governed records and
published history validated.

This milestone proves only one exact local declarative keyword meaning. It
does not prove property requiredness, sibling `type`, UUID format, surrounding
applicator reachability, root acceptance, runtime-validator behavior, public
entrypoint enforcement, independent acceptance, STOP clearance, release
authority, execution authority, wagering authority, or capital authority.
`STOP-M0-3A-002` remains OPEN, live capital remains LOCKED with USD 0
deployable, `live_enabled` remains false, and the kill switch remains ENGAGED.
