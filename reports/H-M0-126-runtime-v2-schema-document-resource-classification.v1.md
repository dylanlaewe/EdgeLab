# H-M0-126 — Runtime-v2 schema-document resource classification

Commit `e32c740ae245d32ad8c3998d8ede554039c55e70` adds the third
deliberately narrow semantic classification over the runtime-v2 resource
census. The cumulative v3 manifest preserves and byte-binds v2, re-audits the
v1 ancestor, and classifies only `MAX_SCHEMA_DOCUMENT_BYTES` as an inclusive
262,144-byte resource maximum over the exact `canonical_json` field bytes
supplied to private host-image preflight or deny-only verifier bundle
inspection.

The classification does not claim that the field contains canonical, parsed,
digest-correct, accepted, or schema-valid JSON. It binds both constant copies,
both enforcement sites, the complete normalized image and verifier
source-module ASTs, both enclosing function ASTs, the ten raw source
identities, both census digests, the fifteen schema identities, governing
contracts, and exact boundary-test bytes. The v3 manifest's canonical
self-digest is
`9e7e799aaa51153b18ef636ca5c6e089538a05d97bedf16c026a396a1e109fc3`.

Boundary evidence distinguishes maximum-minus-one and maximum field bytes
from maximum-plus-one at both stages. Host preflight retains the exact admitted
bytes with no size violation through the inclusive boundary and emits only the
item-limit finding while withholding the image above it. Verifier inspection
proves progression to an exact downstream finding set through the boundary,
then emits only `SCHEMA_DOCUMENT_TOO_LARGE` and remains `INVALID / DENY` above
it. Refreshed-binding attacks deny comparison drift, dead guards, body
rebinding, finding-code/sink changes, authority changes, builtin shadowing,
copy divergence, extra constant reads, predecessor/ancestor redirection,
census laundering, schema/evidence drift, and hardlink aliases.

The first implementation and Skeptic rereviews each found durable-evidence
gaps. After the shared claim was narrowed and the requested propagation,
name-cardinality, and accepted-boundary progression attacks were added, both
returned ACCEPT. An independent final diff review also returned ACCEPT. These
are bounded engineering reviews, not authenticated formal STOP-clearance
authority.

Validation passed 69 focused tests normally and under `python -O`, 375 tests
across the 23-module fast tier, and 437 governed records before publication.
The readiness CLI still exits `1` with `BLOCKED / DENY`, writes no release
artifact, and retains all four blockers.

Only eight of 690 census sites are semantically classified; 682 remain
unclassified and coverage remains `INCOMPLETE`. No closure, carrier, public
verifier connection, STOP clearance, writer, database, selector cutover,
operational authority, or capital path was added. The source-module bindings
do not attest an unpinned interpreter or externally monkeypatched runtime
objects. Capital remains LOCKED with deployable USD 0 and the kill switch
ENGAGED.
