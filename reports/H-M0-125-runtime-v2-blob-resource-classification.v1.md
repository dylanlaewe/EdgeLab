# H-M0-125 — Runtime-v2 blob-byte resource classification

Commit `a6ac1c0add8286686e485e90dc77495cb58dc1e0` adds the second
deliberately narrow semantic classification over the runtime-v2 resource
census. The cumulative v2 manifest preserves and byte-binds v1, then
classifies only `MAX_BLOB_BYTES` as an inclusive 16,777,216-byte resource
maximum over the captured bytes supplied in an exact
`BlobRecord.canonical_json` field.

The classification does not claim that the field contains canonical or even
parsed JSON. It binds the exact definition and enforcement sites, the complete
normalized `runtime_v2_image.py` source-module AST, the enclosing preflight
function AST, the ten raw source identities, both census digests, the fifteen
schema identities, both governing contracts, and exact boundary-test bytes.
The v2 manifest's canonical self-digest is
`2b129c103dd2a5f7ec8764416a8ef0bd34c5c2e9c3ef87a4a275176498ea384b`.

Boundary evidence distinguishes maximum-minus-one and maximum supplied fields
from maximum-plus-one. The former remain byte-identical in the sanitized
deny-only transport; the latter emits the exact item-limit finding and
withholds the sanitized image. Refreshed-binding attacks deny comparison
drift, dead guards, body rebinding, no-op or emptied finding sinks, image
withholding bypass, builtin shadowing, authority-field changes, predecessor
redirection, census laundering, schema/evidence drift, and hardlink aliases.

The first Skeptic rereview blocked insufficient durable adversarial evidence.
After every requested attack and the predecessor-link checks were added, the
Skeptic returned PASS. Independent implementation and diff reviews also
returned PASS. These are bounded engineering reviews, not authenticated formal
STOP-clearance authority.

Validation passed 46 focused tests normally and under `python -O`, 372 tests
across the 22-module fast tier, and 434 governed records before publication.
The readiness CLI still exits `1` with `BLOCKED / DENY`, writes no release
artifact, and retains all four blockers.

Only four of 690 census sites are semantically classified; 686 remain
unclassified and coverage remains `INCOMPLETE`. No closure, carrier, public
verifier connection, STOP clearance, writer, database, selector cutover,
operational authority, or capital path was added. The source-module binding
does not attest an unpinned interpreter or externally monkeypatched runtime
objects. Capital remains LOCKED with deployable USD 0 and the kill switch
ENGAGED.
