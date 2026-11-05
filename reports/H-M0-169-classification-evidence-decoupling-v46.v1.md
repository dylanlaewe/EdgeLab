# H-M0-169 — Classification evidence decoupling V46

Engineering commit `99a4a36` closes the repeated historical-test coupling
exposed by V45. Classification V46 adds no constraint or classified site. It
preserves all 39 V45 constraint semantics and site sets while performing a
one-time, exact evidence migration: nine evidence records across eight
coordinate-allowlisted test paths.

Historical source-constraint tests now bind explicit V42 artifacts, and the
first schema-proof test binds explicit V45 and proof-V1 artifacts. Mutable
current census, blocker, heterogeneous-dispatch, and partition assertions now
live in a dedicated non-evidence integration test. That test is prohibited
from every historical constraint's evidence inputs. A distinct proof V2
changes only the evidence identity; proof V1 and every V1–V45 manifest and
schema remain immutable.

V46 remains 39 constraints, 71 classified source sites, one classified schema
site, 72 classified total, and 649 unclassified. Coverage is `INCOMPLETE`,
authorizing use is `DENY`, and the same four readiness blockers remain.

Artifact identities:

- proof V2 raw SHA-256:
  `ec6f0074f2799cee7a241d217110b11843edd2e4dfe9d6269a66f9d26201213a`
- decoupling design raw SHA-256:
  `cf54fe1f1ea8f50a9d697f4fe5ea833c4b3752ba68f8f8dcd560b523d3552acf`
- V46 manifest raw SHA-256:
  `7a501d128c026e68c6ae3faa857f7d8d1b8e78d1a1a94f08775a90e92560d1b9`
- V46 manifest self-digest:
  `d84fb6db5c982c69483d968d082fca3c028d326354aced767ba78a70036cb718`
- V46 schema raw SHA-256:
  `5ed13467897f95967fb278674063ee598d3da4f7f15353f997430f2fc79e9968`

An independent persistent fast run passed 742 tests across 64 modules in
1087.319 seconds; log SHA-256 is
`03158556f9341da72f13cec8d238d82a1f28f0af73ee0100254e64712fec624e`.
Normal and optimized checker outputs are byte-identical with SHA-256
`8fedaf44c58aac444c3244fc000b7489fd3d5f407e5276bedcde69258db90bea`;
both exit 1 and remain `BLOCKED` / `DENY`. Independent inventory and bounded
Skeptic reviews returned `PASS`. Before governance publication, 566 governed
records and published history validated.

No runtime, public-entrypoint, STOP, release, execution, wagering, or capital
authority changed. `STOP-M0-3A-002` remains OPEN, live capital remains LOCKED
with USD 0 deployable, `live_enabled` remains false, and the kill switch
remains ENGAGED.
