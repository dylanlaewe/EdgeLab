# H-M0-160 — Runtime-v2 finding-string bounds V7/V37

Engineering commit `76a4b67` advances the deny-only runtime-v2 resource
discovery from V6 to V7 and the semantic classification from V36 to V37. An
independent pre-implementation Skeptic selected the artifact and coordinate
finding-string bounds as one atomic semantic family. A separate
post-implementation Skeptic review returned `ACCEPT` for this bounded
engineering milestone only.

Discovery V7 preserves all 424 V6 source sites and adds exactly one
coordinate-specific composite,
`BOUND_FINDING_COORDINATE_CHARACTER_MAXIMUM_BINDING`, at site
`fc21db21b5ee39513518b3732d554f1d231c93841cefebfed39d33846f3355a8`.
It binds only `VerificationFinding.coordinate` to the 512-character
definition, coordinate caller, shared comparison and slice predecessors,
nested helper, full-original UTF-8 digest input, fixed `#sha256=` suffix, and
truncating return. Inputs of 512 characters or fewer are unchanged; longer
inputs become the first 440 characters plus the 72-character suffix and
lowercase SHA-256 hex digest, producing exactly 512 characters.

Classification V37 appends exactly two subject-specific constraints to the
V36 semantic history. The artifact constraint binds the 256-character raw
definition, exact artifact caller, and V6 artifact composite. The coordinate
constraint binds the 512-character raw definition, exact coordinate caller,
and V7 coordinate composite. The shared helper comparison and slice remain
unclassified, as do all `MAX_FINDINGS` meanings. V37 preserves the first 30
V36 constraints byte-for-byte and preserves constraint 31 semantically; only
its successor-aware H158 evidence-test byte identity is refreshed. The checker
requires the exact historical V36 record and rejects broader predecessor
rewrites.

The census is 425 source sites plus 296 schema sites, 721 total. V37 contains
33 constraints, 64 unique classified sites, and 657 unclassified sites.
Coverage remains `INCOMPLETE`, authorizing use remains `DENY`, and the same
four blockers remain unconditional: `ACCEPTANCE_MATRIX_INCOMPLETE`,
`PUBLIC_ENTRYPOINT_DISCONNECTED`, `RESOURCE_INVENTORY_INCOMPLETE`, and
`V1_BRIDGE_UNSUPPORTED`.

The Discovery V7 manifest raw SHA-256 is
`cdcdf26146deb7f9aa3578f62df71517410b16d74a920aff65b381ea857f2c7c`;
its domain-separated self-digest is
`2169d9099446298aa19251790686ece93cc58faab6c3d2c733933c9e711077a3`;
and its schema raw SHA-256 is
`54f0b91eafffd5db8e6f2ee7c0091ccdb946c12ef039a753eb7f626c9aa4a8d3`.
The Classification V37 manifest raw SHA-256 is
`24c17420c7457ebb795019a262ba05d52b7480bde77ce6c614e40b6cfa63be36`;
its domain-separated self-digest is
`8ad95589877784102f1bbba069ce1f73f5c59cdfe3f6787df9fb8af48cabc925`;
and its schema raw SHA-256 is
`50765d73330832ff4dbbfa9dcb6dc18914829570999b060bfbeafdbcf5ea58e6`.

Adversarial evidence covers both subjects at zero, maximum minus one, maximum,
and maximum plus one; multibyte Unicode; full-original versus truncated digest
input; exact suffix and final lengths; swapped maxima; caller, constant,
encoding, digest, comparator, slice, prefix, and order attacks; missing,
duplicated, substituted, and stale composites; set-union arithmetic; shared
helper and `MAX_FINDINGS` exclusions; refreshed census attacks; and complete
predecessor/ancestor evidence. The V7-aware attack helpers refresh discovery
evidence before exercising classification failures so mutations still fail at
the intended conservative layer. They do not weaken the production checker.

The complete fast tier passed 666 tests across 55 isolated modules in 941.984
seconds. The full release-readiness module passed 71 tests in 879.366 seconds.
Dedicated H160 checks passed normally and under optimized Python. Normal and
optimized readiness outputs were byte-identical with SHA-256
`495bb36c050ce9e34d44862ff01656bf4636d6bd41c5c6f41e4fa4f0dc4b1657`;
both exited 1, retained the same four blockers, and wrote no release artifacts.
Before governance publication, 539 governed records and published history
validated.

No runtime source changed. No scientific, public-verifier, STOP, execution,
wagering, or capital authority expanded. `STOP-M0-3A-002` remains OPEN, live
capital remains LOCKED with USD 0 deployable, `live_enabled` remains false,
and the kill switch remains ENGAGED.
