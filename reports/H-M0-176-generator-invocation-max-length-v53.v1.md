# H-M0-176 — Generator-invocation maximum-length proof V53

Engineering commit `49b00fd` appends one exact Draft 2020-12 proof for
`schemas/m0-3a-verifier-dependency-closure.v1.schema.json` at
`/properties/generator_identity/properties/invocation/maxLength`, stable site
`f193d860a83da82df674ace3da79ca2a26371f43751c4ca1776713d4d4130195`.
The selected value is `512`; the isolated meaning is only
`UNICODE_CODE_POINT_COUNT <= 512 UNICODE_CODE_POINTS` for strings, with no
assertion from this keyword for non-string instances.

The proof binds the 15,938-byte schema, root ID, five-level ordinary-properties
ancestry, full Discovery V8 site record, and container digest
`5789bce9561e2fea80886b8fe5436a7a73d413ac9c49dd3a6628a7a2b575d83c`.
Tests discriminate 511/512/513 code points, including 512/513 astral code
points, combining sequences, the empty string, and nonstrings. All five other
same-schema maximum sites, the sibling minimum site, the exact copied source
helper, and supplemental equal-valued source sites fail substitution attacks.

The proof does not establish sibling `type` or `minLength`; invocation presence,
grammar, content, correctness, or reproducibility; generator identity,
authenticity, behavior, or authority; command, argv, shell, process, or runtime
semantics; property reachability, requiredness, or composition; cross-document
or evidence independence/equivalence; full-schema, deployed-validator, or
public validity; independent acceptance; STOP/release clearance; execution,
wagering, or capital authority.

V53 is the exact V52 50-constraint prefix plus this proof, with zero historical
rebases. It has 51 constraints and 84 classified sites: 71 source and thirteen
schema. Of 637 remaining sites, 354 are source-bound and 283 are schema-bound.
Coverage remains `INCOMPLETE`, authorizing use remains `DENY`, and all four
release-readiness blockers remain.

Final identities:

- proof: 2,544 bytes, SHA-256 `215695d491802dfbc9bd9f82ec6bd1773f5937571ee569fe146dcbdd05581fa8`
- V53 manifest: 128,616 bytes, raw SHA-256 `65f044cbfdcd7ac470c3d778e2a89416e22222d397799054063aaa17c70d72c3`, self-digest `e665f36df84e103545bfd55ecc04102583bdc598e66a7ef32b8f5a147616e310`
- V53 schema: 139,229 bytes, SHA-256 `9898117dc678d4f32cade72c05c6ca72f04605b2b9181e1591ec468eba45a916`

The final fast tier passed 79/79 modules in 1307.575 seconds. Its 176,487-byte
log `/tmp/h176-fast-final.log` has SHA-256
`bfd1aae76cd15cf14aefb2199c0376d82a2da9dc17a9d9e64fef3112c9b0e0d8`.
Normal and optimized readiness outputs were byte-identical, 362,403 bytes,
SHA-256 `878c8a01c8d385f13bd9e69698e95c27cb4a60e0e00de96395dc173f3254b3aa`,
and intentionally exited 1 with `BLOCKED` / `DENY`. Two independent bounded
audits returned PASS/ACCEPT. Before governance publication, 587 governed
records and published history validated.

No runtime, public-entrypoint, STOP, release, execution, wagering, or capital
authority changed. `STOP-M0-3A-002` remains OPEN, live capital remains LOCKED
with USD 0 deployable, and the kill switch remains ENGAGED.
