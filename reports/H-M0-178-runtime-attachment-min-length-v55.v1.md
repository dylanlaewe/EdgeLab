# H-M0-178 — Runtime-attachment minimum-length family V55

Engineering commit `ee914d3` appends a closed two-member Draft 2020-12 family
for the direct-root runtime-attachment string minima:

- `git_common_dir_identity/minLength`, site `91ac8b306ad7aaabaccc9f87de0460ce6ae4aa41d7edc09ca870364eaa9ecf38`
- `repository_root_realpath/minLength`, site `b9d97c6663e8bf814f90b1e69ba3a8ea30573b0ef575709552fe9c5e20ca06ca`

Each proof is independently owned and means only
`UNICODE_CODE_POINT_COUNT >= 1 UNICODE_CODE_POINTS` for strings at its exact
pinned location. Non-string instances receive no assertion from this keyword.
Both sites share the same 1,527-byte schema and copied
`{type:string,minLength:1,maxLength:4096}` container, but coordinate identity
remains mandatory: container equality never substitutes for path, pointer, or
ancestor identity. The closed family binds exact membership, canonical order,
predicate, excluded maximum siblings, evidence lanes, and family digest
`e75f6a8bf084041b7882629f89fc5529d95b76b89879905dbaaf8539f0e5f616`.

Boundary evidence distinguishes empty from nonempty strings but cannot by
itself distinguish code-point, byte, grapheme, or another positive-length
metric. The unit comes only from the frozen Draft 2020-12 profile. The two
immutable V50 exclusion records remain truthful as V50-time nonmembership and
unclassified state; V55 separately classifies the sites without rewriting or
enlarging V50.

The family does not establish sibling `type` or `maxLength`, combined
1-to-4096 validity, requiredness, path syntax or canonicality, filesystem or
repository properties, Git identity, source-helper equivalence, runtime
enforcement, cross-member independence, full-schema or public validity,
independent acceptance, STOP/release clearance, execution, wagering, or
capital authority.

V55 is the exact V54 52-constraint prefix plus the two ordered proofs, with
zero historical rebases. It has 54 constraints and 87 classified sites: 71
source and sixteen schema. Of 634 remaining sites, 354 are source-bound and 280
are schema-bound. Coverage remains `INCOMPLETE`, authorizing use remains
`DENY`, and all four release-readiness blockers remain.

Final identities:

- git proof: 2,321 bytes, SHA-256 `118185812dfc9179a291570dc4616d69ac9f9ad7485135273c905dfd1b58f426`
- repository proof: 2,326 bytes, SHA-256 `51c6e47b7945d3cf6a2a9d668824d67e53fff0778762aed82dc9885a1976dfcf`
- family artifact: 5,384 bytes, raw SHA-256 `e7ceb134dffe66e7ca3695c4d4dc73eb4d644f2a3a6628ec75f045b36bb27f2d`
- V55 manifest: 136,924 bytes, raw SHA-256 `c82365a11a5cce64c91422151c4b38052ea78f2ed43d4848802734e6d2fe5ad1`, self-digest `d3bddff8ddb0d5f8ed137872f4125f04329035db8f1e48e7a49f2a454f4d3aab`
- V55 schema: 148,309 bytes, SHA-256 `178bf3a50470180e666543df97aa2bc2370478c0a5f85008d82aef041b9fe3a9`

The final fast tier passed 83/83 modules in 1750.234 seconds. Its 184,367-byte
log `/tmp/h178-fast-final.log` has SHA-256
`4bb1cf85c1d622a78064574675a864d0e9f1232eae0338b0b8d890468970243a`.
Normal and optimized readiness outputs were byte-identical, 362,403 bytes,
SHA-256 `7d5b0e6180321f3e58f7a2377ccf17f6651bb38306034997ab51f5a0fdc581f8`,
and intentionally exited 1 with `BLOCKED` / `DENY`. Two independent bounded
audits returned PASS/ACCEPT. Before governance publication, 593 governed
records and published history validated.

No runtime, public-entrypoint, STOP-clearance, release, execution, wagering, or
capital authority changed. `STOP-M0-3A-002` remains OPEN, live capital remains
LOCKED with USD 0 deployable, and the kill switch remains ENGAGED.
