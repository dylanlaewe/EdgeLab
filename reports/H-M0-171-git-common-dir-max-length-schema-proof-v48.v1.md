# H-M0-171 — Git common-directory maximum-length schema proof V48

Engineering commit `6675db2` appends one exact location-scoped JSON Schema
meaning to the deny-only runtime-v2 resource classification. The selected V8
census site is `schemas/m0-3a-runtime-attachment.v2.schema.json` at
`/properties/git_common_dir_identity/maxLength`, site
`d35901dd714a95a4a2aa09a3ce17cbcc45dd1634b681cca5aca40be61d479574`,
with `maxLength: 4096`.

The proof classifies only the local Draft 2020-12 STRING-domain assertion that
Unicode code-point count is at most 4096. Its executable boundary distinguishes
Unicode code points from UTF-8 bytes and grapheme clusters. It does not
classify sibling `type` or `minLength`, root requiredness or
`additionalProperties`, path or filesystem semantics, normalization,
existence, symlinks, Git identity or authenticity, runtime string validation,
full-schema or deployed-validator conformance, or any public, STOP, release,
execution, wagering, or capital authority.

V48 is the exact V47 40-constraint prefix plus this one proof, with zero
predecessor evidence rebases. It contains 41 constraints, 71 classified source
sites, three classified schema sites, 74 classified sites total, and 647
unclassified sites. Coverage remains `INCOMPLETE`, authorizing use remains
`DENY`, and all four release-readiness blockers remain.

Final artifact identities:

- proof JSON: 2,418 bytes, SHA-256
  `3bf20b29d6000c74b1b90a1bd8adbd672e71554572967c3ffd861db6b7907048`
- evidence document: 2,166 bytes, SHA-256
  `6313620c0717d030befbc811f583c3556e4e83f8d10ffab20315dbc8642f2b1a`
- adversarial evidence test: 12,882 bytes, SHA-256
  `54524c3c4a83a000863539135b4fe951b125a101ea16b4dab8663026bf9b497f`
- V48 manifest: 102,065 bytes, raw SHA-256
  `4cc0eb031a8dcd32817fdf7b0d50b54fd1bc933c5f90dc324c826cb126973035`
- V48 manifest self-digest:
  `6771fc9370c02cca61157e92dc8760dedbc8d0f34e357c32292dffbb057c6106`
- V48 schema: 110,129 bytes, SHA-256
  `51ead22568f7db1eef2fa7b71233e80a02838df8f2b1d367c70b6c67880321eb`

The final fast tier passed all 66 isolated modules in 1100.574 seconds. Its
156,966-byte log is `/tmp/h171-fast-final.log` with SHA-256
`961f8c3bc7cf2c85e1921dfa38238d01336e412d0439edab0e8125e3f2830ad7`.
The focused final audit passed 18 tests. Normal and optimized checker outputs
were byte-identical with SHA-256
`ce8fe1841572970a575325c9431ac551e240b32068e24340924fadc689529a93`;
both exited 1 and reported `BLOCKED` / `DENY`. Independent inventory and
bounded Skeptic reviews returned `PASS`. Before governance publication, 572
governed records and published history validated.

No runtime, public-entrypoint, STOP, release, execution, wagering, or capital
authority changed. `STOP-M0-3A-002` remains OPEN, live capital remains LOCKED
with USD 0 deployable, `live_enabled` remains false, and the kill switch
remains ENGAGED.
