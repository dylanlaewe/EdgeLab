# H-M0-174 — Repository-root maximum-length proof V51

Engineering commit `fce0632` appends one exact Draft 2020-12 schema proof for
`schemas/m0-3a-runtime-attachment.v2.schema.json` at
`/properties/repository_root_realpath/maxLength`, site
`bd7b0ebc888973d3388c8ab0d67c0fbcf03333fa27b5b86616a924c5ee90b848`.
The pinned keyword is `maxLength: 4096` and its isolated local meaning is only
`UNICODE_CODE_POINT_COUNT <= 4096 UNICODE_CODE_POINTS` for STRING instances.
Non-string instances receive no assertion from this keyword.

The proof binds the 1,527-byte runtime-attachment schema, root identifier,
direct-root pointer ancestry, complete Discovery V8 site record, and containing
subschema digest
`1cb0f2473cb55b110447de322170e5050e56184fc26d1d544cb298ff202d9ac5`.
Boundary evidence covers 4095, 4096, and 4097 code points, the empty string,
astral code points, combining sequences, and non-string instances. Hostile
substitution with the prior Git-common-directory maximum, both minimum-length
siblings, and equal-valued source helper behavior fails closed.

The proof does not establish sibling `type` or `minLength`; requiredness or
property presence; path syntax; realpath normalization; absoluteness;
existence; symlink resolution; repository containment; filesystem-byte length;
Git identity or correspondence; attachment consistency; source `_string`
behavior; full-schema or deployed-validator conformance; public validity;
independent acceptance; STOP or release clearance; execution, wagering, or
capital authority. It changes no runtime behavior.

V51 is the exact V50 45-constraint prefix plus this one proof, with zero
historical evidence rebases. It has 46 constraints and 79 classified sites:
71 source plus eight schema. Of 642 unclassified sites, 354 are source-bound
and 288 are schema-bound. Coverage remains `INCOMPLETE`, authorizing use
remains `DENY`, and the same four release-readiness blockers remain.

Final identities:

- proof: 2,332 bytes, SHA-256
  `b69ed286b02c56ba7949517fd5e304898413987c44c24162e64aeec03c61a79f`
- V51 manifest: 115,339 bytes, raw SHA-256
  `e867326b807795e83bbcef14b5dfacad268de6a88e0c80bd60f4adfb03585d19`
- V51 manifest self-digest:
  `a5e22f919f2058415df9534f6e014d67d22335c1fb4cdf75602f7f30187f12fd`
- V51 schema: 124,664 bytes, SHA-256
  `97630c1ecf3d4c7a5412b5c481b6ecaa2ebe9ad8fd773a3875b927d9429effd8`

The final fast tier passed all 73 isolated modules in 1183.508 seconds. Its
168,392-byte log is `/tmp/h174-fast-final.log` with SHA-256
`5a831b31c0117f0ec90c33fd7c15dd31f8e5314c730d2079210c63c5e520120d`.
Dedicated and current-integration suites passed 16/16 normally and optimized.
Normal and optimized readiness outputs were byte-identical, 362,402 bytes,
with SHA-256
`266964fb0ad070ef67dfc8198a15a8947d60d79c8646d50684e97d6919b361e0`;
both intentionally exited 1 and reported `BLOCKED` / `DENY`. Bounded Skeptic
review returned PASS/ACCEPT. Before governance publication, 581 governed
records and published history validated.

No public-entrypoint, STOP, release, execution, wagering, or capital authority
changed. `STOP-M0-3A-002` remains OPEN, live capital remains LOCKED with USD 0
deployable, `live_enabled` remains false, and the kill switch remains ENGAGED.
