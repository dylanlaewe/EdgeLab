# H-M0-170 — Generator-version minimum schema proof V47

Engineering commit `7ed3ac2` appends one exact location-scoped JSON Schema
meaning to the deny-only runtime-v2 resource classification. The selected V8
census site is
`schemas/m0-3a-verifier-dependency-closure.v1.schema.json` at
`/properties/generator_identity/properties/generator_version/minimum`, site
`55fed7617dc5fedbe4f113493ae8096cf62078a2a6dc7803fd4417fb6d60e44b`,
with `minimum: 1`.

The proof classifies only the local Draft 2020-12 NUMBER-domain assertion
`JSON_NUMBER_VALUE >= 1`. It does not classify the sibling `type: integer`,
property requiredness or reachability, root or `allOf` applicability,
operational generator validity, runtime `_integer` behavior, full-schema or
deployed-validator conformance, or any public, STOP, release, execution,
wagering, or capital authority.

V47 is the exact V46 39-constraint prefix plus this one proof, with zero
predecessor evidence rebases. It contains 40 constraints, 71 classified source
sites, two classified schema sites, 73 classified sites total, and 648
unclassified sites. Coverage remains `INCOMPLETE`, authorizing use remains
`DENY`, and all four release-readiness blockers remain.

Final artifact identities:

- proof JSON: 2,675 bytes, SHA-256
  `af0ef9f2cde60c7a73092132394a7d45412b9a21b8eec3256b93f40f62afaf10`
- evidence document: 2,081 bytes, SHA-256
  `da802f3205e32aa07bf8125df22248746f01dc2dbd76968a0ff25f9c1a84b4db`
- adversarial evidence test: 12,197 bytes, SHA-256
  `6b8865fb6b9c705f15d219b033d096931d4351f47a0da89ee9ccfb6ff08ced8f`
- V47 manifest: 99,394 bytes, raw SHA-256
  `3f5a60191425f8cf9328a6f2feccbdc9daa5b2afc4c2c5bdc25dbe4c3494f167`
- V47 manifest self-digest:
  `64446bc215f74dcac201c8034e6d35a12a3ccb1f35a4507156eac84eb2df20e0`
- V47 schema: 107,198 bytes, SHA-256
  `5641296c63b6e8ee6e3ef75d682983776f79eb6e949955edcb0b966b621658e9`

An independent persistent fast-tier run passed 752 tests across 65 modules in
1095.701 seconds. Its 1,278-line log is `/tmp/h170-final-audit.log` with
SHA-256
`224bb965a9f6f90d1b75970f7b19c950f0e44d674636a6a5948ff6af33dd6b5d`.
The focused proof/current/readiness suite passed 17 tests. Normal and optimized
checker outputs were byte-identical with SHA-256
`feb1bb2ce4da122a25d68f5239d93f067c7ce7a4623aa3393bfab09200dfcfc1`;
both exited 1 and reported `BLOCKED` / `DENY`. Independent inventory and
bounded Skeptic reviews returned `PASS`. Before governance publication, 569
governed records and published history validated.

No runtime, public-entrypoint, STOP, release, execution, wagering, or capital
authority changed. `STOP-M0-3A-002` remains OPEN, live capital remains LOCKED
with USD 0 deployable, `live_enabled` remains false, and the kill switch
remains ENGAGED.
