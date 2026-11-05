# H-M0-173 — Operation-key minimum-length proof family V50

Engineering commit `2725cd7` appends a second closed two-member schema-proof
family while preserving the complete V49 classification history byte-for-byte.
V50 adds the exact Draft 2020-12 `minLength: 1` sites, ordered by schema path:

1. command-request `/properties/operation_key/minLength`, site
   `b2840fbfba98b7107e46eee42f8d818a2e8d60582f9fbd4e394993a686bda437`;
2. response-projection `/properties/operation_key/minLength`, site
   `5dce821ee45f15010f24959f58819323b0112024635aeb4ede5380e3e47c69d4`.

Each site retains an independent exact proof, rationale, and adversarial test.
The closed family artifact pins the V8 discovery identity, V49 predecessor,
predicate, ordered member vector, fourteen full excluded-candidate records,
proof paths, distinct evidence ownership, and family self-digest. It performs
no dynamic member discovery.

Both proofs classify only the local STRING-domain assertion that Unicode
code-point count is at least one. They do not classify sibling `type`,
`maxLength`, or `pattern`; root `required`, `additionalProperties`, `allOf`,
`if`, or `then`; reachability; operation-key grammar; cross-document
correspondence; event, transaction, or payload meaning; uniqueness,
idempotency, chain, or task behavior; runtime `_OPERATION_KEY`; full-schema or
deployed-validator conformance; or any public, acceptance, STOP, release,
execution, wagering, or capital authority.

V50 is the exact V49 43-constraint prefix plus these two proofs, with zero
historical evidence rebases. It contains 45 constraints and 78 classified
sites: 71 source plus seven schema. Of the 643 remaining unclassified sites,
354 are source-bound and 289 are schema-bound. Coverage remains `INCOMPLETE`,
authorizing use remains `DENY`, and all four release-readiness blockers remain.

Final key identities:

- command proof: 2,295 bytes, SHA-256
  `48b71b7f3e20f4e74272174cab84be8c74c75270c93e45722c8dc9fbd39fc27b`
- response proof: 2,314 bytes, SHA-256
  `dbb0971ca2e3ab613d5674bc4f1d6bf6e9863423655965c5fe9e903382694516`
- family artifact: 10,407 bytes, raw SHA-256
  `c5c09a5c5cb653e90b311d1f777513923dbfa8bfc9700b7b6ca21e7ca2462c46`
- family self-digest:
  `f18cc1f2951e23423fc98b21add126ae7c50bcd38fd8cc9bee2f7a983d7e3dda`
- V50 manifest: 112,664 bytes, raw SHA-256
  `4b257aa866d875fd410b5eab2c60c2184c8ba3ee2322388ff9abc692b1f4bcf1`
- V50 manifest self-digest:
  `df226aad14778f50300a29246c60ca83ecbe42d26eb99dca82e4a9006b89f160`
- V50 schema: 121,733 bytes, SHA-256
  `f33ab3757d1aaf3a0c54276b690f9d6fd8fdb7e5925c71c723f28724703bf670`

The final fast tier passed all 72 isolated modules in 1180.687 seconds. Its
166,368-byte log is `/tmp/h173-fast-final.log` with SHA-256
`80e0ec8bb0100d7a9e86659d4b1b1eeff718665791ec0a2ff1df236119f14ab8`.
Independent focused tests passed 24/24 normally and optimized. Normal and
optimized readiness outputs were byte-identical, 362,402 bytes, with SHA-256
`bad95f37204926ae4eaad6c729ec2152d43301dc4940152d5f68b1fe3b5b4818`;
both intentionally exited 1 and reported `BLOCKED` / `DENY`. Two independent
bounded engineering reviews returned PASS/ACCEPT. Before governance
publication, 578 governed records and published history validated.

No runtime, public-entrypoint, STOP, release, execution, wagering, or capital
authority changed. `STOP-M0-3A-002` remains OPEN, live capital remains LOCKED
with USD 0 deployable, `live_enabled` remains false, and the kill switch
remains ENGAGED.
