# H-M0-172 — Operation-key maximum-length proof family V49

Engineering commit `7d3a706` introduces the first closed, multi-member schema
proof family without weakening the existing one-site proof contract. V49
appends two independent Draft 2020-12 `maxLength: 256` proofs, ordered by
schema path:

1. command-request `/properties/operation_key/maxLength`, site
   `9a219d2847af954061fe8e233e8e316f57a09e9ec256c83ed829724b9930f626`;
2. response-projection `/properties/operation_key/maxLength`, site
   `1d6cb316a9edd5dfe397fc767d6e23f7c22e93c1e1292f19cbeff98cfea96514`.

Each member owns a separate exact proof, rationale, and adversarial evidence
test. A closed family artifact pins the exact Discovery V8 identity, V48
predecessor, predicate, ordered member vector, excluded lookalikes, proof
paths, and self-digest. It never discovers future members dynamically.

Both proofs classify only the exact local STRING-domain assertion that Unicode
code-point count is at most 256. They do not classify sibling `type`,
`minLength`, or `pattern`; property reachability; root `required`,
`additionalProperties`, or `allOf`; operation-key grammar; request/projection
correspondence; event/transaction lookalikes; idempotency or chain meaning;
runtime `_OPERATION_KEY`; full-schema or deployed-validator conformance; or
any public, STOP, release, execution, wagering, or capital authority.

V49 is the exact V48 41-constraint prefix plus these two proofs, with zero
predecessor evidence rebases. It contains 43 constraints and 76 classified
sites: 71 source plus five schema. Of the 645 remaining unclassified sites,
354 are source-bound and 291 are schema-bound. Coverage remains `INCOMPLETE`,
authorizing use remains `DENY`, and all four release-readiness blockers remain.

Final key identities:

- command proof: 2,299 bytes, SHA-256
  `499129d8d113e8dcb6b7fecdecffcfeb3142c11903ec938b3b2f93fd1bb0ee8a`
- response proof: 2,318 bytes, SHA-256
  `6d6f4219f7605a7d8f4d5977157f03b6efbc2298ee6f7e681fc717cbd9a6ca12`
- family artifact: 5,215 bytes, raw SHA-256
  `16484b9e4f8d99dd3605b54daf481182696ec95dedebdf5f8124fd9c8386cbbc`
- family self-digest:
  `06a32d9f49c79e5bc45a139ca9ff841b19e0f269141d343728d738309fd3906a`
- V49 manifest: 107,369 bytes, raw SHA-256
  `d3730cfd44abb28ec17368e364ab0bfa5ce6b6e9c6176d4f3f148ce833e90b04`
- V49 manifest self-digest:
  `7c468e8785b07b23b50f78a9f1bbba4595890342f8d5efce5fcc4c4ca24ab62a`
- V49 schema: 115,937 bytes, SHA-256
  `eaa0d5ea38c0227474e3130e2e21f420460db19850b5ecad847f75130f15cf9a`

The final fast tier passed all 69 isolated modules in 1142.262 seconds. Its
161,670-byte log is `/tmp/h172-fast-final.log` with SHA-256
`353a722deb80a73e2b8bb90c22c30880f4ef98b84dcdd5ec91d2d870fe678498`.
Dedicated family/member tests passed 23/23 normally and optimized. Normal and
optimized checker outputs were byte-identical, 362,402 bytes, with SHA-256
`543a045609bfc0c2393b37dda4afec0a3aed95df4bcb534bbbea01fabe14dbdd`;
both exited 1 and reported `BLOCKED` / `DENY`. A bounded Skeptic review
returned `ACCEPT/PASS`. Before governance publication, 575 governed records
and published history validated.

No runtime, public-entrypoint, STOP, release, execution, wagering, or capital
authority changed. `STOP-M0-3A-002` remains OPEN, live capital remains LOCKED
with USD 0 deployable, `live_enabled` remains false, and the kill switch
remains ENGAGED.
