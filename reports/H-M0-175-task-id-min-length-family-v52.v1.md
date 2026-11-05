# H-M0-175 — Task-ID minimum-length proof family V52

Engineering commit `1cd9b40` appends a closed four-member family for the exact
Draft 2020-12 `/$defs/taskId/minLength` sites in command request, event
envelope, event payload, and task state. In schema-path order their stable site
identities are `05539c8d…fb0b`, `54cb7f4b…21a5`, `237e413d…12da`, and
`cf92955f…127b`.

Every member has a separate proof, rationale, test, raw-schema/root binding,
site record, and file identity. Their shared local container is exactly
`{type:string,minLength:1,maxLength:128,pattern:^[A-Za-z0-9][A-Za-z0-9._:-]*$}`
with digest
`508f4e9c702082b8fcc8420d76e459159cb9103585311b30b2e0dc6f51416644`.
The family classifies only the isolated STRING-domain assertion
`UNICODE_CODE_POINT_COUNT >= 1`; non-string values receive no assertion from
that keyword.

The family closes an exact ordered allowlist and fully binds the only
same-container lookalike, nested response-projection site `17390c9d…8b4e`, as
excluded and unclassified. It freezes the complete V51 prior-proof set so a
future successor cannot change historical ownership through a live aggregate.
Contraction, expansion, reorder, proof swap, excluded-site injection,
recomputed-digest exclusion mutation, sibling substitution, evidence aliasing,
and transitive predecessor-history attacks all fail closed.

No proof establishes sibling `type`, `maxLength`, or `pattern`; task-ID grammar,
identity, uniqueness, or validity; `$ref` reachability or use; cross-role or
cross-document equivalence or independence; nested response-projection meaning;
requiredness; full-schema, deployed-validator, or public validity; runtime task
behavior; independent acceptance; STOP or release clearance; execution,
wagering, or capital authority.

V52 is the exact V51 46-constraint prefix plus four proofs with zero rebases.
It has 50 constraints and 83 classified sites: 71 source plus twelve schema.
Of 638 unclassified sites, 354 are source-bound and 284 are schema-bound.
Coverage remains `INCOMPLETE`, authorizing use remains `DENY`, and the same
four release-readiness blockers remain.

Final identities:

- command-request proof: 2,064 bytes, SHA-256 `a0a7964577fca3c9b52243c00a04984a52bff70b3cedd39b4e309c935ef38b41`
- event-envelope proof: 2,038 bytes, SHA-256 `cb9dd48199fbae9269065a3649cf64e653522fb2ece3467c71079158bcde35a9`
- event-payload proof: 2,034 bytes, SHA-256 `77a891aba0afcc7eb06b99cba35f84f5ffe61a1ed6b7ea75b87f760ede1c3822`
- task-state proof: 2,018 bytes, SHA-256 `3090b65ad00d66a7a3307ffbd6d91163a483a39fefa102a29417c1bd9651910d`
- family: 6,331 bytes, raw SHA-256 `db7b06537fcf1d45da28d8eeca05461fc89449ca5bd3711923a2ccd447f44225`, self-digest `05af01779300eff526f72e7b1c20b52a997708ff1a29331ef103c93b3cdfb74c`
- V52 manifest: 125,637 bytes, raw SHA-256 `ed369c50451deaaa083825dc9efebb4875175b8c5e451c62f9fa9d9f00d4e698`, self-digest `56c45c3534caa5ac6502c010fed98a560aefb4b06688265ef38f78f5fc9d380d`
- V52 schema: 135,959 bytes, SHA-256 `3a001eced92a293cc98a9a11a09c8f4e477390b8b1b46343b5ce388a08769a0a`

The final fast tier passed 78/78 modules in 1270.372 seconds. The 173,977-byte
log `/tmp/h175-fast.log` has SHA-256
`c9ed75d4929d9f5492306eb6ed7d929c14f58e828015aba6f3d01b78cede0945`.
Checker outputs were byte-identical under normal and optimized Python, 362,403
bytes, SHA-256
`b04256f34326a20e7b8f36cb60bbdcd78874c6b1449c12546c3645e223b95efc`,
and intentionally exited 1 with `BLOCKED` / `DENY`. Two bounded independent
engineering audits returned PASS/ACCEPT. Before governance publication, 584
governed records and published history validated.

No runtime, public-entrypoint, STOP, release, execution, wagering, or capital
authority changed. `STOP-M0-3A-002` remains OPEN, live capital remains LOCKED
with USD 0 deployable, and the kill switch remains ENGAGED.
