# H-M0-140 — Runtime-v2 top-level blob cardinality classification

Commit `7712b35` extends the cumulative deny-only runtime-v2 semantic resource
classification without changing runtime behavior. Classification v17
byte-binds v16, preserves all fourteen predecessor constraints and all forty
predecessor-classified sites exactly, and appends one narrow classification
for `MAX_BLOBS` as the supplied top-level `RuntimeImage.blobs` tuple ceiling.

The new constraint classifies exactly two Discovery v3 sites: the sole
300,000-item scalar definition and the branch-specific `blobs` cardinality
binding. The binding closes the captured tuple subject, table row and
assignment, matching tuple-fields row, both loops, subject lookup, chained
comparison, validity result, rejection diagnostic and accounting branch,
member-loop gate, sanitized-image withholding, complete host-preflight
function, and source module.

The equal-valued 300,000-row `_TableSpec` ceiling is a different subject and
remains unclassified, along with its enclosing table-spec aggregate and the
shared table-row comparator. The shared cardinality comparator also remains
unclassified. The pre-existing `MAX_BLOB_BYTES` body ceiling stays separate.
This milestone does not classify record validity, accounting/root-work limits,
blob roles, digests, canonicality, uniqueness, fixed-point reachability,
table equality, sibling cardinalities, or public-verifier acceptance.

The governing boundary contract is
`M0.3A_RUNTIME_BLOB_CARDINALITY_LIMIT.v1.md`. Dedicated evidence proves zero,
maximum-minus-one, the inclusive maximum, and maximum-plus-one; exact built-in
tuple guards; tuple-subclass rejection; valid-count member validation;
collection-before-member ordering; input preservation and order; fixed `DENY`
and non-Boolean reports; sibling independence; and executable separation from
the equal-valued blobs table-row cap.

At exactly 300,000 records an oversized final body produces only the exact
per-member byte finding and its bytes are included in accounted input. At
300,001 records the same oversized member is not inspected, only the top-level
cardinality finding is reported, and accounted totals are withheld. Separately,
an empty top-level blobs tuple with 300,001 supplied blobs-table rows produces
only the table-row-limit finding.

Attacker-refreshed census tests reject same-valued and off-by-one scalar
definitions, alternate or literal row maxima, subject substitution, extra
loads or stores, comparison and diagnostic bypasses, accounting-failure
removal, blob-member-gate bypass, sanitized-image-withholding bypass, and
module-level `len` or `type` shadowing. Independent bounded inventory and
Skeptic reviews reproduced and accepted the final engineering evidence. These
reviews are not authenticated STOP clearance, formal independent project
acceptance, public-verifier acceptance, or release authority.

The v17 schema is 41,177 bytes with raw SHA-256
`12fe501633f5d6417449a9edd34a47952cb7d0ffa58fe80459ee690f30885504`.
The manifest is 37,309 bytes with raw SHA-256
`595049a2059cd7bf335a55546727500e97e7660f9b54e164db2388fe1e3a8c5b`
and domain-separated self-digest
`3a7d8c3f595aa516e96422ccce73b3884bdeb6f58ce41e525f291ffe9976cb55`.
The dedicated evidence file is 11,439 bytes with raw SHA-256
`284ef2be27905cd18c81b5f2cbf6dad870b14d5a4fa508abef9b5ba322fbb93a`.

Validation passed all 42 readiness tests and all 11 dedicated boundary tests
both normally and under optimized Python. Normal and optimized checker outputs
were byte-identical and both exited 1 with `BLOCKED / DENY`. The complete fast
tier passed 490 tests across 35 isolated modules. Before governance
publication, 479 governed records and published history validated.

Classification v17 contains fifteen constraints and forty-two classified
sites. Of 703 census sites, 661 remain unclassified. Coverage remains
`INCOMPLETE`, generation remains `DENY`, all four readiness blockers remain,
and `STOP-M0-3A-002` remains OPEN. No closure, carrier, positive public-
verifier result, writer, database, selector cutover, execution authority,
STOP clearance, or capital path was added. Capital remains LOCKED with USD 0
deployable and the kill switch ENGAGED.
