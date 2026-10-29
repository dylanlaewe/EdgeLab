# H-M0-129 — Runtime-v2 event-byte resource classification

Commit `6f773f7260c4d8b855a19f4e61df71ee8f77a9a4` classifies one
additional branch-specific non-relational maximum: `MAX_EVENT_BYTES`. The
classification is deliberately limited to exact built-in `bytes` members of
the captured runtime-image `events` tuple after tuple and cardinality
validation. It binds the exact module definition and the branch-specific
`byte_collections:events` row. The shared table comparator, sibling rows,
cardinality, aggregate accounting, parsing, validity, reducer correctness,
and public-verifier acceptance remain outside this claim.

Classification v6 byte-binds its v5 predecessor and retains the four v5
constraints exactly. It adds the event-byte definition and branch-binding
sites, increasing the cumulative inventory to five constraints and twelve
classified sites. Its schema SHA-256 is
`82b3be852d277568e9fd17b61ba17e7248f90316d40f9b096bb1ebb1aed35064`,
manifest raw SHA-256 is
`e5a16822a452129ef450fe8b0d582666b51d9d6ad718a01e956c172b6533921a`,
and domain-separated self-digest is
`1864d1df8a39ccaf20eba1cec2249576e04101ec2f6694b4dfda43aa82ddb443`.

The dedicated boundary evidence proves exact one-member `M-1`, `M`, and
`M+1` behavior at coordinate `/0`: accepted values retain the supplied byte
object without truncation, while `M+1` produces exactly
`IMAGE_ITEM_BYTE_LIMIT / events / /0`, withholds the image, remains
non-Boolean, and retains `DENY`. Additional tests preserve nonzero-index,
multi-member, type-order, and cardinality-order coverage. Readiness attacks
also refresh the ordinary discovery bindings before testing the independent
classification pins, and reject same-valued substitution, definition/site
drift, extra loads or stores, diagnostic drift, withholding drift, and DENY
drift.

Two independent final reviews initially rejected incomplete durable test
evidence. After the exact `/0` matrix and attacker-refreshed semantic-pin
attacks were added and the evidence identities were rebound, both reviewers
returned ACCEPT. These are bounded engineering reviews, not authenticated
formal STOP-clearance authority.

Validation passed 85 focused readiness, closure, image, verifier,
schema-document, schema-reference-node, and event-byte tests normally and
under optimized Python; 391 tests passed across the 25-module fast tier; and
446 governed records validated before publication. The readiness CLI still
exits `1` with `BLOCKED / DENY`, writes no release artifact, and retains all
four blockers.

Only twelve of 697 census sites are semantically classified; 685 remain
unclassified and coverage remains `INCOMPLETE`. `STOP-M0-3A-002` remains
OPEN. No closure, carrier, public-verifier connection, positive result, STOP
clearance, writer, database, selector cutover, operational authority, or
capital path was added. Capital remains LOCKED with deployable USD 0 and the
kill switch ENGAGED.
