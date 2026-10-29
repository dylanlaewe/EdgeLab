# H-M0-131 — Runtime-v2 bootstrap-document resource classification

Commit `cb3278fcf3ad9d2437b86d12477967f83c36e674` classifies the
complete `MAX_BOOTSTRAP_DOCUMENT_BYTES` family. The classification is limited
to exact built-in `bytes` values in `verifier_dependency_closure`, `manifest`,
and `attachment`, plus exact built-in `bytes` members reached after tuple and
cardinality validation in `checkpoint_copies` and `selector_history`. It binds
the sole definition and all five branch-specific uses atomically. Both shared
generic comparators, collection cardinality, aggregate accounting, document
validity, retained storage, authorization, and public-verifier acceptance
remain outside this claim.

Classification v8 byte-binds its v7 predecessor and retains all six v7
constraints exactly. It adds six unique bootstrap-document sites, increasing
the cumulative inventory to seven constraints and twenty-two classified
sites. Its schema SHA-256 is
`decde7f7f5927a4809d21077848bfcb31dde68daf4df2e51c8cfcfb5e34a97cb`,
manifest raw SHA-256 is
`32aa72a70f77e9d0a43969b8471e3374ebd3adfd108283a65a1d9f263f2de1b7`,
and domain-separated self-digest is
`a2b112dfec65b15cda67ea6d14a1199305a3614cfe2174966894afb32ca261e7`.

Dedicated evidence proves `M-1`, `M`, and `M+1` behavior independently for
all five branches. Admitted values retain exact supplied byte identity;
overflow produces the exact `IMAGE_ITEM_BYTE_LIMIT` artifact and coordinate
and withholds the image. The evidence also covers nonzero collection indices,
field/tuple/member type ordering, invalid-cardinality traversal suppression,
per-subject sibling independence, non-Boolean outcomes, and retained `DENY`.
Readiness attacks refresh ordinary discovery identities before challenging
the hard pins and reject same-valued substitutions, row/table/loop/comparator
drift, extra loads or stores, diagnostic drift, withholding drift, ancestry
drift, and authority mutation.

Two independent bounded engineering reviews returned ACCEPT after verifying
the exact six-site/five-branch binding, cumulative ancestry, evidence
identities, adversarial tests, and retained denial. These reviews are not
authenticated formal STOP-clearance authority.

Validation passed 100 focused readiness, closure, image, verifier, schema-
document, schema-reference-node, event-byte, schema-registry, and bootstrap-
document tests normally and under optimized Python; 406 tests passed across
the 27-module fast tier; and 452 governed records validated before publication.
The readiness CLI still exits `1` with `BLOCKED / DENY`, writes no release
artifact, and retains all four blockers.

Only twenty-two of 697 census sites are semantically classified; 675 remain
unclassified and coverage remains `INCOMPLETE`. `STOP-M0-3A-002` remains
OPEN. No closure, carrier, public-verifier connection, positive result, STOP
clearance, writer, database, selector cutover, operational authority, or
capital path was added. Capital remains LOCKED with deployable USD 0 and the
kill switch ENGAGED.
