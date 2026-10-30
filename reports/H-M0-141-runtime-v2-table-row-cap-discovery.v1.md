# H-M0-141 — Runtime-v2 positional table row-cap discovery

Commit `d2aeb14` extends the deny-only runtime-v2 resource census without
changing runtime behavior. Discovery v4 preserves all 407 Discovery v3 source
sites and adds fifteen exact positional bindings behind the shared table-row
cap comparator, one for each `_TABLE_SPECS` entry.

Each new record binds the exact `_TableSpec` helper predecessor, aggregate
assignment and positional index, `_TableSpec.max_rows` field meaning, the
Discovery v3 exact-15 `table_snapshots` cardinality predecessor, the outer
cardinality gate, strict positional `enumerate(zip(..., strict=True))` loop,
snapshot type guard, table and rows slot reads, individual and combined
missing-field gates, supplied-label mismatch behavior, exact rows-tuple guard,
`len(rows) > spec.max_rows`, exact diagnostic/accounting/continue branch, and
complete host-preflight function and source-module identities.

The bindings explicitly record
`POSITIONAL_STRICT_ZIP_NOT_SUPPLIED_TABLE_LABEL`. A supplied snapshot label
does not select its cap. At position one, a snapshot labelled `events` still
uses the positional `blobs` cap; at position three, a snapshot labelled
`blobs` still uses the positional `events` cap. Runtime evidence reproduces
this distinction, all distinct cap classes 0, 1, 9, 100,000, and 300,000 at
their inclusive boundary and plus one, and missing/non-tuple rows failing
before any unsafe length inspection.

Discovery v4 byte-binds its v3 manifest and schema. It reports 422 source
sites and 296 schema sites, for 718 discovered sites. Fifteen bindings are new
in this extension and twenty-eight are cumulative across v2, v3, and v4. The
source-census digest is
`5918304896b54b757e26d94367227c9f36db56e367964133d793c3539f47ab2f`.
The v4 schema raw SHA-256 is
`558baf8aa2e1da502e4c19a733bfe0a73d42bcd1d0c1d5e1ad3b948fd12d9bd4`;
the manifest raw SHA-256 is
`9d4c0630a802ef849e3ccb2cd6993cc58b8b2c8fa694888bff8ef96a52384681`;
and its domain-separated self-digest is
`2f34479e4597041b122a61c4aea29ae051446285ec51518d965bfd0e8b8e09d6`.

Classification v18 is a census-only rebase. It byte-binds v17 and preserves
all fifteen constraints and all forty-two classified sites exactly. Its schema
raw SHA-256 is
`7901e551042b9dd95832c811de44d2ff9bad11c6464ee9b104c158a8f900b739`;
its manifest raw SHA-256 is
`77a61978d92b1087321ab51281617516faace8a083db12245d8ae1b37e240333`;
and its self-digest is
`b7ef974f4bf1ae67a60f671fdf607c79be3b0727663f3adafd5bc4e09094947d`.

Adversarial tests reject helper deletion, duplication, reordering and
same-valued expression substitution; class-field, aggregate, outer-gate,
loop-target, iterator-source and strictness drift; snapshot/slot/missing/type/
identity gate changes; supplied-label early continuation; comparator,
diagnostic, accounting and row-cap continuation changes; inter-loop rebindings;
built-in/helper shadowing; attacker-refreshed census identities; and v18
predecessor or constraint-history drift. Independent bounded inventory and
Skeptic reviews reproduced and accepted this engineering evidence. These are
not authenticated STOP-clearance, formal independent project acceptance, or
release authority.

Validation passed all 44 readiness tests and all three dedicated row-cap tests
both normally and under optimized Python. Normal and optimized checker outputs
were byte-identical and both exited 1 with `BLOCKED / DENY`. The complete fast
tier passed 495 tests across 36 isolated modules. Before governance
publication, 482 governed records and published history validated.

All fifteen new records remain `UNCLASSIFIED`. Only forty-two of 718 census
sites are semantically classified; 676 remain unclassified. Coverage remains
`INCOMPLETE`, generation remains `DENY`, all four readiness blockers remain,
and `STOP-M0-3A-002` remains OPEN. No closure, carrier, positive public-
verifier result, writer, database, selector cutover, execution authority,
STOP clearance, or capital path was added. Capital remains LOCKED with USD 0
deployable and the kill switch ENGAGED.
