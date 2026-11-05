# H-M0-167 — Schema declarative proof contract V44

Engineering commit `74340bd` adds an executable, closed proof contract for
future declarative JSON Schema resource constraints without classifying any
schema site. Discovery remains V8. Classification V44 is a zero-new-constraint
successor that preserves V43 exactly.

The `SCHEMA_DECLARATIVE_KEYWORD_V1` proof profile binds an exact addressed V8
schema record, raw schema document, root identifier and Draft 2020-12 dialect,
mechanically derived containing-subschema pointer and domain-separated digest,
ordered root-to-parent context, local applicability, structured equation,
unit, evidence bytes, and fixed nonclaims. Source and schema constraints use
disjoint proof paths; schema proofs cannot contain source-AST or runtime
enforcement fields.

The executable validator derives the closed local-declarative mapping for all
twelve supported bound keywords: minimum/maximum, exclusive minimum/maximum,
minimum/maximum string length, array items, object properties, and contains
matches. It requires nonnegative count/length bounds, exact adjacent `contains`
siblings for contains counts, strict terminal keyword agreement, per-location
constraint IDs, and at least two distinct non-schema evidence artifacts.

The supported reference subset is deliberately narrow. Only raw local RFC 6901
fragment references are admitted. Dynamic, recursive, percent-encoded,
external, unresolved, nested-identity, and nested-dialect reference contexts
deny. Explicit pointer scanners preserve valid `~0`/`~1` behavior without the
prohibited generic `.replace` API. This is local keyword semantics, not proof
that an ancestor branch applies, that a runtime validator executes, or that a
public entrypoint enforces the schema.

Classification V44 contains the exact 38 V43 constraints with zero evidence
rebases. It classifies 71 source sites, zero schema sites, and leaves 650 of 721
sites unclassified. Coverage remains `INCOMPLETE`, authorizing use remains
`DENY`, and the same four unconditional blockers remain.

Artifact identities:

- V44 manifest raw SHA-256:
  `592ba55df15012f90dac5ad883c75bde3647d0c56916ffc74b45241b8c6d9e81`
- V44 manifest self-digest:
  `2277c5da20cf89fc048c4aeb43c29b05e88e9355ed066d7cd76d4d9f565fbd81`
- V44 schema raw SHA-256:
  `fbb495f28cb07a2d50fccc5baa3bf26430ccc48f58bc3eedddf817032eb071c1`
- Proof profile raw SHA-256:
  `de4f676df1d89ecbfcf3de10ae8015a9c1508e053d7bdc9cf7a62ee2a685f921`
- Proof profile self-digest:
  `bb0a64e1b331bbe4df6ba78411b44fc3af9da3cf542b41371f5a5556ee2b2369`
- Proof schema raw SHA-256:
  `f7afccfeee300b294b4e498dd6cf243e4c8167c24def540846d8170b5047eefa`

Independent reviews found and closed three mandatory issue classes: structured
ancestor/context inconsistencies and insufficient per-site distinctions;
unsupported dynamic/recursive/percent-encoded reference semantics; and a
fast-tier security regression caused by `.replace`. Final bounded Skeptic
review returned `PASS` after normal and optimized adversarial reproduction.

The complete fast tier passed 727 tests across 62 isolated modules in
1060.239 seconds. Its release-readiness module passed 78 tests. Normal and
optimized checker outputs were byte-identical with current-tree SHA-256
`bcc910ce7836eeea1e39584a7dc9e426e2775e250a2eea7a4653957102ad7a76`;
both exited 1, retained the same four blockers, and wrote no release artifacts.
Before governance publication, 560 governed records and published history
validated.

The contract does not establish runtime validation, public-entrypoint
reachability, root-document applicability, complete schema correctness,
deployed-validator conformance, independent acceptance, STOP clearance,
release authority, execution authority, wagering authority, or capital
authority. `STOP-M0-3A-002` remains OPEN, live capital remains LOCKED with USD
0 deployable, `live_enabled` remains false, and the kill switch remains
ENGAGED.
