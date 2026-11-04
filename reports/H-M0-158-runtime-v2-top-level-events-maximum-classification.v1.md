# H-M0-158 — Runtime-v2 top-level events maximum classification

Engineering commit `0461a57` advances the deny-only runtime-v2 resource
classification from V34 to V35. It preserves the exact thirty-constraint V34
prefix and appends one constraint,
`HOST_PREFLIGHT_TOP_LEVEL_EVENTS_MAXIMUM`, for Discovery V5 composite site
`0788e261996efdb32e9fdca233db8d5e809fdb533da89d835357ab1f2c9f1fa4`.

The classified subject is only the exact built-in tuple item count of
`captured['events']` at `inspect_runtime_image_host` preflight. Its unit is
`ITEMS`, its inclusive maximum is 100,000, and its accepted equation is
`0 <= len(captured['events']) <= 100000`. Definition and enforcement are the
same composite and therefore count once by set union. Exact tuple guarding
precedes the comparison. An at-limit malformed member is inspected and makes
accounting incomplete; a 100,001-item tuple produces the cardinality finding,
skips member inspection, leaves accounting incomplete, and withholds the
sanitized image.

The raw `MAX_EVENTS` definition, Discovery V3 branch, initial reducer,
transition definition and comparisons remain globally unclassified. The
positional events-table composite and event-byte meanings were already
classified by independent prior constraints; they remain outside this V35
constraint and are not reclassified. Public-verifier acceptance, STOP state,
execution, authorization, and capital authority are also outside the
constraint.

Classification V35 contains 31 constraints and 58 unique classified sites.
The Discovery V5 census remains 423 source sites plus 296 schema sites, 719 in
total, so 661 sites remain unclassified. Coverage remains `INCOMPLETE`,
generation remains `DENY`, and the unconditional resource-inventory blocker
is retained. The V35 manifest raw SHA-256 is
`d3f897173eae7b7deb3ec1aced0f6f722fbf567493791717bae68b6dd8e8dafd`;
its domain-separated self-digest is
`be9ef46386ea1c170cfe4fbc004ec6495ce8784c464a8a1a12e995cbcfef95cf`;
and its schema raw SHA-256 is
`169a22f38512f75b3f62a62f63ae841692dd499c15731c009d6c0d1bcc8d507b`.

Adversarial evidence covers zero, 99,999, 100,000, and 100,001 items; exact
tuple versus tuple subclass behavior; at-limit malformed-member inspection;
plus-one member skipping and image withholding; raw-definition and V3-branch
separation; equal-valued table and transition meanings; source-level
semantic drift; and attacker-refreshed V5 shape, missing-site, and duplicate
composite mutations. An inherited V5 mutation test was repaired after the
new classification correctly moved those failures from discovery-binding
errors to exact classification shape or missing-site errors.

Independent inventory selected this single composite as the smallest
complete slice. Independent Skeptic review returned `ACCEPT` for the bounded
classification only, confirming the exact V34 prefix, one-site set-union
accounting, 31/58/661/719 census arithmetic, explicit exclusions, and absence
of runtime or authority expansion.

The final complete fast tier passed 654 tests across 53 isolated modules.
Normal and optimized readiness outputs were byte-identical with SHA-256
`344da2f90393134467da49f6d14bcdf34fd2b057472b902ea376e305f89a1e32`;
both exited 1, retained `ACCEPTANCE_MATRIX_INCOMPLETE`,
`PUBLIC_ENTRYPOINT_DISCONNECTED`, `RESOURCE_INVENTORY_INCOMPLETE`, and
`V1_BRIDGE_UNSUPPORTED`, and wrote no release artifacts. Before this
governance publication, 533 governed records and published history validated.

This is deny-only M0 evidence, not formal project or release acceptance.
`STOP-M0-3A-002` remains OPEN, live capital remains LOCKED with USD 0
deployable, `live_enabled` remains false, and the kill switch remains ENGAGED.
