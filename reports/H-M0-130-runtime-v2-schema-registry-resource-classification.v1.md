# H-M0-130 — Runtime-v2 schema-registry resource classification

Commit `87e8a13eabcfce2cf4eefc048433bda363be1a99` classifies one
additional branch-specific non-relational maximum:
`MAX_SCHEMA_REGISTRY_BYTES`. The classification is deliberately limited to
the exact built-in `bytes` schema-registry value supplied independently to
host preflight or verifier bundle inspection. It binds both scalar definitions,
the host `byte_fields:schema_registry` branch binding, and the verifier's
direct comparison. Registry canonicality, schema validity, digest and pin
equality, schema-document and aggregate limits, retained-storage semantics,
authorization, and public-verifier acceptance remain outside this claim.

Classification v7 byte-binds its v6 predecessor and retains the five v6
constraints exactly. It adds four schema-registry definition and enforcement
sites, increasing the cumulative inventory to six constraints and sixteen
classified sites. Its schema SHA-256 is
`84447dba722c97f50e60e928e3356e485aa093f06a267019e88e01948dd82cb8`,
manifest raw SHA-256 is
`773579688c9ab1363d3a9576582c1ea9ec21cf00616e05d4878f370f7fe444c5`,
and domain-separated self-digest is
`9f08a5f8f56907a661c9cc0ba31874bf63bf1e730dc2aa728408c07f76d98c0d`.

Dedicated boundary evidence proves host and verifier behavior at `M-1`, `M`,
and `M+1`. Host preflight retains admitted bytes exactly and withholds the
image with the exact byte-limit finding above the maximum. Verifier inspection
parses admitted inputs and returns the exact `SCHEMA_REGISTRY_TOO_LARGE`
finding with `INVALID / DENY` before inventory accounting or traversal above
the maximum. Type guards precede size checks, outcomes remain non-Boolean,
and attacker-refreshed tests reject same-valued definition substitution,
comparator drift, extra loads or stores, diagnostic drift, withholding drift,
return drift, evidence drift, semantic-binding drift, and DENY drift.

Two independent bounded engineering reviews returned ACCEPT after verifying
the exact four-site/two-function binding, cumulative ancestry, evidence
identities, adversarial tests, and retained denial. These reviews are not
authenticated formal STOP-clearance authority.

Validation passed 92 focused readiness, closure, image, verifier,
schema-document, schema-reference-node, event-byte, and schema-registry tests
normally and under optimized Python; 398 tests passed across the 26-module
fast tier; and 449 governed records validated before publication. The
readiness CLI still exits `1` with `BLOCKED / DENY`, writes no release
artifact, and retains all four blockers.

Only sixteen of 697 census sites are semantically classified; 681 remain
unclassified and coverage remains `INCOMPLETE`. `STOP-M0-3A-002` remains
OPEN. No closure, carrier, public-verifier connection, positive result, STOP
clearance, writer, database, selector cutover, operational authority, or
capital path was added. Capital remains LOCKED with deployable USD 0 and the
kill switch ENGAGED.
