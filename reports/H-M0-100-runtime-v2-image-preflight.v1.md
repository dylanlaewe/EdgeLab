# H-M0-100 — Runtime-v2 image host preflight

## Outcome

Commit `bae50048356167de2243c956ba66617ecf683524` implements the exact private
runtime-format-2 host transport and a pure resource/table preflight. It also
pins the remaining two bootstrap schema files and accepts only the exact
supported schema-registry and storage-descriptor canonical domain identities.

This is a bounded engineering milestone, not whole-image verification. The
public verifier remains disconnected and can still return only `INVALID` or
`UNSUPPORTED` under `UNANCHORED / UNKNOWN / DENY`.

## Closed boundary

- `RuntimeImage`, `SchemaDocumentRecord`, `BlobRecord`, and `TableSnapshot`
  are exact frozen/slotted transports with no input defaults.
- Host preflight rejects subclasses, mutable container aliases, missing slots,
  wrong nested types, booleans as integers, non-signed-64 values, invalid
  Unicode, missing/duplicate keys, non-BINARY row order, and every published
  cardinality or individual-byte limit it owns.
- It accounts every declared input occurrence, saturates at 1 GiB plus one,
  independently charges all 15 final supplied table roots, and bounds findings.
  Cached/capped string scans prevent shared values from amplifying validation
  work; table ordering avoids allocating attacker-sized UTF-8 key copies.
- A successful host preflight returns a detached sanitized image and `DENY`.
  Boolean coercion raises. It does not parse canonical documents, reduce
  events, establish consistency/currentness, or grant authority.
- The remaining bootstrap validators are explicitly singleton identity
  languages: already-parsed canonical values must reproduce the exact
  domain-separated published registry or descriptor digest. They are not
  advertised as general JSON Schema evaluators.

## Adversarial review

Initial independent review found that exact dataclass instances constructed
with missing slots raised `AttributeError`, and that a source object could be
mutated after inspection. It also challenged repeated unbounded scans of
shared strings. The implementation was repaired to capture every required
slot explicitly, return deterministic findings, reconstruct an alias-free
snapshot, cache and cap size scans, saturate accounting, reject giant integers
before decimal conversion, and avoid large encoded order keys.

Two independent final adversarial rereviews and a separate bootstrap-identity
review returned `ACCEPT BOUNDED MILESTONE`. One rereview exercised more than
2,000 malformed substitutions and every deleted slot without an exception.
The ordinary same-process Python assumption remains explicit: the future
reducer must invoke preflight inline and consume the sanitized result, never
trust a caller-constructed preflight report as evidence or authority.

## Executed evidence

- Focused bootstrap/image suite: 29 tests passed.
- Final fast tier: 241 tests passed across 14 isolated modules.
- Production validator before evidence publication: 359 records and published
  history validated; capital remained locked and no approval was granted.
- Production validator after evidence publication: 362 records and published
  history validated with the same locked, non-authorizing result.
- Five raw bootstrap schema pins and both supported domain pins reproduced.
- Compiled columns, nullability, primary keys, row order, and table inventory
  matched the exact supported storage descriptor.
- Targeted compilation and `git diff --check` passed.

## Residual boundary

`STOP-M0-3A-002.v3` remains OPEN. System genesis/legacy bridge, complete event
grouping, typed reachability, checkpoint/export reconstruction, all-table
semantic derivation, the generated dependency closure/carrier, and the full
A-J matrix are still required. The legacy bridge remains archive-only: missing
published per-column v1 storage profiles, backup/plan bytes, and frozen v1
closure bytes must not be invented or presented as independently reverified.

`STOP-M0-001` and `STOP-M0-3A-001` also remain OPEN; H-M0-041 remains BLOCKED;
H-M0-086 still lacks a genuinely distinct trusted Skeptic; live remains
LOCKED; kill remains ENGAGED; deployable capital remains USD 0; and no edge
has been demonstrated.
