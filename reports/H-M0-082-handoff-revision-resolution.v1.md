# H-M0-082 handoff revision resolution — v1

## Authorized correction

This bounded governance/schema correction adds handoff schema version 2 without
changing schema version 1 or any published historical record. A v2
`depends_on` entry is either a legacy bare handoff ID or the existing exact
typed-reference shape `{path, kind, id, version, sha256}` with kind `handoff`.
The validator selects the declared schema version for each handoff.

Dependency nodes retain `(handoff ID, record version)` identity. Every current
handoff head remains a graph root. Bare IDs resolve to the target's current
head; exact references resolve only after repository path, kind, ID, version,
filename, schema and byte SHA-256 validation. Traversal follows every dependency
of each reached revision, including historical revisions reached by exact
references. Missing, mismatched, ambiguous, duplicate/conflicting and cyclic
targets fail closed. `evidence_refs` are not dependency declarations.

## Exact review-prerequisite binding

`H-M0-075.v4` is a metadata-only successor authored by `/root` acting as
00 Director under the user's explicit authority. It preserves the independent
H-M0-075.v3 verdict `M0_2_M0_3_ADAPTER_PLAN_REQUIRES_REVISION`, original review
evidence, open issues, blockers and completion criteria. It does not claim a new
Skeptic review or approval.

Its sole dependency is exactly:

```text
path    docs/handoffs/H-M0-074.v1.json
kind    handoff
id      H-M0-074
version 1
sha256  01812864de27568ada00d66b20d0dfb6dd763b607924a0b77ef70eacf7dec782
```

The SHA-256 was independently reproduced from current working-tree bytes and
from the same path at reported source commit
`670b1df2e7b8f59a739dc4c15bf21c6c2868b966`.

## Preservation and validation

`schemas/handoff.schema.json`, H-M0-074.v1–v3, H-M0-075.v1–v3,
H-M0-080.v4 and H-M0-081.v2 have no working-tree changes. Existing historical
records still undergo per-record schema, clock, evidence-reference,
filename/identity, version-continuity and typed-reference validation before the
resolved dependency graph is checked.

Final candidate evidence before publication:

- `tests.test_data_integrity`: 28 tests passed, including bare-head behavior,
  exact H-M0-074.v1 pinning, invalid hash/ID/path/version denial, conflicting
  representations, and current/exact/mixed cycle rejection.
- H-M0-080's exact six-module focused suite: 47 tests passed.
- `compileall`, `git diff --check`, JSON/schema and H-M0-075.v4 evidence
  validation passed.
- Production validation at actual `2026-10-15T16:51:56Z`, without a clock
  override, advanced beyond H-M0-075 and exited 1 only on the unchanged,
  explicitly excluded `Dependency cycle: H-M0-080.v4`.

The remaining H-M0-080 self-cycle is reported, not waived or repaired. Data
remains BLOCKED; STOP-M0-001 and STOP-M0-3A-001 remain OPEN; M0 remains blocked;
M1 remains unreleased; capital remains LOCKED. This work grants no scientific,
project, capability, execution or capital approval.
