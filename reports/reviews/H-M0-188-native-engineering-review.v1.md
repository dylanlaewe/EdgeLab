# H-M0-188 read-only engineering review

## Boundary

This owner-authorized AI engineering review is internal and non-authorizing.
It is not formal 05 Skeptic approval, governance acceptance, STOP clearance,
an authenticated receipt, or operational release. The reviewer made no edits.

## Initial verdict: CHANGES_REQUIRED

At implementation commit `f8baaefe7301e667a7874268aff4927a9409d80f`,
the reviewer reproduced 7/7 tests and a cold unchanged comparison, then
demonstrated a semantic closure defect. After recomputing both the context
self-digest and caller-presented expected raw digest, the artifact still
accepted substitutions of:

- historical capture path and sidecar/seal/authority-binding digests;
- top-level capture ID; and
- repository root, dependency IDs, and capability IDs.

The reviewer also found that malformed files matching an ID's version glob
were silently ignored and requested transitive dependency/capability closure
instead of direct-only collection.

## Correction

Commit `53ba0e25f8efcea8fa29340aab97b22d20511a2f` retains the full accepted
authority-binding candidate and runs its semantic verifier, cross-binds capture,
task, attempt, historical seal, current locked authority, and exact summary
fields, and compares all derived source facts to fresh observation. Version
selection rejects every malformed glob candidate. Dependency collection first
uses the existing validators, then recursively retains dependency heads,
completion bindings, and transitive capabilities with cycle checks.

## Final verdict: PASS

The reviewer reproduced:

- focused suite: 9/9 passed in 18.365 seconds;
- cold CLI demo: `UNCHANGED_CONTEXT_UNKNOWN_DENY` and
  `UNKNOWN / FAIL / false / DENY`;
- recomputed-pin historical-summary and capture substitutions:
  `EVIDENCE_REJECTED_DENY / ARTIFACT_INTEGRITY_INVALID`;
- repository-root substitution: `DRIFT_DETECTED_DENY` on `git_repository`;
- dependency/capability substitutions: `DRIFT_DETECTED_DENY` on
  `dependency_capability`;
- malformed version candidates fail closed;
- production validation: 625 records; and
- `git diff --check f8baaef..53ba0e2` passed.

No remaining implementation defect was demonstrated. This PASS is limited to
the bounded non-authorizing engineering behavior.
