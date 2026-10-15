# H-M0-084 handoff self-cycle correction — v1

## Root cause

Production validation at the actual 2026-10-15 clock failed with
`Dependency cycle: H-M0-080.v4`.

`H-M0-080.v3` and `H-M0-080.v4` each used the bare dependency
`H-M0-080` as shorthand for continuing the preceding revision of the same
assignment. Under the approved dependency rules, however, a bare handoff ID
resolves to its authoritative current head. Once v4 was the current head, its
bare reference therefore resolved back to v4. This was a historical-revision
continuation represented as a current dependency, not an actual current
self-prerequisite.

The historical chain establishes `H-M0-079.v3` as the real external
prerequisite: that completed review returned the requires-revision verdict
which caused the H-M0-080 remediation. Its exact SHA-256 is
`8c0cf6d242fda7474e5eb990be1bc6dd6d79250d7f7fad9d25ecb3af581d57bd`.

## Correction

`docs/handoffs/H-M0-080.v5.json` is an additive, metadata-only successor. It
preserves the completed historical-verifier result, its evidence, limitations,
test claims, and non-authorization boundary. It replaces only the invalid
same-ID dependency representation with an exact-revision reference to
`H-M0-079.v3`.

This is valid under the existing exact-revision mechanism. No resolver code or
cycle rule changed, no historical handoff was edited, and no legitimate
prerequisite was removed. The SHA-256 values for H-M0-080.v1 through v4 remain:

- v1: `c66089ca81233443fbaf7346b4c17c5b409657fa2ee6280cdeb464796b0bbab4`
- v2: `b48410f98863b466cd88ae787c26ea42ac323340d3dda7cfb843e02f8e7a51e9`
- v3: `1ab93b31e8638451fdc477047623fd17ecea2b05c5c1f4c427c26631f94bbbe7`
- v4: `d194bc3e06b2e0dfec8c25a3b3ba5bec6fe2e6b09e4674c0d386a81e15b6da3b`

The focused regression models the same distinction: a superseded historical
same-ID shorthand is not a current graph root, while a bare same-ID dependency
on the authoritative current version still raises a cycle.

## Validation

Initial writer results on implementation commit
`70c9da7ced264ee1ab2c62c0c8c348a3ddca7d66`:

- focused dependency-resolution and genuine-cycle regressions: 4/4 passed in
  0.138 seconds;
- accepted H-M0-081 data-integrity suite: 29/29 passed in 7.508 seconds;
- exact H-M0-080 six-module historical-verifier suite: 47/47 passed in 33.591
  seconds;
- production validator at the actual clock: exit 0, validating 323 records and
  published history while keeping M0 capital locked;
- `compileall` and `git diff --check`: passed.

Final completion-tree validation, including this report, the review record,
audit event, and completion handoff, produced:

- focused dependency-resolution and genuine-cycle regressions: 4/4 passed in
  0.129 seconds;
- accepted H-M0-081 data-integrity suite: 29/29 passed in 9.103 seconds;
- exact H-M0-080 six-module historical-verifier suite: 47/47 passed in 33.911
  seconds;
- production validator at the actual clock: exit 0, validating 325 records and
  published history while keeping M0 capital locked;
- `compileall` and `git diff --check`: passed.

The separate read-only reviewer independently reproduced the pre-correction
v4 cycle, checked the exact prerequisite hash and unchanged historical bytes,
and passed 10/10 focused dependency tests, 29/29 data-integrity tests, the
47/47 verifier suite, production validation, compilation, and diff checks. The
review verdict was `ACCEPTED_FOR_BOUNDED_METADATA_CORRECTION` with no findings.

## Boundary and remaining blockers

This correction grants no formal Skeptic/project approval and implements no
currentness, R-gate, source access, paper/live, execution, or capital feature.
Data remains BLOCKED; STOP-M0-001 and STOP-M0-3A-001 remain OPEN; M0 remains
blocked; M1 remains unreleased; the executor remains `MOCK_ONLY`; live remains
`LOCKED`; the kill switch remains `ENGAGED`; the conceptual bankroll remains
USD 50.00 with USD 0.00 deployable.
