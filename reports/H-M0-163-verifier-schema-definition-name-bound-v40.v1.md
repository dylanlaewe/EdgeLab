# H-M0-163 — Verifier schema definition-name bound V40

Engineering commit `13a3cc4` advances the deny-only runtime-v2 semantic
classification from V39 to V40 without changing Discovery V7 or runtime
source. Independent inventory and bounded Skeptic review selected the existing
root `$defs` definition-name character ceiling as the smallest complete slice.

V40 adds exactly one constraint,
`VERIFIER_SCHEMA_DEFINITION_NAME_CHARACTER_MAXIMUM`. It binds the overlapping
definition and enforcement site for `len(name) > 64` at
`7c91639838faea15e6de8b51227a0b9bc0044c0c66b6a98cc4b5b4897a0f63fd`.
The complete semantic slice pins root `$defs` extraction, non-dictionary
fallback, exact `definitions.items()` iteration, the compound name profile,
the diagnostic and `continue`, graph insertion, recursive walk, the enclosing
function, and the verifier module. Rejected names create no graph edge and
receive no definition-body walk.

The rule counts Python string characters. Valid names of lengths 1, 63, and
64 pass this ceiling; a 65-character name emits `SCHEMA_DEF_NAME` at `/$defs`.
The constraint does not claim the other name-profile terms, reference-token
validity, target existence, graph safety, body validity, parser acceptance,
public-verifier acceptance, STOP clearance, execution authority, or capital
authority.

Classification V40 contains 36 constraints and 69 unique classified sites.
Discovery remains 425 source sites plus 296 schema sites, 721 total; 652 sites
remain unclassified. Coverage remains `INCOMPLETE`, authorizing use remains
`DENY`, and the same four unconditional blockers remain.

The V40 manifest raw SHA-256 is
`84af0451a3d4c5674a0147290e717d25142807fd833baa639444ee42550b2992`;
its domain-separated self-digest is
`00458554e1598a29969ac0fe3bfe94a4dc32e999bab3542eb6cc26c7f1aedf96`;
and its schema raw SHA-256 is
`1f59c2f654ff27a4a4e967b07d47b7611207e4922fb36a72516b3a8eaf63762e`.

V40 preserves every V39 semantic field and site set. Exactly five historical
constraints receive enumerated evidence-only refreshes because their tests
assert the current classification census: top-level events, both
finding-string constraints, the closure integer-token constraint, and the
schema-reference token constraint. Their historical V39 evidence records are
byte-pinned; any sixth or broader rewrite is rejected.

The complete fast tier passed 693 tests across 58 isolated modules in 1008.354
seconds. Its embedded release-readiness module passed 75 tests in 942.004
seconds. Dedicated tests passed normally and under optimized Python. Normal
and optimized checker outputs were byte-identical with current-tree SHA-256
`bad0c6368c94ddbd0fb7a0f400c461969f7e0064650008b685eb36100ffb77d6`;
both exited 1, retained the same four blockers, and wrote no release artifacts.
Before governance publication, 548 governed records and published history
validated.

Independent bounded Skeptic review returned `PASS` with no actionable
findings after reproducing the dedicated normal/optimized tests, V40
schema/instance validation, checker parity, exact-five evidence-only rebase,
and absence of runtime or authority expansion. This is engineering review, not
trusted formal acceptance. `STOP-M0-3A-002` remains OPEN, live capital remains
LOCKED with USD 0 deployable, `live_enabled` remains false, and the kill switch
remains ENGAGED.
