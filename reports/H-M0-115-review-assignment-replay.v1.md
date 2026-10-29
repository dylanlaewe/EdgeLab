# H-M0-115 — Review assignment replay

## Outcome

Commit `0a8bb02d093ecd3d6ccdffad0d2560d5d23a8c72` compiles private
runtime-v2 `ASSIGN_REVIEW` replay. From N3 it derives N4, advances scheduler
generation only, and atomically creates the OPEN review row while binding one
assignment UUID across payload, response generated reference, task state, and
review history.

The request actor label must differ from the immutable owner label and its role
label must differ from the owner-role label. This is exact-string separation,
not identity authentication or independent Skeptic acceptance.

## Assurance

Positive whole-image replay and owner/role self-assignment attacks pass through
the shared planner, transition workspace, cumulative cursor, and derived review
projection. A delegated read-only reviewer found no blocking defect and reran
92 focused tests normally and under optimized Python. The 318-test fast tier,
compile checks, whitespace checks, and 404-record pre-publication validator
passed. This is engineering evidence only.

After publication, 407 governed records validated and the 18-test
alpha/observatory regression passed with capital still LOCKED.

## Residual boundary

Review decisions and director routing remain uncompiled. Valid candidates stay
opaque `UNSUPPORTED/CLOSURE_NOT_COMPILED/DENY`; reviewer labels are not
authenticated; STOP-M0-3A-002 remains OPEN; execution and capital authority are
unchanged.
