# H-M0-116 — Review decisions and routing replay

Commit `e42a6b00fca85449a0352c03c2789c2204f94e90` compiles private
`APPROVE`, `REJECT`, `REMEDIATE`, and `ROUTE` replay. Decisions atomically
transition the task, close the active review, and retain one private
per-attempt decision index. Routing is N7-only and reaches
`DIRECTOR_GATE_READY`; it is not operational approval.

96 focused tests passed normally and under `python -O`; 322 fast-tier tests
passed. A delegated read-only review found no blocker. After publication,
the validator accepted 410 governed records and 18 alpha/observatory tests
passed with capital LOCKED.

The decision index is private and non-materialized. Remediation/import,
checkpoint/export, root-work, closure generation, and A-J acceptance remain
unfinished. Valid images remain `UNSUPPORTED/CLOSURE_NOT_COMPILED/DENY` and
STOP-M0-3A-002 remains OPEN.
