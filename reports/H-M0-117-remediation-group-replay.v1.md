# H-M0-117 — Remediation group replay

Commit `275b4d0019794ea7e4d2ff9a98551d46fbe9b938` compiles the private
`CREATE_REMEDIATION_TASK` group as two ordered task semantics followed by one
commit envelope. It reconstructs the source update, child creation, reciprocal
link, both task heads, and exact link digest from a retained `REJECT` or
`REMEDIATE` decision for the same task and attempt.

The implementation initially failed to validate an untrusted source task ID
before dictionary lookup. Adversarial review reproduced the uncaught host-type
failure; the defect was fixed, list/object attacks were added, and the reviewer
found no remaining blocker. Validation passed 66 focused tests normally and
under `python -O`, 133 combined runtime-v2 tests, and 325 tests across the
isolated fast tier.

This is a bounded terminal replay slice. Post-remediation task selection,
repository import, checkpoint/export cuts, cumulative root work, closure
generation, and A-J acceptance remain unfinished. Valid images remain
`UNSUPPORTED/CLOSURE_NOT_COMPILED/DENY`; STOP-M0-3A-002 remains OPEN and
capital remains LOCKED.
