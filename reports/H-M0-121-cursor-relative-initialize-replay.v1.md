# H-M0-121 — Cursor-relative INITIALIZE replay

Commit `57bb9860033a2efca7f5f85a80506a849e4ba072` compiles
`INITIALIZE` at every complete contract-permitted position in the private
runtime-v2 replay. The group now derives its coordinates from the retained
cursor and transition workspace rather than assuming sequence zero, a genesis
predecessor, or a single-task workspace.

Distinct absent tasks may be initialized at attempt 1 after ordinary work,
repository imports, checkpoints, or exports. The reducer binds the current
repository generation and bundle, current global head, synthetic task root,
exact derived N0 state, response projection, attempt head, idempotency row,
and five reachable blobs. Existing task IDs, stale repository coordinates,
forged heads or roots, partial groups, duplicate identities, hostile host
types, extra blobs, and forged table materializations fail closed. Unrelated
task, claim, review, decision, remediation-link, and attempt history remains
unchanged.

Independent review identified one contract-valid prefix that the initial
implementation missed: genesis followed by an empty `IMPORT_REPOSITORY`
before the first task. The import reducer's obsolete post-initialization cursor
floor was removed and explicit genesis-import-initialize tests were added.
First-task initialization after checkpoint and export prefixes is also covered.

Validation passed 75 focused initial/snapshot/post-import/initialize tests
normally and under `python -O`, all 223 runtime-v2 tests, and 352 tests across
the 21-module isolated fast tier. Writer, Skeptic, contract, and independent
diff reviews found no remaining blocker after the empty-import repair.

Exact generated closure identity/carrier, the unsupported legacy bridge, and
the remaining A-J acceptance work remain unfinished. Valid private images
remain `UNSUPPORTED/CLOSURE_NOT_COMPILED/DENY`; the public verifier is still
disconnected, STOP-M0-3A-002 remains OPEN, and capital remains LOCKED.
