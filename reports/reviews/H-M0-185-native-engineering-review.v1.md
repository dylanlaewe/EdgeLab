# H-M0-185 read-only engineering review

Reviewer mode: read-only AI engineering subagent; no filesystem, commit, or
push mutations.

## Findings

### BLOCKER — frozen runtime format 1 would be silently changed

The proposed prototype retained `SCHEMA_VERSION = 1` while adding two tables
and two new task-event semantics. Current authority defines runtime format
versions by tables, replay closure, and persistence; preserves format 1 as
evidence; fixes its closed archive inventory; and leaves existing v1 wire
semantics unchanged pending a versioned storage migration. The format-2
content/event vocabulary is also closed.

Disposition: do not commit the implementation. Require the exact successor
format decision recorded in
`reports/H-M0-185-native-scientific-dependency-authority-blocker.v1.md`.

### HIGH — prototype repository import could create replay-invalid state

The prototype allowed repository import to advance a claimable dependent Data
task but did not update or reject the immutable dependency row's consumer
repository generation. Replay required equality, so the normal writer path
could commit state that the next startup/export/transition denied.

Disposition: removed with the uncommitted prototype. Any authorized successor
must specify and test dependency behavior under repository generation changes.

## Reproduction

- `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest -v tests.test_scheduler_scientific_dependency` — 10/10 passed on the prototype.
- `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest -q tests.test_scheduler_scientific_dependency tests.test_scheduler_coordinated_research tests.test_synthetic_research_experiment tests.test_synthetic_lifecycle tests.test_transactional_scheduler` — 90/90 passed on the prototype.
- `git diff --check` — passed.

An earlier broad invocation named two nonexistent modules; 90 real tests passed
but that invocation ended with two import errors. It is not cited as an
authoritative pass.

## Review conclusion

The requested semantics were not eligible to land under the current frozen
format authority. Passing behavior tests did not cure the authority mismatch.
The correct outcome is `BLOCKED`, with H-M0-184 production code unchanged.
