# H-M0-088 — Deterministic isolated test tiering

## Outcome

EdgeLab now has one explicit, serial test entry point for all 54 test modules.
The 7-module fast tier and 4-module current-domain tier are green gates. The
43-module historical/adversarial tier is an audit corpus and deliberately
remains non-green until one complete isolated run is reviewed and converted
into an exact expected-outcome fingerprint.

Commit `d48f35050298665e50a1879b6935b3bd0ba9268a` implements and documents the
boundary. It also reconciles `docs/project-state.json` from stale M0.1 wording
to the actual blocked M0.3A engineering state. Both OPEN STOPs, the engaged kill
switch, locked live status, and zero deployable capital are preserved.

## Controls

- `tools/run_test_tier.py` explicitly assigns every `test_*.py` module. A new
  unclassified module fails closed.
- Every module runs in a separate Python process with deterministic hash seed,
  UTC timezone, and bytecode writes disabled.
- A repository-keyed cooperative lock denies overlapping tier-runner
  processes.
- Fast and domain modules fail immediately on a nonzero result.
- Historical modules all run even after a failure, then receive an aggregate
  nonzero result and complete failure summary.
- Dotted imports are not used; per-file unittest discovery preserves the
  legacy suites' top-level sibling imports.

## Mutable-state test repair

Project-state reconciliation correctly invalidated two tests that had treated
mutable current files as frozen September fixtures. The tests were repaired,
not the controls:

- M0.2 orchestration positive replay now uses the retained authentic Stage 1
  project-state bytes whose SHA-256 already matches the frozen scheduler
  binding.
- September Risk tests now build an isolated retained M0 fixture rather than
  omitting the later M0.3A STOP from today's authoritative repository.
- The data-integrity project-state schema test derives its validation instant
  from the record under test, while all synthetic temporal-boundary cases keep
  their frozen clock.

Production validation continues to require today's complete STOP inventory.

## Executed evidence

- `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python tools/run_test_tier.py fast`:
  58 tests passed across 7 isolated modules in 10.012 seconds.
- `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python tools/run_test_tier.py domain`:
  98 tests passed across 4 isolated modules in 479.496 seconds.
- `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m src.edgelab.validate`:
  333 records and published history validated; M0 capital remained LOCKED and
  no scientific or operational approval was granted.
- `git diff --check`: passed before commit.
- A targeted isolated `test_research_protocol.py` observation retained its
  documented 20 setup errors. It is not represented as a pass and is not a
  substitute for the pending complete historical audit.

## Remaining work and authority

The next bounded step is one complete isolated historical run, followed by
review of every module outcome and a checked fingerprint that distinguishes
preserved expected red results from regressions. No fingerprint may be inferred
from the partial observation above.

This milestone is test infrastructure and status reconciliation only. It does
not accept M0.3A, clear a STOP, provide independent Skeptic authority, attach an
executor, release M1, authorize paper/live activity, or unlock capital.
