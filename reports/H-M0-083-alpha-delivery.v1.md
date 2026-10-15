# H-M0-083 runnable developer alpha — v1

## Delivered artifact

EdgeLab now has a runnable, read-only developer alpha:

```sh
.venv/bin/python -m src.edgelab.alpha
```

JSON and Markdown renderers are available through `--format`. `--output` may
create a new file outside the repository; it refuses repository targets,
symlink aliases into the repository, and existing files.

The alpha reads the closed, SHA-256-bound manifest at
`examples/alpha/sample-workflow.v1.json`. It validates retained Data and
Research fixture closures with the existing validators, displays retained
Quant and independent Skeptic evidence, reconciles reviewed Risk evidence with
current bankroll and risk policy, inventories every STOP version, selects each
STOP's validated numeric head, and runs the current repository-resolved
preflight without executing anything.

## Observable sample result

The sample visibly traces these contributions:

- Director: a historical frozen `DISPATCH` through `MOCK_ONLY`, contrasted with
  the current `DENY` result;
- Data: content and timestamp provenance with source access explicitly
  `UNKNOWN`;
- Research: a synthetic frozen hypothesis, exploratory disclosure, and
  unexamined holdout contract;
- Quant: bounded timestamp/evidence-integrity checks, with no sports performance
  metrics;
- Skeptic: a focused historical review verdict plus explicit trust limitations;
- Risk: USD 50.00 conceptual, USD 0.00 deployable, live `LOCKED`, kill switch
  `ENGAGED`, and `DENY_NEW_EXPOSURE`.

The aggregate result is exactly `NO_DEMONSTRATED_EDGE / BLOCKED`. It claims no
scientific, source-access, paper, live, execution, or capital authorization.
Data remains BLOCKED. STOP-M0-001 and STOP-M0-3A-001 remain OPEN. M0 remains
blocked and M1 remains unreleased.

## Validation

Final writer evidence on implementation commit
`2372a7c213844e653da4c5c29783094fa5210e63`:

- `tests.test_alpha`, `tests.test_orchestration`, and
  `tests.test_data_integrity`: 41 tests passed in 10.821 seconds;
- the exact H-M0-080 six-module preservation suite: 47 tests passed in 32.863
  seconds;
- text, JSON, and Markdown CLI runs succeeded; JSON parsed successfully;
- outside-repository exclusive output creation succeeded;
- `compileall` and `git diff --check` passed;
- production validation exited 1 at only the separately tracked
  `Dependency cycle: H-M0-080.v4` blocker.

The legacy `test_research_protocol.py` suite is not an alpha acceptance suite.
Its discover run executed 20 methods and all produced the previously documented
missing authoritative-history-baseline setup error. An earlier named-module
invocation also produced its known top-level import-layout error. Neither was
hidden or represented as green; the alpha directly validates the retained
preregistration closure without invoking confirmation eligibility.

## Independent native engineering review

The read-only reviewer found two defects in round one:

1. `--output` could overwrite a repository artifact.
2. OPEN STOP reporting considered historical versions instead of numeric heads.

The sole writer repaired both. Output now rejects repository and alias targets
and exclusively creates a new outside file. STOP processing now rejects
duplicate identities, malformed filename/identity pairs and version gaps,
selects the highest numeric version per ID, and reports only OPEN heads.

Round two independently reproduced direct/alias output denials, exclusive
creation, resolved-successor behavior, duplicate and version-gap rejection,
8/8 alpha tests, compilation and diff checks. The reviewer accepted the bounded
engineering scope with no remaining findings. This is not formal Skeptic or
project approval.

## Known limitations and next milestone

- The historical `MOCK_ONLY` dispatch is evidence, not current authority or an
  authenticated receipt.
- There is no real sport, market, source, odds, result, ROI, uncertainty
  estimate, robustness result, paper portfolio, or live integration.
- `docs/project-state.json` remains stale and was intentionally not changed
  inside this bounded alpha scope.
- Production validation remains blocked by H-M0-080.v4's exact self-cycle.
- STOP-M0-3A-001 continues to block R-gated M0.3A transitions because a trusted
  exact M0.2 receipt/currentness interface is not available.

The recommended next original-roadmap milestone is formal review of the
H-M0-080 historical verifier, followed by authoritative locked currentness and
composed R-gate/receipt integration. Data release remains a later, separately
authorized decision.
