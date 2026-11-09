# H-M0-183 — Synthetic research experiment integration

## Outcome

H-M0-183 implements one deterministic, fictional, local-only scientific
experiment through Research, synthetic Data, Quant, a synthetic adversarial
stage, Risk, Director, and the existing H-M0-179 scheduler lifecycle. The
scientific result is `INSUFFICIENT_DATA`. Every authority projection is `DENY`.
The experiment is not a strategy, real pick, paper-trading decision, formal
Skeptic approval, governance acceptance, or operational release.

Runnable human-readable command:

```sh
runtime_dir=$(mktemp -d /tmp/edgelab-hm0183.XXXXXX)
rmdir "$runtime_dir"
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python tools/run_synthetic_research_experiment.py --runtime-dir "$runtime_dir" --format text
```

Use `--format json` for the closed machine-readable result.

## Retained scientific chain

- Research registered `H-SYNTHETIC-001.v1` at `2026-01-01T00:00:00Z`; the
  protocol froze one day later and evaluation occurred after all outcomes were
  available. The hypothesis fixes one signal threshold, minimum price, unit
  stake, cost model, 20-event minimum, metrics, uncertainty rule, and rejection
  conditions before evaluation.
- Data is exactly twelve fictional timestamped observations from
  `SYNTHETIC-EXAMPLE-BALL-001`. The input package SHA-256 is
  `48b5fe80a19a402ba676285d67d90fda8d3a98ecdd2089c14844fa13841768fb`.
  No external data or real sports observation is present.
- Quant selected all twelve preregistered observations. The fictional record is
  7-5; average offered decimal odds `2.054167`; average two-way overround
  `0.028880`; fixed cost `0.020000` per selection; net PnL `2.180000` units;
  net ROI `0.181667`; maximum drawdown `2.040000`; cost-adjusted break-even win
  rate `0.496552`; and 95% Wilson interval `0.319511` to `0.806740`.
- The synthetic Skeptic stage confirmed three limitations: sample size is below
  the preregistered 20-event minimum, uncertainty contains break-even, and
  positive synthetic ROI is not evidence of a real edge. Its deliberately
  future-leaking signal control was rejected before Quant and never admitted to
  the primary analysis.
- Risk recorded fictional-data, sample-size, uncertainty, and absent-formal-
  review limitations and retained capital, paper, promotion, and execution
  `DENY`. Director recorded `INSUFFICIENT_DATA` and
  `NO_REAL_EDGE_OR_OPERATIONAL_READINESS_DEMONSTRATED`.
- Only after scientific evaluation succeeds fail-closed does the existing
  H-M0-179 local scheduler run. The result retains a deterministic projection of
  its exact seven events, replay result, final states, unsupported public
  verifier, and DENY boundaries. Random local scheduler identifiers are not
  represented as reproducible scientific evidence. The scheduler's review is
  task-recording-only and is not formal scientific approval.

## Reproducibility and fail-closed behavior

The evaluator uses closed input/result schemas, exact hypothesis identity,
canonical SHA-256 evidence identities, fixed `Decimal` arithmetic, a fixed
Wilson constant, and no random calculation. Independent direct and CLI runs
were byte-identical to the retained result. The result SHA-256 is
`eba4b15dd06159209947d6f9ecec7fc3ea61a4a2f7d94fa28a68515ac51da304`.

Focused tests reject missing fields, future-leaking primary input, duplicate
events, outcomes unavailable at evaluation, an accepted negative control,
invalid registration order, a missing result schema, and a substituted
one-event DENY lifecycle. The production path also rejects any retained input
byte change through the pinned package digest.

Validation performed:

- H-M0-183 focused suite: 13/13 passed in 7.468 seconds.
- H-M0-179 lifecycle suite: 5/5 passed during the compatibility run.
- Research-history successor suite: 27/27 passed during the compatibility run.
- Quant protocol suite: 24/24 passed during the compatibility run.
- Risk controls suite: 18/18 passed during the compatibility run.
- The older 20-test `ResearchProtocolTests` class reproduced its known fail-
  closed requirement for verifier-supplied authoritative baseline and inventory
  during setup; no production contract was weakened to make those legacy calls
  pass.
- Production repository validation passed 610 governed records before
  completion records, retaining M0 capital `LOCKED` and granting no scientific
  or operational approval.
- `compileall` and `git diff --check` passed.

## Engineering review and limitations

The first read-only engineering review found that result-schema validation was
optional and the scheduler projection accepted an incomplete DENY lifecycle.
Both defects were fixed. Re-review reproduced 13/13 tests, both attacks now
fail with `MISSING_SCHEMA` and `SCHEDULER_CONTRACT_MISMATCH`, and a fresh JSON
CLI result matched retained evidence byte-for-byte. The verdict is engineering
PASS, not formal 05 Skeptic approval.

The input package is a purpose-built isolated synthetic evidence contract, not
accepted operational Data authority. The local scheduler receipt remains
untrusted and DENY-only; the stable projection demonstrates integration but
does not establish an authenticated experiment-to-runtime authorization
receipt. No external validity, statistical edge, formal review, currentness,
R-gate, public runtime-v2 release, paper eligibility, or capital authority is
established.

Data remains `BLOCKED`; all STOPs remain `OPEN`; M0 remains blocked; M1 remains
unreleased; authorization remains `DENY`; executor remains `MOCK_ONLY`; live
remains `LOCKED`; kill remains `ENGAGED`; deployable capital remains `$0.00`.
