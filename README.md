# EdgeLab

A laboratory for testing whether sports-market edges exist. A reproducible rejection is a successful result.

Current milestone: **M0 — Laboratory Foundation**, active increment **M0.3A — Transactional Scheduler / Event Store**. Bounded local scheduler and viewer engineering exist, but M0.3A is **not formally accepted**; both `STOP-M0-001` and `STOP-M0-3A-001` remain **OPEN**. Conceptual experimental bankroll: **USD 50.00**; deployable live capital: **USD 0.00**; live status: **LOCKED**; kill switch: **ENGAGED**. This is a declared budget, not a verified account balance. No providers, wagering adapters, deposits, external executor, or live/paper execution are implemented.

Start with [AGENTS.md](AGENTS.md), [constitution](PROJECT_CONSTITUTION.md), [operating guide](docs/OPERATIONS.md), and [project state](docs/project-state.json). Role contracts live in `agents/`; queued assignments live in `docs/handoffs/`.

## Local validation

Python 3.11 or newer:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python tools/run_test_tier.py fast
.venv/bin/python tools/run_test_tier.py domain
.venv/bin/python -m src.edgelab.validate
```

The fast and domain tiers are green gates. Run them serially: the runner holds a
repository-specific cooperative lock and executes each module in an isolated
process. The retained historical/adversarial corpus is a separate audit:

```sh
set -o pipefail
.venv/bin/python tools/run_test_tier.py historical 2>&1 | tee /tmp/edgelab-historical.log
.venv/bin/python tools/verify_historical_outcomes.py /tmp/edgelab-historical.log
```

That audit includes documented preserved red results and is intentionally not a
green gate. The runner observes every historical module and returns nonzero
when any fail. The verifier checks the complete ordered outcome against the
reviewed non-green baseline, including every failure/error identity and
diagnostic plus runner/test source hashes. A verifier success means only that
the known audit pattern did not drift; it is not a test pass or approval.
`--exact-capture` additionally verifies the one reviewed raw-log hash.
`tools/run_test_tier.py all` runs all three tiers in order. Do not run
overlapping test processes against the retained fixture corpus.

The validator checks record shape and M0 capital invariants. It does **not** authenticate reviewers, enforce append-only storage, validate scientific evidence, or implement promotion/execution. Those limitations are explicit M0 blockers, not approvals.

## Layout

- `schemas/`: strict JSON Schema record contracts; `docs/SPECIFICATIONS.md` defines cross-record semantics.
- `data/`: source registry and future immutable raw, normalized, derived data.
- `research/`: registered hypotheses, experiments, rejected evidence, paper and validated artifacts.
- `strategies/`: versioned strategy records; no strategies registered yet.
- `portfolio/`: conceptual bankroll and conservative risk policy.
- `reports/audit/`, `reports/stops/`: durable event and integrity records.
- `docs/`: lifecycle, operations, milestone tracking and handoffs.
- `src/`, `tests/`: local validation and regression checks.

No demonstrated edge exists. No strategy has earned paper or live eligibility.

## Developer alpha

A read-only, content-bound walkthrough of the intended workflow is available
using retained synthetic and `MOCK_ONLY` evidence:

```sh
.venv/bin/python -m src.edgelab.alpha
```

It shows the Director, Data, Research, Quant, Skeptic, and Risk contributions,
including provenance, uncertainty, current OPEN STOPs, and locked capital. The
sample is a developer demonstration only and ends `NO_DEMONSTRATED_EDGE /
BLOCKED`; see [examples/alpha/README.md](examples/alpha/README.md).

The loopback-only laboratory observatory exposes both governed repository
status and the retained alpha walkthrough:

```sh
.venv/bin/python -m src.edgelab.web
```

Open `http://127.0.0.1:8765`. The observatory supports only `GET` and `HEAD`,
rebuilds its source snapshot for every request, disables caching, and fails
closed when governed state or retained evidence cannot be verified.
`/api/v1/status` reports the current M0 project, OPEN STOPs, locked bankroll,
kill switch, remaining work, and explicit `UNKNOWN / DENY` evidence boundary;
`/api/v1/alpha` preserves the synthetic `MOCK_ONLY` walkthrough. This remains
a local read-only visibility surface, not positive currentness, an approval
workflow, scheduler interface, or execution control.
