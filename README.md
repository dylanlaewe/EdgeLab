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
.venv/bin/python tools/run_test_tier.py historical
```

That audit currently includes documented preserved red results and must not be
called green until its exact outcomes have been captured and independently
reviewed. The runner observes every historical module and returns nonzero when
any fail. `tools/run_test_tier.py all` runs all three tiers in order. Do not run
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

The same report is available as a loopback-only local viewer:

```sh
.venv/bin/python -m src.edgelab.web
```

Open `http://127.0.0.1:8765`. The viewer supports only `GET` and `HEAD`,
rebuilds the content-bound report for each API request, disables caching, and
fails closed when evidence cannot be verified. It is not an authoritative
whole-project dashboard or an operational control surface.
