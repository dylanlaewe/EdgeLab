# EdgeLab

A laboratory for testing whether sports-market edges exist. A reproducible rejection is a successful result.

Current milestone: **M0 — Laboratory Foundation**, increment **M0.1**. Conceptual experimental bankroll: **USD 50.00**; deployable live capital: **USD 0.00**; live status: **LOCKED**. This is a declared budget, not a verified account balance. No providers, wagering adapters, deposits, or execution are implemented.

Start with [AGENTS.md](AGENTS.md), [constitution](PROJECT_CONSTITUTION.md), [operating guide](docs/OPERATIONS.md), and [project state](docs/project-state.json). Role contracts live in `agents/`; queued assignments live in `docs/handoffs/`.

## Local validation

Python 3.11 or newer:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m src.edgelab.validate
```

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
