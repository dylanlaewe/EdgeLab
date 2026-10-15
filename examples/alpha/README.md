# EdgeLab developer alpha

This read-only alpha makes the intended EdgeLab workflow visible using retained
synthetic fixtures and previously published review evidence. It does not run an
agent, contact a source, execute a strategy, paper trade, or move capital.

From the repository root:

```sh
.venv/bin/python -m src.edgelab.alpha
```

Machine-readable and Markdown views are also available:

```sh
.venv/bin/python -m src.edgelab.alpha --format json
.venv/bin/python -m src.edgelab.alpha --format markdown --output /tmp/edgelab-alpha.md
```

`--output` only creates a new file outside the repository. It refuses existing
paths, repository paths, and aliases into the repository.

The report shows:

- the historical frozen `MOCK_ONLY` preflight capture and the current fail-closed
  preflight result;
- Data provenance and explicit unknown source access;
- a synthetic Research hypothesis, preregistration, and holdout contract;
- bounded Quant validation evidence and its missing statistical claims;
- the independent focused Skeptic verdict and trust limitations;
- current Risk controls, all OPEN STOPs, locked live status, engaged kill switch,
  and zero deployable live capital;
- SHA-256 provenance for every top-level artifact used in the display.

The expected aggregate result is `NO_DEMONSTRATED_EDGE / BLOCKED`. A missing,
altered, aliased, unlisted, or contradictory bound artifact causes the command
to fail closed with exit status 2.
