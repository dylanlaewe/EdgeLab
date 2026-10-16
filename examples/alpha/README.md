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

## Local viewer

Serve the same content-bound report as a local read-only web page:

```sh
.venv/bin/python -m src.edgelab.web
```

Then open `http://127.0.0.1:8765`. The server binds only to IPv4 loopback,
serves no external assets, enables no cross-origin access, disables caching,
and exposes no mutation methods. If report construction fails, the API returns
`503 UNAVAILABLE_FAIL_CLOSED` and the page discards any displayed report.

Endpoints:

- `GET /` — static responsive viewer.
- `GET /api/v1/alpha` — freshly verified report envelope.
- `GET /healthz` — process liveness only; it does not imply project health or
  approval.

This is deliberately a Developer Alpha Viewer rather than an authoritative
project dashboard. It does not reconcile mutable project summaries, invoke the
scheduler, ingest sources, authorize paper/live activity, clear STOPs, or move
capital.
