"""Loopback-only, read-only web viewer for the EdgeLab developer alpha.

This module exposes the existing content-bound alpha report. It is not an
operational dashboard, scheduler, approval surface, or execution API.
"""
from __future__ import annotations

import argparse
import json
import secrets
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Iterable
from urllib.parse import urlsplit

from . import alpha


LOOPBACK_HOST = "127.0.0.1"
DEFAULT_PORT = 8765
SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
}

PAGE = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>EdgeLab Developer Alpha</title>
  <style nonce="__EDGELAB_NONCE__">
    :root {
      color-scheme: dark;
      --ink: #f2f1e9;
      --muted: #a7aba5;
      --line: #2b302f;
      --panel: rgba(19, 23, 22, .86);
      --acid: #c5ff4a;
      --amber: #ffbd59;
      --red: #ff6b62;
      --cyan: #65d9e8;
      --shadow: 0 22px 70px rgba(0, 0, 0, .36);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      background:
        radial-gradient(circle at 88% 8%, rgba(101, 217, 232, .11), transparent 28rem),
        radial-gradient(circle at 5% 30%, rgba(197, 255, 74, .08), transparent 24rem),
        #0a0d0c;
      color: var(--ink);
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    }
    body::before {
      content: "";
      position: fixed;
      inset: 0;
      pointer-events: none;
      opacity: .16;
      background-image: linear-gradient(rgba(255,255,255,.05) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,.04) 1px, transparent 1px);
      background-size: 38px 38px;
      mask-image: linear-gradient(to bottom, black, transparent 75%);
    }
    main { width: min(1180px, calc(100% - 32px)); margin: 0 auto; padding: 32px 0 72px; position: relative; }
    header { display: flex; align-items: flex-start; justify-content: space-between; gap: 24px; padding-bottom: 28px; border-bottom: 1px solid var(--line); }
    .eyebrow { color: var(--acid); letter-spacing: .13em; font-size: .72rem; text-transform: uppercase; margin-bottom: 10px; }
    h1 { margin: 0; font-family: Inter, ui-sans-serif, system-ui, sans-serif; font-size: clamp(2.3rem, 7vw, 5.8rem); font-weight: 740; letter-spacing: -.075em; line-height: .9; }
    .subtitle { max-width: 620px; margin: 18px 0 0; color: var(--muted); line-height: 1.65; font-family: Inter, ui-sans-serif, system-ui, sans-serif; }
    .scope { border: 1px solid var(--acid); color: var(--acid); padding: 9px 12px; font-size: .72rem; white-space: nowrap; box-shadow: 4px 4px 0 rgba(197,255,74,.12); }
    .status-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1px; background: var(--line); margin: 28px 0; border: 1px solid var(--line); box-shadow: var(--shadow); }
    .metric { min-height: 130px; padding: 18px; background: #0f1312; }
    .label { color: var(--muted); font-size: .67rem; letter-spacing: .09em; text-transform: uppercase; }
    .value { margin-top: 20px; font-size: clamp(1.1rem, 2.4vw, 1.7rem); overflow-wrap: anywhere; }
    .blocked, .open { color: var(--red); }
    .locked { color: var(--amber); }
    .safe { color: var(--acid); }
    .section { margin-top: 42px; }
    .section-head { display: flex; align-items: baseline; justify-content: space-between; gap: 20px; margin-bottom: 15px; }
    h2 { margin: 0; font: 650 1.35rem Inter, ui-sans-serif, system-ui, sans-serif; letter-spacing: -.025em; }
    .count { color: var(--muted); font-size: .72rem; }
    .cards { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }
    .card { padding: 20px; border: 1px solid var(--line); background: var(--panel); box-shadow: 0 12px 40px rgba(0,0,0,.18); }
    .card-top { display: flex; align-items: flex-start; justify-content: space-between; gap: 18px; }
    .role { color: var(--cyan); font-size: .78rem; }
    .tag { max-width: 62%; text-align: right; color: var(--amber); font-size: .65rem; line-height: 1.45; }
    .card p { font: .91rem/1.6 Inter, ui-sans-serif, system-ui, sans-serif; color: #d5d7d0; margin: 15px 0 0; }
    .uncertainty { border-top: 1px solid var(--line); padding-top: 13px; color: var(--muted) !important; font-size: .79rem !important; }
    .stop { border-left: 3px solid var(--red); }
    .stop h3 { margin: 8px 0 12px; font-size: 1.05rem; }
    .affected { color: var(--muted); font-size: .76rem; margin-top: 14px; line-height: 1.55; }
    .limitations { margin: 0; padding: 0; list-style: none; border-top: 1px solid var(--line); }
    .limitations li { display: grid; grid-template-columns: 2rem 1fr; gap: 8px; padding: 13px 0; border-bottom: 1px solid var(--line); color: #ced0ca; font: .88rem/1.55 Inter, ui-sans-serif, system-ui, sans-serif; }
    .limitations li::before { content: "//"; color: var(--amber); font-family: ui-monospace, monospace; }
    details { border-bottom: 1px solid var(--line); }
    summary { cursor: pointer; padding: 14px 0; color: #dfe1da; overflow-wrap: anywhere; }
    .hash { padding: 0 0 14px; color: var(--muted); overflow-wrap: anywhere; font-size: .72rem; }
    .unavailable { margin-top: 28px; padding: 26px; border: 1px solid var(--red); background: rgba(255, 107, 98, .07); }
    .unavailable h2 { color: var(--red); }
    .unavailable p { color: var(--muted); font-family: Inter, ui-sans-serif, system-ui, sans-serif; line-height: 1.55; }
    footer { margin-top: 54px; color: var(--muted); font-size: .68rem; line-height: 1.7; }
    @media (max-width: 820px) { .status-grid { grid-template-columns: repeat(2, 1fr); } .cards { grid-template-columns: 1fr; } }
    @media (max-width: 560px) { main { width: min(100% - 20px, 1180px); padding-top: 20px; } header { display: block; } .scope { display: inline-block; margin-top: 22px; } .status-grid { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
<main>
  <header>
    <div>
      <div class="eyebrow">DEVELOPER ALPHA · RETAINED EVIDENCE</div>
      <h1>EdgeLab</h1>
      <p class="subtitle">A truth-first laboratory for sports-market research. This local viewer makes the current synthetic workflow and safety state visible; it cannot approve research, trade, or move capital.</p>
    </div>
    <div class="scope">MOCK_ONLY</div>
  </header>
  <div id="app" aria-live="polite">
    <section class="status-grid" aria-label="Verifying status">
      <div class="metric"><div class="label">Evidence</div><div class="value">VERIFYING</div></div>
    </section>
  </div>
  <footer>LOCAL VIEW · GET/HEAD ONLY · CACHE DISABLED · NO EXTERNAL ASSETS · NO OPERATIONAL AUTHORITY</footer>
</main>
<script nonce="__EDGELAB_NONCE__">
  const app = document.getElementById('app');
  const el = (tag, className, text) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = String(text);
    return node;
  };
  const section = (title, count) => {
    const node = el('section', 'section');
    const head = el('div', 'section-head');
    head.append(el('h2', '', title), el('div', 'count', count));
    node.append(head);
    return node;
  };
  const money = (minor, currency) => new Intl.NumberFormat('en-US', {style: 'currency', currency}).format(minor / 100);

  function render(report) {
    app.replaceChildren();
    const capital = report.controls.capital;
    const grid = el('section', 'status-grid');
    [
      ['Edge conclusion', report.outcome.edge_conclusion, 'safe'],
      ['Workflow', report.outcome.workflow_disposition, 'blocked'],
      ['Live capital', capital.live_status, 'locked'],
      ['Deployable', money(capital.live_deployable_minor, capital.currency), 'locked']
    ].forEach(([label, value, state]) => {
      const cell = el('div', 'metric');
      cell.append(el('div', 'label', label), el('div', `value ${state}`, value));
      grid.append(cell);
    });
    app.append(grid);

    const stops = section('Open STOPs', `${report.controls.open_stops.length} ACTIVE`);
    const stopCards = el('div', 'cards');
    report.controls.open_stops.forEach(stop => {
      const card = el('article', 'card stop');
      const top = el('div', 'card-top');
      top.append(el('div', 'role open', `${stop.severity} · OPEN`), el('div', 'tag', stop.id));
      card.append(top, el('h3', '', stop.reason));
      card.append(el('div', 'affected', `AFFECTS: ${stop.affected_components.join(' · ')}`));
      stopCards.append(card);
    });
    stops.append(stopCards);
    app.append(stops);

    const workflow = section('Synthetic workflow', `${report.stages.length} ROLES`);
    const stageCards = el('div', 'cards');
    report.stages.forEach(stage => {
      const card = el('article', 'card');
      const top = el('div', 'card-top');
      top.append(el('div', 'role', stage.role), el('div', 'tag', stage.status));
      card.append(top, el('p', '', stage.contribution), el('p', 'uncertainty', `UNCERTAINTY · ${stage.uncertainty}`));
      stageCards.append(card);
    });
    workflow.append(stageCards);
    app.append(workflow);

    const limits = section('Known limitations', `${report.known_limitations.length} DECLARED`);
    const list = el('ul', 'limitations');
    report.known_limitations.forEach(item => list.append(el('li', '', item)));
    limits.append(list);
    app.append(limits);

    const provenance = section('Content-bound provenance', `${report.provenance.length} SHA-256 RECORDS`);
    report.provenance.forEach(item => {
      const detail = el('details');
      detail.append(el('summary', '', `${item.label} · ${item.path}`), el('div', 'hash', item.sha256));
      provenance.append(detail);
    });
    app.append(provenance);
  }

  function unavailable() {
    app.replaceChildren();
    const box = el('section', 'unavailable');
    box.append(el('h2', '', 'UNAVAILABLE_FAIL_CLOSED'));
    box.append(el('p', '', 'The content-bound alpha report could not be verified. No cached or partial project state is being displayed.'));
    app.append(box);
  }

  fetch('/api/v1/alpha', {cache: 'no-store', credentials: 'same-origin'})
    .then(response => response.ok ? response.json() : Promise.reject(new Error('unavailable')))
    .then(payload => render(payload.report))
    .catch(unavailable);
</script>
</body>
</html>
"""


class AlphaViewerHandler(BaseHTTPRequestHandler):
    """Serve only the static viewer and the verified alpha JSON report."""

    server_version = "EdgeLabAlphaViewer/1"
    sys_version = ""

    def _send(self, status: HTTPStatus, body: bytes, content_type: str, *, head: bool = False,
              extra_headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in {**SECURITY_HEADERS, **(extra_headers or {})}.items():
            self.send_header(key, value)
        self.end_headers()
        if not head:
            self.wfile.write(body)

    def _json(self, status: HTTPStatus, value: Any, *, head: bool = False,
              extra_headers: dict[str, str] | None = None) -> None:
        body = (json.dumps(value, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8", head=head, extra_headers=extra_headers)

    def _route(self, *, head: bool) -> None:
        target = urlsplit(self.path)
        if target.query or target.fragment:
            self._json(HTTPStatus.NOT_FOUND, {"status": "NOT_FOUND"}, head=head)
            return
        if target.path == "/":
            nonce = secrets.token_urlsafe(18)
            page = PAGE.replace("__EDGELAB_NONCE__", nonce).encode("utf-8")
            policy = (
                "default-src 'self'; "
                f"style-src 'nonce-{nonce}'; script-src 'nonce-{nonce}'; "
                "object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
            )
            self._send(
                HTTPStatus.OK,
                page,
                "text/html; charset=utf-8",
                head=head,
                extra_headers={"Content-Security-Policy": policy},
            )
            return
        if target.path == "/healthz":
            self._json(HTTPStatus.OK, {"schema_version": 1, "status": "PROCESS_UP"}, head=head)
            return
        if target.path == "/api/v1/alpha":
            try:
                report = alpha.build_report()
            except Exception:
                self._json(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    {"schema_version": 1, "status": "UNAVAILABLE_FAIL_CLOSED"},
                    head=head,
                )
                return
            self._json(
                HTTPStatus.OK,
                {
                    "schema_version": 1,
                    "served_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    "report": report,
                },
                head=head,
            )
            return
        self._json(HTTPStatus.NOT_FOUND, {"status": "NOT_FOUND"}, head=head)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._route(head=False)

    def do_HEAD(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._route(head=True)

    def _method_not_allowed(self) -> None:
        self._json(
            HTTPStatus.METHOD_NOT_ALLOWED,
            {"status": "METHOD_NOT_ALLOWED"},
            extra_headers={"Allow": "GET, HEAD"},
        )

    do_POST = _method_not_allowed
    do_PUT = _method_not_allowed
    do_PATCH = _method_not_allowed
    do_DELETE = _method_not_allowed
    do_OPTIONS = _method_not_allowed

    def log_message(self, format: str, *args: Any) -> None:
        """Keep routine local requests quiet; startup state is printed by main."""


class AlphaViewerServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def create_server(port: int = DEFAULT_PORT) -> AlphaViewerServer:
    if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535:
        raise ValueError("Port must be an integer from 0 through 65535")
    return AlphaViewerServer((LOOPBACK_HOST, port), AlphaViewerHandler)


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        server = create_server(args.port)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    host, port = server.server_address
    print(f"EdgeLab developer alpha viewer: http://{host}:{port}")
    print("Read-only MOCK_ONLY visibility; no operational authority.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
