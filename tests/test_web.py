"""Loopback developer-alpha viewer checks; visibility only, never authority."""
from __future__ import annotations

import http.client
import json
import threading
import unittest
from contextlib import contextmanager
from unittest.mock import patch

from src.edgelab import web


@contextmanager
def running_server():
    server = web.create_server(port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def request(server, method: str, path: str):
    connection = http.client.HTTPConnection(*server.server_address, timeout=30)
    connection.request(method, path)
    response = connection.getresponse()
    body = response.read()
    headers = {key.lower(): value for key, value in response.getheaders()}
    connection.close()
    return response.status, headers, body


class WebTests(unittest.TestCase):
    def test_api_exposes_exact_non_authorizing_alpha(self):
        with running_server() as server:
            status, headers, body = request(server, "GET", "/api/v1/alpha")

        self.assertEqual(status, 200)
        self.assertEqual(headers["cache-control"], "no-store")
        self.assertNotIn("access-control-allow-origin", headers)
        envelope = json.loads(body)
        self.assertEqual(envelope["schema_version"], 1)
        report = envelope["report"]
        self.assertEqual(report["outcome"]["edge_conclusion"], "NO_DEMONSTRATED_EDGE")
        self.assertEqual(report["outcome"]["workflow_disposition"], "BLOCKED")
        for field in ("scientific_approval", "paper_authorization", "live_authorization", "capital_moved"):
            self.assertFalse(report["outcome"][field])
        self.assertEqual(
            [stop["id"] for stop in report["controls"]["open_stops"]],
            ["STOP-M0-001", "STOP-M0-3A-001"],
        )
        self.assertEqual(report["controls"]["capital"]["conceptual_minor"], 5000)
        self.assertEqual(report["controls"]["capital"]["live_deployable_minor"], 0)
        self.assertEqual(report["controls"]["capital"]["live_status"], "LOCKED")
        self.assertEqual(report["controls"]["capital"]["kill_switch"], "ENGAGED")
        self.assertEqual(len(report["provenance"]), 12)

    def test_page_is_static_safe_and_non_operational(self):
        with running_server() as server:
            status, headers, body = request(server, "GET", "/")

        text = body.decode("utf-8")
        self.assertEqual(status, 200)
        self.assertIn("default-src 'self'", headers["content-security-policy"])
        self.assertIn("style-src 'nonce-", headers["content-security-policy"])
        self.assertIn("script-src 'nonce-", headers["content-security-policy"])
        self.assertNotIn("'unsafe-inline'", headers["content-security-policy"])
        nonce = headers["content-security-policy"].split("style-src 'nonce-", 1)[1].split("'", 1)[0]
        self.assertIn(f'<style nonce="{nonce}">', text)
        self.assertIn(f'<script nonce="{nonce}">', text)
        self.assertEqual(headers["x-frame-options"], "DENY")
        self.assertIn("DEVELOPER ALPHA", text)
        self.assertIn("MOCK_ONLY", text)
        self.assertIn("report.outcome.edge_conclusion", text)
        self.assertIn("report.outcome.workflow_disposition", text)
        self.assertIn("capital.live_status", text)
        self.assertIn("textContent", text)
        self.assertIn("replaceChildren", text)
        self.assertNotIn("innerHTML", text)
        self.assertNotIn("<form", text)

    def test_evidence_failure_returns_unavailable_without_details(self):
        with patch("src.edgelab.web.alpha.build_report", side_effect=ValueError("sensitive detail")):
            with running_server() as server:
                status, headers, body = request(server, "GET", "/api/v1/alpha")

        self.assertEqual(status, 503)
        self.assertEqual(headers["cache-control"], "no-store")
        payload = json.loads(body)
        self.assertEqual(payload, {"schema_version": 1, "status": "UNAVAILABLE_FAIL_CLOSED"})
        self.assertNotIn(b"sensitive detail", body)

    def test_mutation_unknown_and_traversal_paths_are_denied(self):
        with running_server() as server:
            for method in ("POST", "PUT", "PATCH", "DELETE", "OPTIONS"):
                with self.subTest(method=method):
                    status, headers, _ = request(server, method, "/api/v1/alpha")
                    self.assertEqual(status, 405)
                    self.assertEqual(headers["allow"], "GET, HEAD")
            for path in ("/missing", "/../portfolio/bankroll.json", "/api/v1/alpha?path=README.md"):
                with self.subTest(path=path):
                    status, _, _ = request(server, "GET", path)
                    self.assertEqual(status, 404)

    def test_head_has_headers_and_no_body(self):
        with running_server() as server:
            status, headers, body = request(server, "HEAD", "/")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"")
        self.assertEqual(headers["cache-control"], "no-store")

    def test_server_is_loopback_only(self):
        with running_server() as server:
            self.assertEqual(server.server_address[0], web.LOOPBACK_HOST)


if __name__ == "__main__":
    unittest.main()
