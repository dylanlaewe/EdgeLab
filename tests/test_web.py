"""Loopback developer-alpha viewer checks; visibility only, never authority."""
from __future__ import annotations

import http.client
import json
import os
import shutil
import tempfile
import threading
import unittest
from contextlib import contextmanager
from pathlib import Path
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


@contextmanager
def isolated_status_root():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory).resolve()
        stop_paths = web.project_status._stop_paths(web.project_status.ROOT)
        paths = (*web.project_status.STATIC_PATHS, *stop_paths, Path("reports/stops/README.md"))
        for relative in paths:
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(web.project_status.ROOT / relative, target)
        yield root


class WebTests(unittest.TestCase):
    def test_status_api_exposes_governed_non_authorizing_project_state(self):
        with running_server() as server:
            status, headers, body = request(server, "GET", "/api/v1/status")

        self.assertEqual(status, 200)
        self.assertEqual(headers["cache-control"], "no-store")
        self.assertNotIn("access-control-allow-origin", headers)
        envelope = json.loads(body)
        self.assertEqual(envelope["schema_version"], 1)
        report = envelope["status"]
        self.assertEqual(report["observatory_status"], "VERIFIED_READ_ONLY_SNAPSHOT")
        self.assertEqual(report["project"]["phase"], "M0")
        self.assertEqual(report["project"]["status"], "BLOCKED_FOR_APPROVAL_REMEDIATION_ALLOWED")
        self.assertFalse(report["project"]["demonstrated_edge"])
        self.assertEqual(report["safety"]["live_status"], "LOCKED")
        self.assertEqual(report["safety"]["kill_switch"], "ENGAGED")
        self.assertEqual(report["safety"]["deployable_minor"], 0)
        self.assertEqual(report["evidence"]["freshness"], "UNVERIFIED_OR_STALE")
        self.assertEqual(report["evidence"]["currentness"], "UNKNOWN")
        self.assertEqual(report["evidence"]["authorizing_use"], "DENY")
        self.assertTrue(report["capabilities"]["read_only"])
        for field in ("repository_mutation", "scheduler_transition", "paper_execution", "live_execution", "capital_movement"):
            self.assertFalse(report["capabilities"][field])
        self.assertEqual(
            [item["id"] for item in report["open_stops"]],
            ["STOP-M0-001", "STOP-M0-3A-001", "STOP-M0-3A-002"],
        )
        self.assertEqual(len(report["source_digests"]), 27)

    def test_status_builder_is_read_only_and_source_races_fail_closed(self):
        paths = web.project_status._stop_paths(web.project_status.ROOT)
        before = web.project_status._read_sources(web.project_status.ROOT, paths)
        report = web.project_status.build_status()
        after = web.project_status._read_sources(web.project_status.ROOT, paths)
        self.assertEqual(before, after)
        self.assertEqual(report["capabilities"]["repository_mutation"], False)

        changed = dict(before)
        changed[web.project_status.PROJECT_STATE] += b"\n"
        with patch.object(web.project_status._PinnedRepository,"read_sources",side_effect=[before,changed]):
            with self.assertRaises(web.project_status.StatusUnavailable):
                web.project_status.build_status()

    def test_status_builder_denies_contradictory_safety_and_stop_inventory(self):
        paths = web.project_status._stop_paths(web.project_status.ROOT)
        actual = web.project_status._read_sources(web.project_status.ROOT, paths)
        state = json.loads(actual[web.project_status.PROJECT_STATE])
        state["live_status"] = "UNLOCKED"
        contradicted = dict(actual)
        contradicted[web.project_status.PROJECT_STATE] = json.dumps(state).encode()
        with patch.object(web.project_status._PinnedRepository,"read_sources",return_value=contradicted):
            with self.assertRaises(Exception):
                web.project_status.build_status()

        incomplete = tuple(path for path in paths if "3A" not in path.name)
        with patch.object(web.project_status._PinnedRepository,"stop_paths",return_value=incomplete):
            with self.assertRaises(web.project_status.StatusUnavailable):
                web.project_status.build_status()

    def test_status_builder_denies_hidden_stop_hardlink_and_weakened_schema(self):
        with isolated_status_root() as root:
            (root/"reports/stops/.STOP-HIDDEN-001.v1.json").write_text("{}")
            with self.assertRaises(web.project_status.StatusUnavailable):
                web.project_status.build_status(root)

        with isolated_status_root() as root:
            original_open=os.open; raced=False
            def raced_open(path,flags,mode=0o777,*,dir_fd=None):
                nonlocal raced
                if path=="docs" and dir_fd is not None and not raced:
                    raced=True
                    original=root/"docs"; held=root/"docs-held"
                    original.rename(held); original.symlink_to(held, target_is_directory=True)
                    try:
                        return original_open(path,flags,mode,dir_fd=dir_fd)
                    finally:
                        original.unlink(); held.rename(original)
                return original_open(path,flags,mode,dir_fd=dir_fd)
            with patch("src.edgelab.project_status.os.open",side_effect=raced_open):
                with self.assertRaises(OSError):
                    web.project_status.build_status(root)
            self.assertTrue(raced)

        with isolated_status_root() as root:
            os.link(root/web.project_status.BANKROLL,root/"bankroll-hardlink.json")
            with self.assertRaises(web.project_status.StatusUnavailable):
                web.project_status.build_status(root)

        with isolated_status_root() as root:
            (root/web.project_status.RISK_SCHEMA).write_text(json.dumps({"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object"}))
            risk=json.loads((root/web.project_status.RISK_POLICY).read_text())
            risk["phase"]="M9"
            risk["limits"]={f"fake_{index}":0 for index in range(6)}
            (root/web.project_status.RISK_POLICY).write_text(json.dumps(risk))
            with self.assertRaises(web.project_status.StatusUnavailable):
                web.project_status.build_status(root)

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
            ["STOP-M0-001", "STOP-M0-3A-001", "STOP-M0-3A-002"],
        )
        self.assertEqual(report["controls"]["capital"]["conceptual_minor"], 5000)
        self.assertEqual(report["controls"]["capital"]["live_deployable_minor"], 0)
        self.assertEqual(report["controls"]["capital"]["live_status"], "LOCKED")
        self.assertEqual(report["controls"]["capital"]["kill_switch"], "ENGAGED")
        self.assertEqual(len(report["provenance"]), 29)

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
        self.assertIn("LOCAL LABORATORY OBSERVATORY", text)
        self.assertIn("READ_ONLY · DENY_DEFAULT", text)
        self.assertIn("/api/v1/status", text)
        self.assertIn("status.evidence.freshness", text)
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

        with patch("src.edgelab.web.project_status.build_status", side_effect=ValueError("private path")):
            with running_server() as server:
                status, _, body = request(server, "GET", "/api/v1/status")
        self.assertEqual(status, 503)
        self.assertEqual(json.loads(body), {"schema_version": 1, "status": "UNAVAILABLE_FAIL_CLOSED"})
        self.assertNotIn(b"private path", body)

    def test_mutation_unknown_and_traversal_paths_are_denied(self):
        with running_server() as server:
            for method in ("POST", "PUT", "PATCH", "DELETE", "OPTIONS"):
                with self.subTest(method=method):
                    status, headers, _ = request(server, method, "/api/v1/status")
                    self.assertEqual(status, 405)
                    self.assertEqual(headers["allow"], "GET, HEAD")
            for path in ("/missing", "/../portfolio/bankroll.json", "/api/v1/status?path=README.md"):
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
