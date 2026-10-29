"""Developer-alpha checks; synthetic visibility only, never authorization."""
from __future__ import annotations

import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from src.edgelab.alpha import AlphaEvidenceError, _current_stop_heads, build_report, main
from src.edgelab.validate import ROOT, read


class AlphaTests(unittest.TestCase):
    def manifest(self) -> dict:
        return read(ROOT / "examples/alpha/sample-workflow.v1.json")

    def alternate_manifest(self, value: dict) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "manifest.json"
        path.write_text(json.dumps(value, indent=2) + "\n")
        return path

    def test_report_is_complete_visible_and_non_authorizing(self):
        report = build_report()
        self.assertEqual(report["alpha_status"], "COMPLETED_NON_OPERATIONAL_DEMO")
        self.assertEqual(
            [stage["role"] for stage in report["stages"]],
            ["00 Director", "01 Data", "03 Research", "04 Quant", "05 Skeptic", "06 Risk & Execution"],
        )
        self.assertEqual(report["outcome"]["edge_conclusion"], "NO_DEMONSTRATED_EDGE")
        self.assertEqual(report["outcome"]["workflow_disposition"], "BLOCKED")
        for field in ("scientific_approval", "paper_authorization", "live_authorization", "capital_moved"):
            self.assertFalse(report["outcome"][field])
        self.assertEqual(
            [stop["id"] for stop in report["controls"]["open_stops"]],
            ["STOP-M0-001", "STOP-M0-3A-001", "STOP-M0-3A-002"],
        )
        self.assertEqual(report["controls"]["capital"]["live_deployable_minor"], 0)
        self.assertEqual(report["controls"]["capital"]["live_status"], "LOCKED")
        self.assertEqual(report["controls"]["capital"]["kill_switch"], "ENGAGED")
        self.assertEqual(len(report["provenance"]), 27)

    def test_changed_bound_evidence_fails_closed(self):
        manifest = copy.deepcopy(self.manifest())
        manifest["artifacts"]["quant_result"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(AlphaEvidenceError, "Content digest mismatch"):
            build_report(manifest_path=self.alternate_manifest(manifest))

    def test_incomplete_stop_inventory_fails_closed(self):
        manifest = copy.deepcopy(self.manifest())
        manifest["current_stop_artifacts"].pop()
        manifest["expected_controls"]["current_open_stop_ids"].pop()
        with self.assertRaisesRegex(AlphaEvidenceError, "STOP inventory is incomplete"):
            build_report(manifest_path=self.alternate_manifest(manifest))

    def test_manifest_is_closed_and_mock_only(self):
        manifest = copy.deepcopy(self.manifest())
        manifest["operational_authorization"] = True
        with self.assertRaisesRegex(AlphaEvidenceError, "must contain exactly"):
            build_report(manifest_path=self.alternate_manifest(manifest))

    def test_current_stop_heads_ignore_resolved_predecessors(self):
        original = read(ROOT / "reports/stops/STOP-M0-001.v1.json")
        resolved = {
            **original,
            "version": 2,
            "status": "RESOLVED",
            "resolution_event_ref": "reports/audit/A-M0-001.v1.json",
        }
        heads = _current_stop_heads([
            (original, "reports/stops/STOP-M0-001.v1.json"),
            (resolved, "reports/stops/STOP-M0-001.v2.json"),
        ])
        self.assertEqual([(item["id"], item["version"], item["status"]) for item in heads], [
            ("STOP-M0-001", 2, "RESOLVED")
        ])

    def test_output_cannot_overwrite_repository_or_follow_alias(self):
        readme = ROOT / "README.md"
        before = readme.read_bytes()
        self.assertEqual(main(["--output", str(readme)]), 2)
        self.assertEqual(readme.read_bytes(), before)
        with tempfile.TemporaryDirectory() as directory:
            alias = Path(directory) / "repo-alias"
            alias.symlink_to(readme)
            self.assertEqual(main(["--output", str(alias)]), 2)
            self.assertEqual(readme.read_bytes(), before)

    def test_output_is_exclusive_and_outside_repository(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "alpha.json"
            self.assertEqual(main(["--format", "json", "--output", str(output)]), 0)
            self.assertEqual(json.loads(output.read_text())["outcome"]["workflow_disposition"], "BLOCKED")
            before = output.read_bytes()
            self.assertEqual(main(["--format", "json", "--output", str(output)]), 2)
            self.assertEqual(output.read_bytes(), before)

    def test_json_cli_is_machine_readable(self):
        output = io.StringIO()
        with redirect_stdout(output):
            result = main(["--format", "json"])
        self.assertEqual(result, 0)
        report = json.loads(output.getvalue())
        self.assertEqual(report["outcome"]["workflow_disposition"], "BLOCKED")
        director = next(stage for stage in report["stages"] if stage["role"] == "00 Director")
        self.assertEqual(director["evidence"]["current_decision"], "DENY")
        self.assertEqual(director["evidence"]["execution_adapter"], "MOCK_ONLY")


if __name__ == "__main__":
    unittest.main()
