"""End-to-end regressions for the non-operational synthetic composition."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from src.edgelab.locked_authority import read_locked_authority
from src.edgelab.synthetic_lifecycle import (
    CANONICAL_ROOT,
    TASK_ID,
    SyntheticLifecycleError,
    run_synthetic_lifecycle,
)
from src.edgelab.transactional_scheduler import Scheduler, digest


class _SubstitutedPublicResult:
    def as_mapping(self):
        return {
            "status": "CONSISTENT",
            "anchor_status": "ANCHORED",
            "currentness_status": "CURRENT",
            "authorizing_use": "ALLOW",
            "findings": [],
        }


class SyntheticLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.runtime = Path(self.temp.name) / "runtime"

    def test_complete_synthetic_lifecycle_replays_and_remains_deny(self):
        report = run_synthetic_lifecycle(self.runtime)
        self.assertEqual(
            [event["event"] for event in report["events"]],
            [
                "TASK_INITIALIZED",
                "CLAIM_ISSUED",
                "TASK_STARTED",
                "TASK_COMPLETED",
                "REVIEW_ASSIGNED",
                "REVIEW_APPROVED",
                "DIRECTOR_ROUTED",
            ],
        )
        self.assertEqual(
            tuple(report["final_locked_authority"]["tuple"][key] for key in (
                "workflow", "execution", "review"
            )),
            ("DIRECTOR_GATE_READY", "EXECUTION_COMPLETED", "APPROVED"),
        )
        self.assertEqual(report["historical_binding"]["status"], "BOUND_DENY_ONLY")
        self.assertEqual(
            report["historical_binding"]["evidence_class"],
            "R_GATE_CANDIDATE_EVIDENCE",
        )
        self.assertEqual(
            report["public_runtime_v2_verification"]["status"], "UNSUPPORTED"
        )
        self.assertIn(
            "REDUCER_UNIMPLEMENTED",
            [finding["code"] for finding in report["public_runtime_v2_verification"]["findings"]],
        )
        self.assertEqual(report["authorization"]["authorizing_use"], "DENY")
        self.assertEqual(report["scheduler_replay"], "PASSED")
        self.assertEqual(
            report["report_sha256"],
            digest({key: value for key, value in report.items() if key != "report_sha256"}),
        )
        Scheduler(CANONICAL_ROOT, self.runtime).startup()

    def test_runtime_path_must_be_new_and_outside_repository(self):
        with self.assertRaisesRegex(SyntheticLifecycleError, "outside"):
            run_synthetic_lifecycle(CANONICAL_ROOT / ".forbidden-synthetic-runtime")
        self.runtime.mkdir()
        with self.assertRaisesRegex(SyntheticLifecycleError, "must not already exist"):
            run_synthetic_lifecycle(self.runtime)

    def test_positive_public_verifier_substitution_rejects_before_runtime_creation(self):
        with patch(
            "src.edgelab.synthetic_lifecycle.verify_runtime_image",
            return_value=_SubstitutedPublicResult(),
        ):
            with self.assertRaisesRegex(SyntheticLifecycleError, "did not fail closed"):
                run_synthetic_lifecycle(self.runtime)
        self.assertFalse(self.runtime.exists())

    def test_positive_binding_substitution_rejects_before_claim(self):
        substituted = {
            "status": "BOUND_DENY_ONLY",
            "evidence_class": "R_GATE_CANDIDATE_EVIDENCE",
            "verification": {
                "currentness_status": "CURRENT",
                "verifier_status": "PASS",
                "generation_match": True,
                "authorizing_use": "ALLOW",
            },
        }
        with patch(
            "src.edgelab.synthetic_lifecycle.compose_authority_binding",
            return_value=substituted,
        ):
            with self.assertRaisesRegex(SyntheticLifecycleError, "binding did not fail closed"):
                run_synthetic_lifecycle(self.runtime)
        observation = read_locked_authority(Scheduler(CANONICAL_ROOT, self.runtime), TASK_ID)
        self.assertEqual(
            observation["authority"]["task"]["tuple"]["execution"], "CLAIMABLE"
        )
        self.assertEqual(observation["verification"]["authorizing_use"], "DENY")

    def test_cli_emits_sealed_deny_report(self):
        completed = subprocess.run(
            [
                sys.executable,
                str(CANONICAL_ROOT / "tools/run_synthetic_lifecycle.py"),
                "--runtime-dir",
                str(self.runtime),
            ],
            cwd=CANONICAL_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        report = json.loads(completed.stdout)
        self.assertEqual(report["integration_status"], "RECORDED_NON_OPERATIONAL_LIFECYCLE")
        self.assertEqual(report["authorization"]["authorizing_use"], "DENY")


if __name__ == "__main__":
    unittest.main()
