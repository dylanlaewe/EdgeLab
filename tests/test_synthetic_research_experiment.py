"""Integration and adversarial tests for H-M0-183."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from src.edgelab.data_integrity import canonical
import src.edgelab.synthetic_research_experiment as experiment_module
from src.edgelab.synthetic_research_experiment import (
    CANONICAL_ROOT,
    INPUT_PATH,
    PINNED_INPUT_SHA256,
    SyntheticResearchError,
    evaluate_scientific_package,
    format_human,
    mutable_package_copy,
    run_synthetic_research_experiment,
)


RESULT_PATH = CANONICAL_ROOT / "reports/synthetic-research/H-M0-183-result.v1.json"
TOOL = CANONICAL_ROOT / "tools/run_synthetic_research_experiment.py"


class SyntheticResearchExperimentTests(unittest.TestCase):
    def runtime_path(self, label: str) -> Path:
        root = Path(tempfile.mkdtemp(prefix=f"edgelab-hm0183-{label}-"))
        root.rmdir()
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        return root

    def assert_code(self, expected: str, callback) -> None:
        with self.assertRaises(SyntheticResearchError) as raised:
            callback()
        self.assertEqual(raised.exception.code, expected)

    def test_end_to_end_result_matches_retained_evidence_and_is_deterministic(self):
        expected = json.loads(RESULT_PATH.read_text(encoding="utf-8"))
        first = run_synthetic_research_experiment(self.runtime_path("direct"))
        completed = subprocess.run(
            [sys.executable, str(TOOL), "--runtime-dir", str(self.runtime_path("json")), "--format", "json"],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        second = json.loads(completed.stdout)
        self.assertEqual(first, expected)
        self.assertEqual(second, expected)
        unsigned = {key: value for key, value in first.items() if key != "result_sha256"}
        self.assertEqual(first["result_sha256"], hashlib.sha256(canonical(unsigned)).hexdigest())

    def test_human_output_is_observable_and_non_authorizing(self):
        result = json.loads(RESULT_PATH.read_text(encoding="utf-8"))
        rendered = format_human(result)
        self.assertIn("Result: INSUFFICIENT_DATA", rendered)
        self.assertIn("Negative control: REJECTED_AS_EXPECTED", rendered)
        self.assertIn("Authorization: DENY", rendered)
        completed = subprocess.run(
            [sys.executable, str(TOOL), "--runtime-dir", str(self.runtime_path("text")), "--format", "text"],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(completed.stdout, rendered)

    def test_quant_accounts_for_prices_costs_uncertainty_and_drawdown(self):
        stages = evaluate_scientific_package(mutable_package_copy())
        quant = stages["quant"]["output"]
        self.assertEqual((quant["wins"], quant["losses"]), (7, 5))
        self.assertEqual(quant["average_offered_decimal_odds"], "2.054167")
        self.assertEqual(quant["average_two_way_overround"], "0.028880")
        self.assertEqual(quant["net_profit_units"], "2.180000")
        self.assertEqual(quant["net_roi"], "0.181667")
        self.assertEqual(quant["maximum_drawdown_units"], "2.040000")
        self.assertEqual(quant["cost_adjusted_break_even_win_rate"], "0.496552")
        self.assertEqual((quant["wilson_95_lower"], quant["wilson_95_upper"]), ("0.319511", "0.806740"))
        self.assertFalse(quant["sample_sufficient"])
        self.assertFalse(quant["uncertainty_excludes_break_even"])
        self.assertEqual(quant["status"], "INSUFFICIENT_DATA")

    def test_synthetic_skeptic_rejects_positive_roi_claim_and_future_leak_control(self):
        stages = evaluate_scientific_package(mutable_package_copy())
        review = stages["synthetic_skeptic"]["output"]
        self.assertEqual(review["status"], "CHALLENGE_CONFIRMED")
        self.assertIn("POSITIVE_SYNTHETIC_ROI_IS_NOT_REAL_EDGE_EVIDENCE", review["findings"])
        self.assertEqual(review["negative_controls"][0], {
            "control_id": "NEG-FUTURE-SIGNAL-001",
            "status": "REJECTED_AS_EXPECTED",
            "finding": "FUTURE_LEAKAGE",
            "admitted_to_primary_analysis": False,
        })
        self.assertFalse(review["formal_skeptic_approval"])

    def test_missing_evidence_fails_closed(self):
        package = mutable_package_copy()
        del package["primary_observations"][0]["offered_decimal_odds"]
        self.assert_code("MALFORMED_EVIDENCE", lambda: evaluate_scientific_package(package))

    def test_primary_future_leakage_fails_closed(self):
        package = mutable_package_copy()
        package["primary_observations"][0]["signal_published_at"] = "2026-01-03T10:11:00Z"
        self.assert_code("FUTURE_LEAKAGE", lambda: evaluate_scientific_package(package))

    def test_duplicate_event_fails_closed(self):
        package = mutable_package_copy()
        package["primary_observations"][1]["event_id"] = package["primary_observations"][0]["event_id"]
        self.assert_code("DUPLICATE_EVIDENCE", lambda: evaluate_scientific_package(package))

    def test_outcome_unavailable_at_evaluation_fails_closed(self):
        package = mutable_package_copy()
        package["primary_observations"][0]["outcome_available_at"] = "2026-01-20T02:00:00Z"
        self.assert_code("STALE_OR_INCOMPLETE_EVIDENCE", lambda: evaluate_scientific_package(package))

    def test_negative_control_that_is_accepted_fails_the_evaluator(self):
        package = mutable_package_copy()
        package["negative_controls"][0]["observation"]["signal_published_at"] = "2026-01-15T10:00:00Z"
        self.assert_code("NEGATIVE_CONTROL_FAILED", lambda: evaluate_scientific_package(package))

    def test_registration_must_precede_protocol_and_evaluation(self):
        package = mutable_package_copy()
        package["protocol"]["protocol_frozen_at"] = "2025-12-31T00:00:00Z"
        self.assert_code("PREREGISTRATION_ORDER_INVALID", lambda: evaluate_scientific_package(package))

    def test_retained_package_identity_and_all_authority_boundaries_are_deny(self):
        self.assertEqual(
            hashlib.sha256((CANONICAL_ROOT / INPUT_PATH).read_bytes()).hexdigest(),
            PINNED_INPUT_SHA256,
        )
        result = json.loads(RESULT_PATH.read_text(encoding="utf-8"))
        self.assertEqual(result["authorization"]["authorizing_use"], "DENY")
        self.assertEqual(result["stages"]["risk"]["status"], "DENY")
        self.assertEqual(result["stages"]["director"]["output"]["authorization"], "DENY")
        self.assertEqual(result["stages"]["scheduler"]["output"]["authorizing_use"], "DENY")
        self.assertFalse(result["formal_skeptic_approval"])

    def test_missing_result_schema_fails_before_scheduler_runtime_creation(self):
        runtime = self.runtime_path("missing-schema")
        with patch.object(
            experiment_module,
            "RESULT_SCHEMA_PATH",
            Path("schemas/nonexistent-synthetic-result.schema.json"),
        ):
            self.assert_code(
                "MISSING_SCHEMA",
                lambda: run_synthetic_research_experiment(runtime),
            )
        self.assertFalse(runtime.exists())

    def test_incomplete_deny_lifecycle_substitution_fails_closed(self):
        runtime = self.runtime_path("substituted-lifecycle")
        substituted = {
            "integration_status": "RECORDED_NON_OPERATIONAL_LIFECYCLE",
            "mode": "SYNTHETIC_LOCAL_ONLY",
            "task_id": "T-SYNTHETIC-001",
            "events": [{"event": "TASK_INITIALIZED"}],
            "authorization": {
                "authorizing_use": "DENY",
                "operational_release": "DENIED",
                "currentness": "UNKNOWN",
            },
        }
        with patch.object(
            experiment_module,
            "run_synthetic_lifecycle",
            return_value=substituted,
        ):
            self.assert_code(
                "SCHEDULER_CONTRACT_MISMATCH",
                lambda: run_synthetic_research_experiment(runtime),
            )
        self.assertFalse(runtime.exists())


if __name__ == "__main__":
    unittest.main()
