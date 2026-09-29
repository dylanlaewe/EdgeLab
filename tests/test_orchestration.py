"""Director-owned positive tests for the repository-resolved M0.2 preflight."""
from __future__ import annotations

import unittest
from unittest.mock import patch

from src.edgelab.orchestration import completion, decision
from src.edgelab.validate import ROOT


INTENT = {"task_id": "T-SYNTHETIC-001", "attempt": 1}


class OrchestrationTests(unittest.TestCase):
    def test_authoritative_synthetic_task_dispatches_mock_only(self):
        result = decision(ROOT, INTENT)
        self.assertEqual(result["decision"], "DISPATCH")
        self.assertEqual(result["execution_adapter"], "MOCK_ONLY")
        self.assertEqual(result["operation"], "SYNTHETIC_ASSERT")
        self.assertEqual(result["decision_id"], "D-1-T-SYNTHETIC-001-1")

    def test_intent_cannot_supply_task_semantics_or_legacy_authority(self):
        self.assertEqual(
            decision(ROOT, {**INTENT, "operation": "LIVE_EXECUTION"})["decision"], "DENY"
        )
        self.assertEqual(
            decision(ROOT, INTENT, completed={"anything"})["decision"], "DENY"
        )
        self.assertEqual(
            decision(ROOT, INTENT, writer_task="other")["decision"], "DENY"
        )

    def test_wrong_attempt_unknown_task_and_wrong_remote_deny(self):
        self.assertEqual(decision(ROOT, {"task_id": "T-SYNTHETIC-001", "attempt": 2})["decision"], "DENY")
        self.assertEqual(decision(ROOT, {"task_id": "T-UNKNOWN", "attempt": 1})["decision"], "DENY")
        with patch("src.edgelab.orchestration._remote", return_value="https://example.invalid/EdgeLab.git"):
            self.assertEqual(decision(ROOT, INTENT)["decision"], "DENY")

    def test_completion_and_review_are_fail_closed_future_gate(self):
        with self.assertRaisesRegex(ValueError, "FUTURE_GATE"):
            completion(ROOT, INTENT, evidence=["untrusted prose"])


if __name__ == "__main__":
    unittest.main()
