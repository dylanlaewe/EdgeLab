"""Versioned semantic acceptance probes for H-M0-028 remediation.

The v1 probes remain untouched as historical demonstrations of the replaced
API.  These probes exercise the current repository-resolved boundary.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.edgelab.orchestration import _validate_capabilities, completion, decision
from src.edgelab.validate import ROOT, validate_record


INTENT = {"task_id": "T-SYNTHETIC-001", "attempt": 1}


class SkepticOrchestrationV2(unittest.TestCase):
    def test_valid_authoritative_task_is_mock_only(self):
        result = decision(ROOT, INTENT)
        self.assertEqual(result["decision"], "DISPATCH")
        self.assertEqual(result["execution_adapter"], "MOCK_ONLY")

    def test_disguised_live_operation_cannot_be_supplied_by_caller(self):
        result = decision(ROOT, {**INTENT, "operation": "LIVE_EXECUTION"})
        self.assertEqual(result["decision"], "DENY")

    def test_legacy_task_writer_dependency_and_capability_inputs_deny(self):
        for legacy in (
            {"task": {"operation": "LIVE_EXECUTION"}},
            {"completed": {"forged"}},
            {"writer_task": "forged"},
            {"capability": {"network_required": False}},
        ):
            self.assertEqual(decision(ROOT, INTENT, **legacy)["decision"], "DENY")

    def test_unknown_stale_and_malformed_intents_deny(self):
        for intent in (
            {"task_id": "T-UNKNOWN", "attempt": 1},
            {"task_id": "T-SYNTHETIC-001", "attempt": 2},
            {"task_id": "T-SYNTHETIC-001"},
            {"task_id": "T-SYNTHETIC-001", "attempt": "1"},
        ):
            self.assertEqual(decision(ROOT, intent)["decision"], "DENY")

    def test_copied_checkout_and_unreachable_history_deny(self):
        with tempfile.TemporaryDirectory() as directory:
            copied = Path(directory)
            with patch("src.edgelab.orchestration._remote", return_value="https://github.com/dylanlaewe/EdgeLab.git"):
                self.assertEqual(decision(copied, INTENT)["decision"], "DENY")
        with patch("src.edgelab.orchestration._is_ancestor_of_remote_main", return_value=False):
            self.assertEqual(decision(ROOT, INTENT)["decision"], "DENY")

    def test_task_schema_requires_complete_authoritative_semantics(self):
        incomplete = {
            "schema_version": 2, "task_id": "T-EVIL", "milestone": "M0.2",
            "task_purpose": "SYNTHETIC_ORCHESTRATION", "action_classification": "SYNTHETIC_TEST",
        }
        with self.assertRaises(Exception):
            validate_record("orchestration-task", incomplete, ROOT)

    def test_completion_and_review_routes_are_unavailable_without_authentication(self):
        with self.assertRaisesRegex(ValueError, "FUTURE_GATE"):
            completion(ROOT, INTENT, evidence=["forged completion"])

    def test_unsafe_or_unknown_capability_reference_denies(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capabilities = root / "orchestration/capabilities"
            capabilities.mkdir(parents=True)
            schemas = root / "schemas"
            schemas.mkdir()
            (schemas / "capability-registry.schema.json").write_bytes(
                (ROOT / "schemas/capability-registry.schema.json").read_bytes()
            )
            unsafe = {
                "schema_version": 1, "capability_id": "C-NET", "name": "network", "source_repository": "x",
                "source_owner": "x", "pinned_version": "1", "provenance": "x", "intended_roles": ["00 Director"],
                "capabilities": ["x"], "permissions": [], "network_required": True, "external_dependencies": [],
                "credential_required": False, "executable_code": False, "security_review": "REVIEWED",
                "trust_status": "TRUSTED", "approval_status": "APPROVED", "update_policy": "pinned", "revoked": False,
            }
            (capabilities / "C-NET.json").write_text(json.dumps(unsafe), encoding="utf-8")
            with self.assertRaises(ValueError):
                _validate_capabilities(root, {"capability_refs": ["C-NET"]})
            with self.assertRaises(ValueError):
                _validate_capabilities(root, {"capability_refs": ["C-UNKNOWN"]})


if __name__ == "__main__":
    unittest.main()
