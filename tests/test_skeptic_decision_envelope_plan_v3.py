"""Historical characterization probes for the Envelope v3 planning package.

The probes preserve what H-M0-055 found. They do not define the desired
successor contract and must not be rewritten to follow a future schema.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]
FREEZE = "bc3a40924ca580ca6eddc4c24e32ff99ddd95330"
ZERO = "0" * 64


class SkepticDecisionEnvelopePlanV3(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = json.loads(
            (ROOT / "schemas/m0-2-decision-evidence-envelope.v3.schema.json").read_text()
        )
        Draft202012Validator.check_schema(cls.schema)
        cls.validator = Draft202012Validator(cls.schema, format_checker=FormatChecker())

    def envelope(self) -> dict:
        subject = {
            "task_id": "T-SYNTHETIC",
            "attempt": 1,
            "assignment_head": ZERO,
            "handoff_head": ZERO,
        }
        raw_mapping = {
            "decision": "DENY",
            "decision_id": "D-local",
            "task_id": "T-SYNTHETIC",
            "reason": "denied",
            "execution_adapter": "MOCK_ONLY",
        }
        raw_bytes = json.dumps(raw_mapping, sort_keys=True, separators=(",", ":")).encode()
        return {
            "schema_version": 3,
            "envelope_id": "E-local",
            "subject": subject,
            "repository": {
                "root": "/replay",
                "git_identity": {
                    "remote_url": "https://github.com/dylanlaewe/EdgeLab.git",
                    "head_sha": ZERO,
                    "origin_main_sha": ZERO,
                    "head_is_ancestor": True,
                },
            },
            "runtime": {"runtime_id": "R-local", "generation": 0},
            "evaluation": {
                "evaluation_time": "2026-10-06T17:00:00Z",
                "timezone": "UTC",
                "locale": "C.UTF-8",
                "hash_seed": "0",
            },
            "source_manifest": [
                {
                    "kind": "FILE",
                    "source_id": "S-one",
                    "path": "orchestration/scheduler-state.json",
                    "media_type": "application/json",
                    "blob_sha256": ZERO,
                    "byte_length": 2,
                    "bytes_base64": "e30=",
                }
            ],
            "engine_manifest": {
                "freeze_commit": ZERO,
                "python_implementation": "CPython",
                "python_version": "3.13.7",
                "jsonschema_version": "4.25.1",
                "entries": [
                    {"path": f"engine-{index}", "sha256": ZERO, "byte_length": 1}
                    for index in range(3)
                ],
                "launcher_sha256": ZERO,
                "clock_shim_sha256": ZERO,
                "git_shim_sha256": ZERO,
            },
            "input": {
                "subject": copy.deepcopy(subject),
                "source_ids": ["S-one"],
                "canonical_sha256": ZERO,
            },
            "raw_output": {
                "encoding": "UTF8_CANONICAL_JSON",
                "bytes_base64": base64.b64encode(raw_bytes).decode(),
                "byte_length": len(raw_bytes),
                "sha256": hashlib.sha256(raw_bytes).hexdigest(),
            },
            "normalized_output": {
                "decision": "DENY",
                "decision_id": "D-local",
                "task_id": "T-SYNTHETIC",
                "reason": "denied",
                "execution_adapter": "MOCK_ONLY",
                "operation": None,
            },
            "envelope_sha256": ZERO,
        }

    def accepted(self, value: dict) -> None:
        self.assertEqual([], list(self.validator.iter_errors(value)))

    def test_nested_extra_property_is_rejected(self):
        value = self.envelope()
        value["repository"]["caller_verified"] = True
        self.assertTrue(list(self.validator.iter_errors(value)))

    def test_schema_cannot_represent_named_stage1_freeze_commit(self):
        value = self.envelope()
        value["engine_manifest"]["freeze_commit"] = FREEZE
        self.assertTrue(list(self.validator.iter_errors(value)))

    def test_impossible_deny_and_dispatch_operation_pairs_are_accepted(self):
        deny = self.envelope()
        deny["normalized_output"]["operation"] = "CAPITAL_MUTATION"
        self.accepted(deny)
        dispatch = self.envelope()
        dispatch["normalized_output"]["decision"] = "DISPATCH"
        dispatch["normalized_output"]["operation"] = None
        self.accepted(dispatch)

    def test_subject_mismatch_is_accepted_and_normalized_attempt_is_unrepresentable(self):
        value = self.envelope()
        value["input"]["subject"]["task_id"] = "T-OTHER"
        self.accepted(value)
        normalized = self.schema["$defs"]["normalized"]["properties"]
        self.assertNotIn("attempt", normalized)
        self.assertNotIn("assignment_head", normalized)
        self.assertNotIn("handoff_head", normalized)

    def test_duplicate_sources_and_unbound_absence_are_accepted(self):
        value = self.envelope()
        absence = {
            "kind": "ABSENT",
            "source_id": "S-absent",
            "path": "missing.json",
            "absence_scope": "FILE",
            "inventory_id": "NO-SUCH-INVENTORY",
        }
        value["source_manifest"] = [absence, copy.deepcopy(absence)]
        value["input"]["source_ids"] = ["S-absent", "S-absent"]
        self.accepted(value)

    def test_invalid_base64_arbitrary_freeze_and_offset_time_are_accepted(self):
        value = self.envelope()
        value["source_manifest"][0]["bytes_base64"] = "not base64!"
        value["engine_manifest"]["freeze_commit"] = ZERO
        value["evaluation"]["evaluation_time"] = "2026-10-06T13:00:00-04:00"
        self.accepted(value)

    def test_v6_reuses_closed_c0_and_introduces_undefined_r0(self):
        v3 = (ROOT / "docs/M0.3A_TRANSACTIONAL_CONTRACT.v3.md").read_text()
        v6 = (ROOT / "docs/M0.3A_TRANSACTIONAL_CONTRACT.v6.md").read_text()
        self.assertIn("`C0=(CLOSED,EXECUTION_COMPLETED,NOT_REQUIRED)`", v3)
        self.assertIn("N0→N1", v3)
        self.assertIn("N0→C0", v6)
        self.assertIn("C0→R0", v6)
        self.assertNotIn("`R0=", v3)


if __name__ == "__main__":
    unittest.main()
