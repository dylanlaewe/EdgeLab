"""Historical characterization probes for the Envelope v2 planning schema.

These probes preserve what the published schema accepted during H-M0-053. They
do not define the desired successor schema and must not be weakened or rewritten.
"""
from __future__ import annotations

import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]


class SkepticDecisionEnvelopePlanV2(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        schema = json.loads(
            (ROOT / "schemas/m0-2-decision-evidence-envelope.v2.schema.json").read_text()
        )
        Draft202012Validator.check_schema(schema)
        cls.validator = Draft202012Validator(schema)

    def envelope(self) -> dict:
        return {
            "schema_version": 2,
            "envelope_id": "arbitrary",
            "subject": {
                "task_id": "T-SYNTHETIC",
                "attempt": 1,
                "assignment_head": "arbitrary",
                "handoff_head": "arbitrary",
            },
            "repository": {},
            "runtime": {},
            "evaluation": {},
            "source_manifest": {},
            "engine_manifest": {},
            "input": {},
            "raw_output": {},
            "normalized_output": {
                "decision": "DENY",
                "decision_id": "arbitrary",
                "task_id": None,
                "reason": "arbitrary",
                "execution_adapter": "MOCK_ONLY",
                "operation": None,
            },
            "envelope_sha256": "0" * 64,
        }

    def assert_schema_accepts(self, value: dict) -> None:
        self.assertEqual([], list(self.validator.iter_errors(value)))

    def test_accepts_empty_security_critical_sections(self):
        self.assert_schema_accepts(self.envelope())

    def test_accepts_hidden_caller_authority_in_open_sections(self):
        value = self.envelope()
        value["repository"] = {"verified": True, "authority": "caller"}
        value["runtime"] = {"receipt_digest": "caller-selected", "extra": {"verified": True}}
        value["input"] = {"capital_permission": True}
        value["raw_output"] = {"invented": True}
        self.assert_schema_accepts(value)

    def test_accepts_deny_with_non_null_operation(self):
        value = self.envelope()
        value["normalized_output"]["operation"] = "CAPITAL_MUTATION"
        self.assert_schema_accepts(value)

    def test_accepts_dispatch_with_null_operation(self):
        value = self.envelope()
        value["normalized_output"]["decision"] = "DISPATCH"
        self.assert_schema_accepts(value)


if __name__ == "__main__":
    unittest.main()
