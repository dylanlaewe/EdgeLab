"""Characterization probes for the Envelope v4 planning package.

These probes preserve the independent H-M0-057 findings. They do not define
the desired successor contract and must not be weakened to follow one.
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


class SkepticDecisionEnvelopePlanV4(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.envelope_schema = json.loads(
            (ROOT / "schemas/m0-2-decision-evidence-envelope.v4.schema.json").read_text()
        )
        cls.result_schema = json.loads(
            (ROOT / "schemas/m0-2-decision-evidence-verification-result.v1.schema.json").read_text()
        )
        cls.payload_schema = json.loads(
            (ROOT / "schemas/m0-3a-evidence-only-payloads.v1.schema.json").read_text()
        )
        for schema in (cls.envelope_schema, cls.result_schema, cls.payload_schema):
            Draft202012Validator.check_schema(schema)
        cls.envelope_validator = Draft202012Validator(
            cls.envelope_schema, format_checker=FormatChecker()
        )
        cls.result_validator = Draft202012Validator(cls.result_schema)
        cls.payload_validator = Draft202012Validator(cls.payload_schema)

    def envelope(self) -> dict:
        mapping = {
            "decision": "DENY",
            "decision_id": "D-local",
            "task_id": "T-SYNTHETIC",
            "reason": "denied",
            "execution_adapter": "MOCK_ONLY",
        }
        encoded = json.dumps(mapping, sort_keys=True, separators=(",", ":")).encode()
        return {
            "schema_version": 4,
            "envelope_id": "E-local",
            "subject": {
                "task_id": "T-SYNTHETIC",
                "attempt": 1,
                "assignment_head": ZERO,
                "handoff_head": ZERO,
            },
            "evaluation": {"evaluation_time": "2026-10-06T17:00:00Z"},
            "artifacts": [
                {
                    "kind": "FILE",
                    "artifact_id": "A-one",
                    "path": "orchestration/scheduler-state.json",
                    "bytes_base64": "e30=",
                    "byte_length": 2,
                    "sha256": ZERO,
                }
            ],
            "source_manifest": [{"source_id": "S-one", "artifact_id": "A-one"}],
            "engine_manifest": {
                "freeze_commit": {"algorithm": "git-sha1", "value": FREEZE},
                "dependency_manifest_id": "A-one",
                "entry_artifact_ids": ["A-one"],
                "launcher_artifact_id": "A-one",
                "clock_shim_artifact_id": "A-one",
                "git_shim_artifact_id": "A-one",
                "python_implementation": "CPython",
                "python_version": "3.13.7",
                "distributions": [{"name": "jsonschema", "version": "4.25.1"}],
            },
            "raw_output": {
                "mapping": mapping,
                "canonical_bytes_base64": base64.b64encode(encoded).decode(),
                "byte_length": len(encoded),
                "sha256": hashlib.sha256(encoded).hexdigest(),
            },
            "normalized_output": {**mapping, "operation": None},
            "envelope_sha256": ZERO,
        }

    def envelope_errors(self, value: dict) -> list:
        return list(self.envelope_validator.iter_errors(value))

    def test_named_stage1_git_sha1_is_structurally_accepted(self):
        self.assertEqual([], self.envelope_errors(self.envelope()))

    def test_malformed_git_identity_is_rejected(self):
        value = self.envelope()
        value["engine_manifest"]["freeze_commit"]["value"] = "not-a-git-object"
        self.assertTrue(self.envelope_errors(value))

    def test_git_algorithm_discriminator_does_not_bind_digest_length(self):
        sha1_labeled_as_sha256 = self.envelope()
        sha1_labeled_as_sha256["engine_manifest"]["freeze_commit"] = {
            "algorithm": "git-sha256",
            "value": FREEZE,
        }
        self.assertEqual([], self.envelope_errors(sha1_labeled_as_sha256))

        sha256_labeled_as_sha1 = self.envelope()
        sha256_labeled_as_sha1["engine_manifest"]["freeze_commit"] = {
            "algorithm": "git-sha1",
            "value": ZERO,
        }
        self.assertEqual([], self.envelope_errors(sha256_labeled_as_sha1))

    def test_authoritative_envelope_has_no_canonical_input_or_generation_binding(self):
        required = set(self.envelope_schema["required"])
        properties = set(self.envelope_schema["properties"])
        for name in ("input", "repository", "runtime", "repository_generation", "runtime_generation"):
            self.assertNotIn(name, required)
            self.assertNotIn(name, properties)
        self.assertEqual([], self.envelope_errors(self.envelope()))

    def test_schema_rejects_basic_impossible_output_pairs(self):
        deny = self.envelope()
        deny["normalized_output"]["operation"] = "CAPITAL_MUTATION"
        self.assertTrue(self.envelope_errors(deny))

        dispatch = self.envelope()
        dispatch_mapping = copy.deepcopy(dispatch["raw_output"]["mapping"])
        dispatch_mapping["decision"] = "DISPATCH"
        dispatch_mapping["operation"] = "STATE_READ"
        dispatch["raw_output"]["mapping"] = dispatch_mapping
        dispatch["normalized_output"]["decision"] = "DISPATCH"
        dispatch["normalized_output"]["operation"] = None
        self.assertTrue(self.envelope_errors(dispatch))

    def test_cross_field_output_contradictions_remain_schema_valid(self):
        value = self.envelope()
        value["normalized_output"]["reason"] = "different reason"
        value["normalized_output"]["decision_id"] = "D-different"
        value["normalized_output"]["task_id"] = "T-OTHER"
        self.assertEqual([], self.envelope_errors(value))

    def test_directory_and_absence_shapes_cannot_encode_declared_context(self):
        variants = self.envelope_schema["$defs"]["artifact"]["oneOf"]
        absent = next(item for item in variants if item["properties"]["kind"].get("const") == "ABSENT")
        directory = next(
            item for item in variants if item["properties"]["kind"].get("const") == "DIRECTORY"
        )
        self.assertNotIn("scope", absent["properties"])
        member_properties = directory["properties"]["members"]["items"]["properties"]
        self.assertNotIn("kind", member_properties)

    def test_verification_result_accepts_contradictory_authorization(self):
        impossible = [
            {
                "historical_status": "INVALID",
                "currentness_status": "CURRENT",
                "runtime_compatibility": "MATCH",
                "authorizing_use": "ALLOW",
                "reason_codes": [],
            },
            {
                "historical_status": "HISTORICALLY_VALID",
                "currentness_status": "STALE",
                "runtime_compatibility": "MATCH",
                "authorizing_use": "ALLOW",
                "reason_codes": [],
            },
            {
                "historical_status": "HISTORICALLY_VALID",
                "currentness_status": "CURRENT",
                "runtime_compatibility": "WRONG_RUNTIME",
                "authorizing_use": "ALLOW",
                "reason_codes": [],
            },
        ]
        for result in impossible:
            with self.subTest(result=result):
                self.assertEqual([], list(self.result_validator.iter_errors(result)))

    def test_evidence_payloads_reject_operational_smuggling_and_bound_note(self):
        smuggled = {
            "operation": "REPORT_BLOCKED",
            "blocker_code": "BLOCKED",
            "evidence_digests": [],
            "note": "bounded",
            "command": "execute",
        }
        self.assertTrue(list(self.payload_validator.iter_errors(smuggled)))
        oversized = copy.deepcopy(smuggled)
        oversized.pop("command")
        oversized["note"] = "x" * 1025
        self.assertTrue(list(self.payload_validator.iter_errors(oversized)))


if __name__ == "__main__":
    unittest.main()
