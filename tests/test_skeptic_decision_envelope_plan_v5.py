"""Characterization probes for the Envelope v5 planning package.

These probes preserve the independent H-M0-059 findings. They do not define
the desired successor contract and must not be weakened to follow one.
"""
from __future__ import annotations

import copy
import json
import unittest
import warnings
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker, RefResolver


ROOT = Path(__file__).resolve().parents[1]
FREEZE = "bc3a40924ca580ca6eddc4c24e32ff99ddd95330"
ZERO = "0" * 64


class SkepticDecisionEnvelopePlanV5(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        schema_path = ROOT / "schemas/m0-2-decision-evidence-envelope.v5.schema.json"
        cls.envelope_schema = json.loads(schema_path.read_text())
        cls.engine_schema = json.loads(
            (ROOT / "schemas/m0-2-engine-distribution.v1.schema.json").read_text()
        )
        cls.result_schema = json.loads(
            (ROOT / "schemas/m0-2-decision-evidence-verification-result.v2.schema.json").read_text()
        )
        for schema in (cls.envelope_schema, cls.engine_schema, cls.result_schema):
            Draft202012Validator.check_schema(schema)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            resolver = RefResolver(
                base_uri=schema_path.parent.resolve().as_uri() + "/",
                referrer=cls.envelope_schema,
            )
        cls.envelope_validator = Draft202012Validator(
            cls.envelope_schema,
            resolver=resolver,
            format_checker=FormatChecker(),
        )
        cls.result_validator = Draft202012Validator(cls.result_schema)

    def git_observations(self) -> dict:
        return {
            "head": {"algorithm": "git-sha1", "value": FREEZE},
            "origin_main": {"algorithm": "git-sha1", "value": FREEZE},
            "origin_url": "https://github.com/dylanlaewe/EdgeLab.git",
            "head_reachable": True,
            "repository_identity": "EdgeLab",
        }

    def envelope(self) -> dict:
        git = self.git_observations()
        return {
            "schema_version": 5,
            "canonical_input_bundle": {
                "task_id": "T-SYNTHETIC",
                "attempt": 1,
                "intent": {},
                "assignment_head": "",
                "handoff_head": "",
                "writer_claim": {},
                "project_artifact_id": "",
                "stop_inventory_id": "",
                "dependency_artifact_id": "",
                "capability_artifact_id": "",
                "repository_identity": {},
                "directory_inventory_ids": [],
                "git_observations": copy.deepcopy(git),
                "evaluation_time": "Z",
            },
            "canonical_input_sha256": ZERO,
            "historical_git_observations": copy.deepcopy(git),
            "runtime_binding": {
                "runtime_id": "",
                "attachment_id": "",
                "repository_generation": 0,
                "runtime_generation": 0,
                "scheduler_generation": 0,
                "dispatch_generation": 0,
                "task_fence": 0,
            },
            "artifacts": [{}],
            "engine_distribution": {
                "distribution_id": "D",
                "python": {"implementation": "", "version": ""},
                "dependencies": [{"name": "", "version": ""}],
                "local_artifact_ids": [""],
                "launcher_artifact_id": "",
                "clock_shim_artifact_id": "",
                "git_shim_artifact_id": "",
                "import_manifest_id": "",
                "validation_manifest_id": "",
                "working_directory": "",
                "module_search_path": [""],
                "allowed_environment": ["PYTHONPATH=/current/mutable/checkout"],
            },
            "raw_output": {
                "mapping": {},
                "canonical_bytes_base64": "",
                "byte_length": 1,
                "sha256": ZERO,
            },
            "normalized_output": {},
            "envelope_sha256": ZERO,
        }

    def envelope_errors(self, value: dict) -> list:
        return list(self.envelope_validator.iter_errors(value))

    def test_empty_authority_bearing_objects_are_schema_valid(self):
        self.assertEqual([], self.envelope_errors(self.envelope()))

    def test_arbitrary_artifact_and_caller_authority_are_schema_valid(self):
        value = self.envelope()
        value["artifacts"] = [
            {
                "kind": "FILE",
                "caller_verified": True,
                "operation": "CAPITAL_MUTATION",
            }
        ]
        self.assertEqual([], self.envelope_errors(value))

    def test_raw_and_normalized_operational_smuggling_are_schema_valid(self):
        value = self.envelope()
        value["raw_output"]["mapping"] = {
            "decision": "DENY",
            "execution_adapter": "LIVE",
            "operation": "CAPITAL_MUTATION",
            "extra_authority": True,
        }
        value["normalized_output"] = {
            "decision": "DISPATCH",
            "execution_adapter": "LIVE",
            "operation": "CAPITAL_MUTATION",
            "verified": True,
        }
        self.assertEqual([], self.envelope_errors(value))

    def test_canonical_input_omits_declared_expected_operation_and_generations(self):
        required = set(
            self.envelope_schema["properties"]["canonical_input_bundle"]["required"]
        )
        for field in (
            "expected_operation",
            "runtime_id",
            "attachment_id",
            "repository_generation",
            "runtime_generation",
            "scheduler_generation",
            "dispatch_generation",
            "task_fence",
        ):
            self.assertNotIn(field, required)

    def test_git_identity_discriminator_binds_algorithm_to_length(self):
        self.assertEqual([], self.envelope_errors(self.envelope()))
        mislabeled_sha1 = self.envelope()
        mislabeled_sha1["historical_git_observations"]["head"] = {
            "algorithm": "git-sha256",
            "value": FREEZE,
        }
        self.assertTrue(self.envelope_errors(mislabeled_sha1))
        mislabeled_sha256 = self.envelope()
        mislabeled_sha256["historical_git_observations"]["head"] = {
            "algorithm": "git-sha1",
            "value": ZERO,
        }
        self.assertTrue(self.envelope_errors(mislabeled_sha256))

    def test_all_unsafe_allow_combinations_are_rejected(self):
        safe = {
            "historical_status": "VALID",
            "currentness_status": "CURRENT",
            "target_runtime_compatible": True,
            "verifier_status": "PASS",
            "exact_generation_match": True,
            "authorizing_use": "ALLOW",
            "reason_code": "NONE",
        }
        self.assertEqual([], list(self.result_validator.iter_errors(safe)))
        mutations = (
            ("historical_status", "INVALID"),
            ("currentness_status", "STALE"),
            ("target_runtime_compatible", False),
            ("verifier_status", "FAIL"),
            ("exact_generation_match", False),
            ("currentness_status", "UNKNOWN"),
        )
        for field, invalid_value in mutations:
            value = copy.deepcopy(safe)
            value[field] = invalid_value
            with self.subTest(field=field, invalid_value=invalid_value):
                self.assertTrue(list(self.result_validator.iter_errors(value)))

    def test_reason_code_can_contradict_denial_status(self):
        contradictory = [
            {
                "historical_status": "INVALID",
                "currentness_status": "CURRENT",
                "target_runtime_compatible": True,
                "verifier_status": "FAIL",
                "exact_generation_match": True,
                "authorizing_use": "DENY",
                "reason_code": "NONE",
            },
            {
                "historical_status": "VALID",
                "currentness_status": "STALE",
                "target_runtime_compatible": True,
                "verifier_status": "PASS",
                "exact_generation_match": False,
                "authorizing_use": "DENY",
                "reason_code": "WRONG_RUNTIME",
            },
        ]
        for value in contradictory:
            with self.subTest(value=value):
                self.assertEqual([], list(self.result_validator.iter_errors(value)))

    def test_engine_distribution_has_no_immutable_external_dependency_artifacts(self):
        properties = self.engine_schema["properties"]
        dependency_properties = properties["dependencies"]["items"]["properties"]
        self.assertEqual({"name", "version"}, set(dependency_properties))
        self.assertNotIn("artifact_id", dependency_properties)
        self.assertNotIn("sha256", dependency_properties)

    def test_v8_drops_v7_actor_claim_and_idempotency_preconditions(self):
        v7 = (ROOT / "docs/M0.3A_TRANSACTIONAL_CONTRACT.v7.md").read_text()
        v8 = (ROOT / "docs/M0.3A_TRANSACTIONAL_CONTRACT.v8.md").read_text()
        for phrase in ("original actor fixture", "closed claim id/fence", "unique idempotency key"):
            self.assertIn(phrase, v7)
            self.assertNotIn(phrase, v8)


if __name__ == "__main__":
    unittest.main()
