"""Characterization probes for the Envelope v6 planning package.

These probes preserve the independent H-M0-061 findings. They do not define
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


class SkepticDecisionEnvelopePlanV6(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        schemas = ROOT / "schemas"
        envelope_path = schemas / "m0-2-decision-evidence-envelope.v6.schema.json"
        cls.envelope_schema = json.loads(envelope_path.read_text())
        cls.artifact_schema = json.loads(
            (schemas / "m0-2-evidence-artifacts.v1.schema.json").read_text()
        )
        cls.engine_schema = json.loads(
            (schemas / "m0-2-engine-distribution.v1.schema.json").read_text()
        )
        cls.import_schema = json.loads(
            (schemas / "m0-2-import-manifest.v1.schema.json").read_text()
        )
        cls.result_schema = json.loads(
            (schemas / "m0-2-decision-evidence-verification-result.v2.schema.json").read_text()
        )
        for schema in (
            cls.envelope_schema,
            cls.artifact_schema,
            cls.engine_schema,
            cls.import_schema,
            cls.result_schema,
        ):
            Draft202012Validator.check_schema(schema)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            resolver = RefResolver(
                base_uri=envelope_path.parent.resolve().as_uri() + "/",
                referrer=cls.envelope_schema,
            )
        cls.envelope_validator = Draft202012Validator(
            cls.envelope_schema,
            resolver=resolver,
            format_checker=FormatChecker(),
        )
        cls.artifact_validator = Draft202012Validator(cls.artifact_schema)
        cls.engine_validator = Draft202012Validator(cls.engine_schema)
        cls.result_validator = Draft202012Validator(cls.result_schema)

    def envelope(self) -> dict:
        return {
            "schema_version": 6,
            "canonical_input_bundle": {
                "task_id": "T-SYNTHETIC",
                "attempt": 1,
                "intent": {"task_id": "T-SYNTHETIC", "attempt": 1},
                "expected_operation": None,
                "assignment_id": "A-1",
                "assignment_head_sha256": ZERO,
                "assignment_record_version": 1,
                "handoff_id": "H-1",
                "handoff_head_sha256": ZERO,
                "handoff_record_version": 1,
                "claim_fixture_id": "F-1",
                "claim_state": "ACTIVE",
                "generation_vector": {
                    "repository": 0,
                    "runtime": 0,
                    "scheduler": 0,
                    "dispatch": 0,
                    "fence": 0,
                    "assignment": 0,
                    "handoff": 0,
                    "claim": 0,
                },
                "repository_id": "EdgeLab",
                "runtime_id": "R-1",
                "attachment_id": "AT-1",
                "inventory_ids": ["I-1"],
                "git_observation_id": "G-1",
                "evaluation_time": "2026-10-06T18:00:00Z",
            },
            "canonical_input_sha256": ZERO,
            "artifacts": [
                {
                    "kind": "FILE",
                    "artifact_id": "ART-1",
                    "source_id": "SRC-1",
                    "source_class": "PROJECT",
                    "path": "docs/project-state.json",
                    "blob_id": ZERO,
                    "raw_byte_length": 2,
                    "raw_sha256": ZERO,
                    "media_type": "application/json",
                    "provenance_id": "P-1",
                }
            ],
            "blobs": [{}],
            "source_manifest": {
                "manifest_id": "SM-1",
                "version": 1,
                "source_artifact_ids": ["ART-1"],
                "inventory_ids": [],
                "absence_artifact_ids": [],
                "canonical_input_sha256": ZERO,
                "source_set_sha256": ZERO,
            },
            "import_manifest": {
                "manifest_id": "IM-1",
                "version": 1,
                "root_modules": ["edgelab.orchestration"],
                "local_modules": ["edgelab.orchestration"],
                "external_distributions": ["jsonschema"],
                "decision_critical_imports": ["edgelab.orchestration"],
                "digest": ZERO,
            },
            "validation_manifest": {
                "manifest_id": "VM-1",
                "version": 1,
                "entry_schema_ids": ["scheduler-state"],
                "recursive_schema_ids": ["scheduler-state"],
                "validator_distribution": "jsonschema",
                "canonicalizer_artifact_id": "ART-1",
                "digest": ZERO,
            },
            "raw_output": {
                "decision": "DENY",
                "decision_id": "D-1",
                "task_id": "T-SYNTHETIC",
                "reason": "denied",
                "execution_adapter": "MOCK_ONLY",
                "operation": None,
                "canonical_bytes_base64": "e30=",
                "byte_length": 2,
                "sha256": ZERO,
            },
            "normalized_output": {
                "decision": "DENY",
                "decision_id": "D-1",
                "task_id": "T-SYNTHETIC",
                "reason": "denied",
                "execution_adapter": "MOCK_ONLY",
                "operation": None,
            },
            "envelope_sha256": ZERO,
        }

    def envelope_errors(self, value: dict) -> list:
        return list(self.envelope_validator.iter_errors(value))

    def test_arbitrary_blob_and_operational_smuggling_are_schema_valid(self):
        value = self.envelope()
        value["blobs"] = [{"verified": True, "operation": "CAPITAL_MUTATION"}]
        self.assertEqual([], self.envelope_errors(value))

    def test_declared_authority_bindings_are_absent_from_envelope_schema(self):
        envelope_properties = set(self.envelope_schema["properties"])
        canonical_properties = set(
            self.envelope_schema["properties"]["canonical_input_bundle"]["properties"]
        )
        self.assertNotIn("engine_distribution", envelope_properties)
        self.assertNotIn("git_observations", envelope_properties)
        for name in (
            "project_artifact_id",
            "stop_inventory_id",
            "dependency_artifact_id",
            "capability_artifact_id",
        ):
            self.assertNotIn(name, canonical_properties)

    def test_artifact_union_rejects_empty_unknown_and_operational_fields(self):
        for artifact in (
            {},
            {"kind": "UNKNOWN"},
            {
                "kind": "FILE",
                "artifact_id": "A",
                "source_id": "S",
                "source_class": "PROJECT",
                "path": "p",
                "blob_id": ZERO,
                "raw_byte_length": 0,
                "raw_sha256": ZERO,
                "media_type": "x",
                "provenance_id": "P",
                "operation": "CAPITAL_MUTATION",
            },
        ):
            with self.subTest(artifact=artifact):
                self.assertTrue(list(self.artifact_validator.iter_errors(artifact)))

    def test_directory_other_member_has_no_resolvable_other_artifact_variant(self):
        member_kinds = set(
            self.artifact_schema["$defs"]["directory"]["properties"]["members"]
            ["items"]["properties"]["member_kind"]["enum"]
        )
        variants = {
            item["$ref"].rsplit("/", 1)[-1] for item in self.artifact_schema["oneOf"]
        }
        self.assertIn("OTHER", member_kinds)
        self.assertNotIn("other", variants)

    def test_raw_and_normalized_impossible_pairs_are_structurally_valid(self):
        deny = self.envelope()
        deny["raw_output"]["operation"] = "CAPITAL_MUTATION"
        deny["normalized_output"]["operation"] = "CAPITAL_MUTATION"
        self.assertEqual([], self.envelope_errors(deny))

        dispatch = self.envelope()
        dispatch["raw_output"]["decision"] = "DISPATCH"
        dispatch["normalized_output"]["decision"] = "DISPATCH"
        self.assertEqual([], self.envelope_errors(dispatch))

    def test_invalid_timestamp_and_base64_are_structurally_valid(self):
        value = self.envelope()
        value["canonical_input_bundle"]["evaluation_time"] = "2026-99-99T99:99:99Z"
        value["raw_output"]["canonical_bytes_base64"] = "not base64!"
        self.assertEqual([], self.envelope_errors(value))

    def test_engine_schema_still_accepts_mutable_and_empty_distribution(self):
        engine = {
            "distribution_id": "D",
            "python": {"implementation": "", "version": ""},
            "dependencies": [{"name": "", "version": ""}],
            "local_artifact_ids": [""],
            "launcher_artifact_id": "",
            "clock_shim_artifact_id": "",
            "git_shim_artifact_id": "",
            "import_manifest_id": "",
            "validation_manifest_id": "",
            "working_directory": "/current/mutable/checkout",
            "module_search_path": ["/current/mutable/checkout/src"],
            "allowed_environment": ["PYTHONPATH=/current/mutable/checkout/src"],
        }
        self.assertEqual([], list(self.engine_validator.iter_errors(engine)))
        dependency_properties = self.engine_schema["properties"]["dependencies"]["items"][
            "properties"
        ]
        self.assertNotIn("artifact_id", dependency_properties)
        self.assertNotIn("sha256", dependency_properties)

    def test_import_manifest_does_not_bind_modules_to_artifacts(self):
        properties = self.import_schema["properties"]
        self.assertNotIn("local_module_artifacts", properties)
        self.assertNotIn("external_distribution_artifacts", properties)
        self.assertEqual({"type", "minItems", "uniqueItems", "items"}, set(properties["local_modules"]))

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
        for field, unsafe in (
            ("historical_status", "INVALID"),
            ("currentness_status", "STALE"),
            ("target_runtime_compatible", False),
            ("verifier_status", "FAIL"),
            ("exact_generation_match", False),
            ("currentness_status", "UNKNOWN"),
        ):
            value = copy.deepcopy(safe)
            value[field] = unsafe
            with self.subTest(field=field, unsafe=unsafe):
                self.assertTrue(list(self.result_validator.iter_errors(value)))

    def test_v6_omits_envelope_self_digest_algorithm(self):
        text = (ROOT / "docs/M0.2_DECISION_EVIDENCE_ENVELOPE.v6.md").read_text()
        self.assertIn("canonical_input_sha256=SHA256(CJ(bundle))", text)
        self.assertNotIn("envelope_sha256=", text)
        self.assertNotIn("envelope excluding only", text)

    def test_v9_restores_scheduler_evidence_prerequisites(self):
        text = (ROOT / "docs/M0.3A_TRANSACTIONAL_CONTRACT.v9.md").read_text()
        for phrase in (
            "original actor fixture",
            "matching already-closed claim ID/fence",
            "exact generation vector",
            "idempotency key",
            "NO_STATE_CHANGE",
            "no retry",
            "no operational authority",
        ):
            self.assertIn(phrase, text)


if __name__ == "__main__":
    unittest.main()
