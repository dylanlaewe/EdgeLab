"""Characterization probes for the Envelope v7 planning package.

These probes preserve the independent H-M0-063 findings. They do not define
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


class SkepticDecisionEnvelopePlanV7(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        schemas = ROOT / "schemas"
        envelope_path = schemas / "m0-2-decision-evidence-envelope.v7.schema.json"
        cls.envelope_schema = json.loads(envelope_path.read_text())
        cls.blob_schema = json.loads((schemas / "m0-2-blob.v1.schema.json").read_text())
        cls.git_schema = json.loads(
            (schemas / "m0-2-git-observation.v1.schema.json").read_text()
        )
        cls.engine_schema = json.loads(
            (schemas / "m0-2-engine-distribution.v2.schema.json").read_text()
        )
        cls.artifact_schema = json.loads(
            (schemas / "m0-2-evidence-artifacts.v1.schema.json").read_text()
        )
        cls.import_schema = json.loads(
            (schemas / "m0-2-import-manifest.v1.schema.json").read_text()
        )
        cls.validation_schema = json.loads(
            (schemas / "m0-2-validation-manifest.v1.schema.json").read_text()
        )
        cls.result_schema = json.loads(
            (schemas / "m0-2-decision-evidence-verification-result.v2.schema.json").read_text()
        )
        for schema in (
            cls.envelope_schema,
            cls.blob_schema,
            cls.git_schema,
            cls.engine_schema,
            cls.artifact_schema,
            cls.import_schema,
            cls.validation_schema,
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
        cls.blob_validator = Draft202012Validator(cls.blob_schema)
        cls.git_validator = Draft202012Validator(cls.git_schema)
        cls.engine_validator = Draft202012Validator(cls.engine_schema)
        cls.artifact_validator = Draft202012Validator(cls.artifact_schema)
        cls.result_validator = Draft202012Validator(cls.result_schema)

    def git_observation(self) -> dict:
        git = {"algorithm": "git-sha1", "value": FREEZE}
        return {
            "observation_id": "G-1",
            "repository_id": "EdgeLab",
            "head": copy.deepcopy(git),
            "origin_main": copy.deepcopy(git),
            "origin_url": "https://github.com/dylanlaewe/EdgeLab.git",
            "ancestry_left": copy.deepcopy(git),
            "ancestry_right": copy.deepcopy(git),
            "head_reachable": True,
            "observation_sha256": ZERO,
        }

    def engine_distribution(self) -> dict:
        return {
            "distribution_id": "ED-1",
            "distribution_sha256": ZERO,
            "python_version": "3.13.7",
            "local_artifact_ids": ["ART-1"],
            "import_manifest_id": "IM-1",
            "validation_manifest_id": "VM-1",
            "launcher_artifact_id": "ART-1",
            "clock_shim_artifact_id": "ART-1",
            "git_shim_artifact_id": "ART-1",
            "working_directory": "replay/root",
            "module_search_path": ["replay/root/src"],
            "environment": {"PYTHONHASHSEED": "0", "LC_ALL": "C.UTF-8"},
            "external_packages": [
                {
                    "name": "jsonschema",
                    "version": "4.25.1",
                    "source_type": "wheel",
                    "artifact_blob_id": ZERO,
                    "artifact_sha256": ZERO,
                    "platform": "any",
                }
            ],
        }

    def envelope(self) -> dict:
        return {
            "schema_version": 7,
            "canonical_input_bundle": {},
            "project_binding": {
                "record_id": "PROJECT",
                "version": 1,
                "head_sha256": ZERO,
                "live_status": "LOCKED",
                "source_artifact_id": "ART-1",
            },
            "stop_binding": {
                "inventory_artifact_id": "ART-1",
                "inventory_sha256": ZERO,
                "records": [
                    {"stop_id": "STOP-M0-001", "status": "OPEN", "artifact_id": "ART-1"}
                ],
            },
            "dependency_bindings": [],
            "capability_bindings": [],
            "blobs": [
                {
                    "blob_id": ZERO,
                    "algorithm": "sha256",
                    "digest": ZERO,
                    "byte_length": 2,
                    "encoding": "base64",
                    "content_base64": "e30=",
                }
            ],
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
            "source_manifest": {
                "manifest_id": "SM-1",
                "version": 1,
                "source_artifact_ids": ["ART-1"],
                "inventory_ids": [],
                "absence_artifact_ids": [],
                "canonical_input_sha256": ZERO,
                "source_set_sha256": ZERO,
            },
            "git_observation": self.git_observation(),
            "engine_distribution": self.engine_distribution(),
            "raw_output": {},
            "normalized_output": {},
            "envelope_sha256": ZERO,
        }

    def envelope_errors(self, value: dict) -> list:
        return list(self.envelope_validator.iter_errors(value))

    def test_canonical_raw_and_normalized_authority_objects_are_unrestricted(self):
        value = self.envelope()
        value["canonical_input_bundle"] = {
            "verified": True,
            "operation": "CAPITAL_MUTATION",
        }
        value["raw_output"] = {"execution_adapter": "LIVE", "operation": "CAPITAL_MUTATION"}
        value["normalized_output"] = {"decision": "DISPATCH", "verified": True}
        self.assertEqual([], self.envelope_errors(value))

    def test_project_binding_omits_frozen_phase_status_and_declared_capital(self):
        properties = self.envelope_schema["properties"]["project_binding"]["properties"]
        self.assertNotIn("phase", properties)
        self.assertNotIn("status", properties)
        self.assertNotIn("capital", properties)

    def test_dependency_binding_has_no_task_artifact_or_record_version(self):
        properties = self.envelope_schema["properties"]["dependency_bindings"]["items"][
            "properties"
        ]
        self.assertNotIn("task_artifact_id", properties)
        self.assertNotIn("record_version", properties)

    def test_blob_schema_rejects_empty_and_operational_fields(self):
        self.assertTrue(list(self.blob_validator.iter_errors({})))
        blob = self.envelope()["blobs"][0]
        blob["operation"] = "CAPITAL_MUTATION"
        self.assertTrue(list(self.blob_validator.iter_errors(blob)))

    def test_git_identity_is_discriminated_but_ancestry_consistency_is_semantic(self):
        observation = self.git_observation()
        observation["ancestry_left"] = {
            "algorithm": "git-sha1",
            "value": "1" * 40,
        }
        observation["ancestry_right"] = {
            "algorithm": "git-sha1",
            "value": "2" * 40,
        }
        self.assertEqual([], list(self.git_validator.iter_errors(observation)))

    def test_engine_schema_accepts_traversal_workdir_and_missing_fixed_environment(self):
        engine = self.engine_distribution()
        engine["working_directory"] = "replay/../../current-checkout"
        engine["module_search_path"] = ["replay/../../current-checkout/src"]
        engine["environment"] = {}
        self.assertEqual([], list(self.engine_validator.iter_errors(engine)))
        engine["working_directory"] = 42
        self.assertEqual([], list(self.engine_validator.iter_errors(engine)))

    def test_external_packages_have_immutable_artifact_identity(self):
        required = set(
            self.engine_schema["properties"]["external_packages"]["items"]["required"]
        )
        self.assertTrue(
            {"name", "version", "source_type", "artifact_blob_id", "artifact_sha256", "platform"}
            <= required
        )

    def test_manifests_still_do_not_map_modules_or_schemas_to_artifacts(self):
        import_properties = json.loads(
            (ROOT / "schemas/m0-2-import-manifest.v1.schema.json").read_text()
        )["properties"]
        validation_properties = json.loads(
            (ROOT / "schemas/m0-2-validation-manifest.v1.schema.json").read_text()
        )["properties"]
        self.assertNotIn("local_module_artifacts", import_properties)
        self.assertNotIn("external_distribution_artifacts", import_properties)
        self.assertNotIn("entry_schema_artifacts", validation_properties)
        self.assertNotIn("recursive_schema_artifacts", validation_properties)

    def test_stage1_dependency_fixture_omits_directly_loaded_schemas_and_its_digest(self):
        closure = json.loads(
            (ROOT / "docs/M0.2_STAGE1_DEPENDENCY_CLOSURE.v1.json").read_text()
        )
        required = {
            "scheduler-state.schema.json",
            "orchestration-task.schema.json",
            "project-state.schema.json",
            "stop.schema.json",
            "capability-registry.schema.json",
            "handoff.schema.json",
        }
        observed = set(closure["schema_dependencies"])
        self.assertEqual(
            {
                "project-state.schema.json",
                "stop.schema.json",
                "capability-registry.schema.json",
                "handoff.schema.json",
            },
            required - observed,
        )
        self.assertNotIn("digest", closure)

    def test_directory_other_remains_schema_valid_despite_v7_prohibition(self):
        directory = {
            "kind": "DIRECTORY",
            "artifact_id": "DIR-1",
            "inventory_id": "I-1",
            "source_id": "SRC-DIR",
            "root": "docs/handoffs",
            "selection_rule": "*.json",
            "members": [
                {
                    "member_kind": "OTHER",
                    "relative_path": "unexpected.json",
                    "artifact_id": "OTHER-1",
                    "raw_sha256": ZERO,
                }
            ],
            "inventory_sha256": ZERO,
        }
        self.assertEqual([], list(self.artifact_validator.iter_errors(directory)))

    def test_v9_still_adopts_superseded_v6_instead_of_v7(self):
        text = (ROOT / "docs/M0.3A_TRANSACTIONAL_CONTRACT.v9.md").read_text()
        self.assertIn("adopts Envelope v6", text)
        self.assertNotIn("adopts Envelope v7", text)

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


if __name__ == "__main__":
    unittest.main()
