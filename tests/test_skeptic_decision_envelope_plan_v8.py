"""Characterization probes for the Envelope v8 planning package.

These probes preserve the independent H-M0-065 findings. They do not define
the desired successor contract and do not modify the frozen Stage 1 engine.
"""
from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
FREEZE = "bc3a40924ca580ca6eddc4c24e32ff99ddd95330"
ZERO = "0" * 64


def load(name: str) -> dict:
    return json.loads((ROOT / name).read_text())


class SkepticDecisionEnvelopePlanV8(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.envelope = load("schemas/m0-2-decision-evidence-envelope.v8.schema.json")
        cls.artifact = load("schemas/m0-2-evidence-artifacts.v1.schema.json")
        cls.engine = load("schemas/m0-2-engine-distribution.v2.schema.json")
        cls.import_manifest = load("schemas/m0-2-import-manifest.v2.schema.json")
        cls.validation_manifest = load("schemas/m0-2-validation-manifest.v2.schema.json")
        cls.verification_result = load(
            "schemas/m0-2-decision-evidence-verification-result.v2.schema.json"
        )
        for schema in (
            cls.envelope,
            cls.artifact,
            cls.engine,
            cls.import_manifest,
            cls.validation_manifest,
            cls.verification_result,
        ):
            Draft202012Validator.check_schema(schema)

    def test_frozen_stage1_sources_are_byte_identical(self) -> None:
        changed = subprocess.run(
            [
                "git",
                "diff",
                "--name-only",
                FREEZE,
                "--",
                "src/edgelab/orchestration.py",
                "src/edgelab/validate.py",
                "src/edgelab/data_integrity.py",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=True,
        ).stdout.strip()
        self.assertEqual(changed, "")

    def test_v8_raw_deny_rejects_the_frozen_stage1_shape(self) -> None:
        # orchestration.decision() lines 288-296 return exactly these fields.
        frozen_deny = {
            "decision": "DENY",
            "decision_id": "D-" + "0" * 32,
            "task_id": None,
            "reason": "synthetic denial",
            "execution_adapter": "MOCK_ONLY",
        }
        deny = self.envelope["$defs"]["deny"]
        self.assertFalse(Draft202012Validator(deny).is_valid(frozen_deny))
        frozen_deny["operation"] = None
        self.assertTrue(Draft202012Validator(deny).is_valid(frozen_deny))

    def test_accepted_closure_digest_does_not_recompute(self) -> None:
        fixture = load("docs/M0.2_STAGE1_DEPENDENCY_CLOSURE.v2.json")
        claimed = fixture.pop("closure_sha256")
        canonical = json.dumps(
            fixture, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
        self.assertNotEqual(claimed, hashlib.sha256(canonical).hexdigest())

    def test_direct_stage1_schemas_are_now_listed(self) -> None:
        fixture = load("docs/M0.2_STAGE1_DEPENDENCY_CLOSURE.v2.json")
        expected = {
            "scheduler-state.schema.json",
            "orchestration-task.schema.json",
            "project-state.schema.json",
            "stop.schema.json",
            "capability-registry.schema.json",
            "handoff.schema.json",
        }
        self.assertLessEqual(expected, set(fixture["schema_dependencies"]))

    def test_directory_other_remains_structurally_valid(self) -> None:
        directory = {
            "kind": "DIRECTORY",
            "artifact_id": "directory-1",
            "inventory_id": "inventory-1",
            "source_id": "source-1",
            "root": "replay/root",
            "selection_rule": "all",
            "members": [
                {
                    "member_kind": "OTHER",
                    "relative_path": "mystery",
                    "artifact_id": "other-1",
                    "raw_sha256": ZERO,
                }
            ],
            "inventory_sha256": ZERO,
        }
        self.assertTrue(Draft202012Validator(self.artifact).is_valid(directory))

    def _engine_fixture(self) -> dict:
        return {
            "distribution_id": "dist-1",
            "distribution_sha256": ZERO,
            "python_version": "3.12.0",
            "local_artifact_ids": ["module-1"],
            "import_manifest_id": "imports-1",
            "validation_manifest_id": "validation-1",
            "launcher_artifact_id": "launcher-1",
            "clock_shim_artifact_id": "clock-1",
            "git_shim_artifact_id": "git-1",
            "working_directory": "replay/root",
            "module_search_path": ["replay/modules"],
            "environment": {},
            "external_packages": [
                {
                    "name": "jsonschema",
                    "version": "1.0",
                    "source_type": "wheel",
                    "artifact_blob_id": ZERO,
                    "artifact_sha256": ZERO,
                    "platform": "any",
                }
            ],
        }

    def test_engine_accepts_non_string_and_traversal_workdirs(self) -> None:
        validator = Draft202012Validator(self.engine)
        for value in (1, None, {}, []):
            engine = self._engine_fixture()
            engine["working_directory"] = value
            self.assertTrue(validator.is_valid(engine), value)
        engine = self._engine_fixture()
        engine["working_directory"] = "replay/../../current-checkout"
        engine["module_search_path"] = ["replay/../../current-checkout"]
        self.assertTrue(validator.is_valid(engine))

    def test_external_distribution_ids_have_no_engine_target(self) -> None:
        external_import = self.import_manifest["properties"]["external_imports"][
            "items"
        ]["properties"]
        package = self.engine["properties"]["external_packages"]["items"][
            "properties"
        ]
        self.assertIn("distribution_id", external_import)
        self.assertNotIn("distribution_id", package)
        self.assertNotIn(
            "distribution_id",
            self.engine["properties"]["external_packages"]["items"]["required"],
        )

    def test_absent_digest_is_not_structurally_bound_to_authority(self) -> None:
        absent = {
            "kind": "ABSENT",
            "artifact_id": "absent-1",
            "source_id": "source-1",
            "expected_path": "replay/missing.json",
            "inventory_id": "inventory-1",
            "source_class": "task",
            "assertion_sha256": ZERO,
            "absence_context": "not present",
        }
        validator = Draft202012Validator(self.artifact)
        self.assertTrue(validator.is_valid(absent))
        altered = copy.deepcopy(absent)
        altered.update(
            expected_path="replay/different.json",
            inventory_id="inventory-2",
            source_class="capability",
            absence_context="different context",
        )
        self.assertTrue(validator.is_valid(altered))
        self.assertEqual(absent["assertion_sha256"], altered["assertion_sha256"])

    def test_canonical_input_omits_consumed_primary_authority_bindings(self) -> None:
        properties = self.envelope["$defs"]["input"]["properties"]
        required = set(self.envelope["$defs"]["input"]["required"])
        for field in (
            "task_artifact_id",
            "task_version",
            "task_head_sha256",
            "scheduler_state_artifact_id",
            "handoff_binding_artifact_id",
        ):
            self.assertNotIn(field, properties)
            self.assertNotIn(field, required)

    def test_dependencies_do_not_encode_required_current_relationship(self) -> None:
        dependency = self.envelope["$defs"]["input"]["properties"][
            "dependencies"
        ]["items"]
        properties = dependency["properties"]
        for field in (
            "required_head_sha256",
            "current_head_sha256",
            "required_completion_head_sha256",
            "current_completion_head_sha256",
        ):
            self.assertNotIn(field, properties)

    def test_envelope_has_no_raw_output_byte_binding(self) -> None:
        properties = self.envelope["properties"]
        for field in (
            "raw_output_blob_id",
            "raw_output_byte_length",
            "raw_output_sha256",
            "raw_output_content_base64",
        ):
            self.assertNotIn(field, properties)

    def test_deny_with_none_reason_remains_structurally_valid(self) -> None:
        contradictory = {
            "historical_status": "VALID",
            "currentness_status": "CURRENT",
            "target_runtime_compatible": True,
            "verifier_status": "PASS",
            "exact_generation_match": True,
            "authorizing_use": "DENY",
            "reason_code": "NONE",
        }
        self.assertTrue(
            Draft202012Validator(self.verification_result).is_valid(contradictory)
        )


if __name__ == "__main__":
    unittest.main()
