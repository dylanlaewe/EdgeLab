"""Characterization probes for the Envelope v9 planning package.

These probes preserve the independent H-M0-067 findings. They do not define
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


class SkepticDecisionEnvelopePlanV9(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.envelope = load("schemas/m0-2-decision-evidence-envelope.v9.schema.json")
        cls.v8 = load("schemas/m0-2-decision-evidence-envelope.v8.schema.json")
        cls.artifact = load("schemas/m0-2-evidence-artifacts.v2.schema.json")
        cls.engine = load("schemas/m0-2-engine-distribution.v3.schema.json")
        cls.import_manifest = load("schemas/m0-2-import-manifest.v2.schema.json")
        cls.validation_manifest = load("schemas/m0-2-validation-manifest.v2.schema.json")
        cls.result = load(
            "schemas/m0-2-decision-evidence-verification-result.v2.schema.json"
        )
        for schema in (
            cls.envelope,
            cls.v8,
            cls.artifact,
            cls.engine,
            cls.import_manifest,
            cls.validation_manifest,
            cls.result,
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
                "orchestration",
                "docs/project-state.json",
                "schemas/scheduler-state.schema.json",
                "schemas/handoff.schema.json",
                "schemas/project-state.schema.json",
                "schemas/stop.schema.json",
                "schemas/capability-registry.schema.json",
                "schemas/orchestration-task.schema.json",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=True,
        ).stdout.strip()
        self.assertEqual(changed, "")

    def test_raw_deny_matches_frozen_five_field_shape(self) -> None:
        raw = {
            "decision": "DENY",
            "decision_id": "D-" + "0" * 32,
            "task_id": None,
            "reason": "synthetic denial",
            "execution_adapter": "MOCK_ONLY",
        }
        validator = Draft202012Validator(self.envelope["$defs"]["deny"])
        self.assertTrue(validator.is_valid(raw))
        raw["operation"] = "STATE_READ"
        self.assertFalse(validator.is_valid(raw))

    def test_normalized_deny_requires_null_operation(self) -> None:
        normalized = {
            "decision": "DENY",
            "decision_id": "D-" + "0" * 32,
            "task_id": None,
            "reason": "synthetic denial",
            "execution_adapter": "MOCK_ONLY",
            "operation": None,
        }
        validator = Draft202012Validator(self.envelope["$defs"]["normdeny"])
        self.assertTrue(validator.is_valid(normalized))
        normalized["operation"] = "STATE_READ"
        self.assertFalse(validator.is_valid(normalized))

    def test_raw_dispatch_matches_frozen_six_field_shape(self) -> None:
        raw = {
            "decision": "DISPATCH",
            "decision_id": "D-" + "0" * 32,
            "task_id": "T-SYNTHETIC-001",
            "reason": "repository-resolved synthetic task passed preflight",
            "execution_adapter": "MOCK_ONLY",
            "operation": "STATE_READ",
        }
        validator = Draft202012Validator(self.envelope["$defs"]["dispatch"])
        self.assertTrue(validator.is_valid(raw))
        del raw["operation"]
        self.assertFalse(validator.is_valid(raw))
        raw["operation"] = "STATE_READ"
        raw["verified"] = True
        self.assertFalse(validator.is_valid(raw))

    def test_closure_digest_recomputes_and_mutation_changes_it(self) -> None:
        fixture = load("docs/M0.2_STAGE1_DEPENDENCY_CLOSURE.v3.json")
        claimed = fixture.pop("closure_sha256")
        canonical = json.dumps(
            fixture, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
        self.assertEqual(claimed, hashlib.sha256(canonical).hexdigest())
        fixture["version"] += 1
        mutated = json.dumps(
            fixture, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
        self.assertNotEqual(claimed, hashlib.sha256(mutated).hexdigest())

    def test_v9_canonical_input_extension_is_unsatisfiable(self) -> None:
        base = self.v8["$defs"]["input"]
        base_properties = set(base["properties"])
        base_required = set(base["required"])
        extension = self.envelope["properties"]["canonical_input_bundle"]["allOf"][1]
        extension_required = set(extension["required"])
        self.assertTrue(base["additionalProperties"] is False)
        self.assertTrue(extension_required.isdisjoint(base_properties))
        self.assertTrue(extension_required.isdisjoint(base_required))

    def test_v9_top_level_omits_historical_evidence_graph(self) -> None:
        properties = set(self.envelope["properties"])
        required = {
            "canonical_input_sha256",
            "blobs",
            "artifacts",
            "source_manifest",
            "git_observation",
            "engine_distribution",
            "import_manifest",
            "validation_manifest",
            "closure_fixture",
        }
        self.assertTrue(required.isdisjoint(properties))

    def test_engine_v3_drops_replay_and_manifest_bindings(self) -> None:
        properties = set(self.engine["properties"])
        required = {
            "python_version",
            "local_artifact_ids",
            "import_manifest_id",
            "validation_manifest_id",
            "launcher_artifact_id",
            "clock_shim_artifact_id",
            "git_shim_artifact_id",
            "working_directory",
            "module_search_path",
            "environment",
        }
        self.assertTrue(required.isdisjoint(properties))

    def test_directory_other_is_structurally_rejected(self) -> None:
        directory = {
            "kind": "DIRECTORY",
            "artifact_id": "directory-1",
            "source_id": "source-1",
            "root": "replay/root",
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
        self.assertFalse(Draft202012Validator(self.artifact).is_valid(directory))

    def test_absent_schema_cannot_carry_all_digest_inputs(self) -> None:
        absent = self.artifact["oneOf"][1]
        properties = set(absent["properties"])
        self.assertNotIn("source_class", properties)
        self.assertNotIn("absence_context", properties)
        value = {
            "kind": "ABSENT",
            "artifact_id": "absent-1",
            "source_id": "source-1",
            "expected_path": "replay/missing.json",
            "inventory_id": "inventory-1",
            "absence_assertion_sha256": ZERO,
            "source_class": "TASK",
            "absence_context": "inventory scan",
        }
        self.assertFalse(Draft202012Validator(self.artifact).is_valid(value))

    def test_replay_path_schemas_still_accept_noncanonical_segments(self) -> None:
        import_path = self.import_manifest["properties"]["local_modules"]["items"][
            "properties"
        ]["replay_path"]
        validation_path = self.validation_manifest["properties"]["schemas"][
            "items"
        ]["properties"]["replay_path"]
        for schema in (import_path, validation_path):
            validator = Draft202012Validator(schema)
            self.assertTrue(validator.is_valid("replay/./module.py"))
            self.assertTrue(validator.is_valid("replay//module.py"))
            self.assertFalse(validator.is_valid("replay/../../current-checkout"))

    def test_external_closure_omits_installed_required_distribution(self) -> None:
        fixture = load("docs/M0.2_STAGE1_DEPENDENCY_CLOSURE.v3.json")
        self.assertIn("jsonschema", fixture["external_distributions"])
        self.assertNotIn(
            "jsonschema-specifications", fixture["external_distributions"]
        )

    def test_v10_still_adopts_envelope_v8(self) -> None:
        text = (ROOT / "docs/M0.3A_TRANSACTIONAL_CONTRACT.v10.md").read_text()
        self.assertIn("adopting Envelope v8", text)
        self.assertNotIn("adopting Envelope v9", text)

    def test_deny_none_reason_remains_structurally_valid(self) -> None:
        contradictory = {
            "historical_status": "VALID",
            "currentness_status": "CURRENT",
            "target_runtime_compatible": True,
            "verifier_status": "PASS",
            "exact_generation_match": True,
            "authorizing_use": "DENY",
            "reason_code": "NONE",
        }
        self.assertTrue(Draft202012Validator(self.result).is_valid(contradictory))

    def test_handoff_relationship_omits_writer_and_assignment_head(self) -> None:
        relationship = self.envelope["properties"]["canonical_input_bundle"][
            "allOf"
        ][1]["properties"]["handoff_relationship"]["properties"]
        for field in (
            "writer_role",
            "assignment_version",
            "assignment_head_sha256",
            "claim_generation",
        ):
            self.assertNotIn(field, relationship)


if __name__ == "__main__":
    unittest.main()
