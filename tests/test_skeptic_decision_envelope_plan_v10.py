"""Characterization probes for the Envelope v10 planning package.

These probes preserve the independent H-M0-069 findings. They do not define
the desired successor contract and do not modify the frozen Stage 1 engine.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import subprocess
import unittest
import warnings
from pathlib import Path

from jsonschema import Draft202012Validator, RefResolver


ROOT = Path(__file__).resolve().parents[1]
FREEZE = "bc3a40924ca580ca6eddc4c24e32ff99ddd95330"
ZERO = "0" * 64


def load(name: str) -> dict:
    return json.loads((ROOT / name).read_text())


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


class SkepticDecisionEnvelopePlanV10(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.path = ROOT / "schemas/m0-2-decision-evidence-envelope.v10.schema.json"
        cls.schema = load("schemas/m0-2-decision-evidence-envelope.v10.schema.json")
        cls.artifact = load("schemas/m0-2-evidence-artifacts.v2.schema.json")
        cls.blob = load("schemas/m0-2-blob.v1.schema.json")
        cls.engine = load("schemas/m0-2-engine-distribution.v4.schema.json")
        cls.import_manifest = load("schemas/m0-2-import-manifest.v2.schema.json")
        cls.validation_manifest = load("schemas/m0-2-validation-manifest.v2.schema.json")
        cls.result = load(
            "schemas/m0-2-decision-evidence-verification-result.v2.schema.json"
        )
        for schema in (
            cls.schema,
            cls.artifact,
            cls.blob,
            cls.engine,
            cls.import_manifest,
            cls.validation_manifest,
            cls.result,
        ):
            Draft202012Validator.check_schema(schema)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            resolver = RefResolver(
                base_uri=cls.path.parent.resolve().as_uri() + "/",
                referrer=cls.schema,
            )
        cls.validator = Draft202012Validator(cls.schema, resolver=resolver)

    def record(self, identifier: str, artifact_id: str) -> dict:
        return {
            "id": identifier,
            "artifact_id": artifact_id,
            "version": 1,
            "head_sha256": ZERO,
        }

    def representative(self) -> dict:
        canonical_input = {
            "primary_task": self.record("T-1", "A-task"),
            "scheduler": {
                "artifact_id": "A-scheduler",
                "attempt": 1,
                "workflow": "ACTIVE",
                "execution": "CLAIMABLE",
                "review": "NOT_REQUIRED",
                "scheduler_generation": 1,
                "dispatch_generation": 0,
                "fence": 0,
                "claim_fixture_id": "claim-1",
                "claim_generation": 1,
            },
            "assignment": self.record("AS-1", "A-assignment"),
            "handoff": self.record("H-1", "A-handoff"),
            "relationship": {
                "task_id": "T-1",
                "assignment_id": "AS-1",
                "handoff_id": "H-1",
                "claim_fixture_id": "claim-1",
            },
            "project": {
                "record": self.record("PROJECT", "A-project"),
                "phase": "M0",
                "status": "BLOCKED_FOR_APPROVAL_REMEDIATION_ALLOWED",
                "live_status": "LOCKED",
            },
            "stops": {
                "inventory_artifact_id": "A-stop-directory",
                "records": [self.record("STOP-M0-001", "A-stop")],
            },
            "dependencies": [],
            "capabilities": [self.record("C-READ", "A-capability")],
            "repository": {"id": "EdgeLab", "generation": 1},
            "runtime": {
                "runtime_id": "runtime-1",
                "attachment_id": "attachment-1",
                "generation": 1,
            },
            "inventory_ids": ["A-stop-directory"],
            "git_observation_id": "G-1",
            "evaluation_time": "2026-01-01T00:00:00Z",
        }
        raw_mapping = {
            "decision": "DISPATCH",
            "decision_id": "D-1",
            "task_id": "T-1",
            "reason": "repository-resolved synthetic task passed preflight",
            "execution_adapter": "MOCK_ONLY",
            "operation": "STATE_READ",
        }
        raw = canonical(raw_mapping)
        names = [
            "task",
            "scheduler",
            "assignment",
            "handoff",
            "project",
            "stop",
            "capability",
            "launcher",
            "clock",
            "git",
            "orchestration",
            "validate",
            "data-integrity",
            "scheduler-schema",
        ]
        blobs = []
        artifacts = []
        for name in names:
            content = canonical({"name": name})
            digest = hashlib.sha256(content).hexdigest()
            blobs.append(
                {
                    "blob_id": digest,
                    "algorithm": "sha256",
                    "digest": digest,
                    "byte_length": len(content),
                    "encoding": "base64",
                    "content_base64": base64.b64encode(content).decode(),
                }
            )
            artifacts.append(
                {
                    "kind": "FILE",
                    "artifact_id": "A-" + name,
                    "source_id": "S-" + name,
                    "blob_id": digest,
                    "path": "replay/" + name + ".json",
                    "raw_sha256": digest,
                }
            )
        stop_digest = next(
            item["raw_sha256"] for item in artifacts if item["artifact_id"] == "A-stop"
        )
        artifacts.append(
            {
                "kind": "DIRECTORY",
                "artifact_id": "A-stop-directory",
                "source_id": "S-stop-directory",
                "root": "reports/stops",
                "members": [
                    {
                        "member_kind": "FILE",
                        "relative_path": "STOP-M0-001.v1.json",
                        "artifact_id": "A-stop",
                        "raw_sha256": stop_digest,
                    }
                ],
                "inventory_sha256": ZERO,
            }
        )
        package_bytes = b"synthetic wheel"
        package_digest = hashlib.sha256(package_bytes).hexdigest()
        blobs.append(
            {
                "blob_id": package_digest,
                "algorithm": "sha256",
                "digest": package_digest,
                "byte_length": len(package_bytes),
                "encoding": "base64",
                "content_base64": base64.b64encode(package_bytes).decode(),
            }
        )
        git_id = {"algorithm": "git-sha1", "value": FREEZE}
        envelope = {
            "schema_version": 10,
            "canonical_input": canonical_input,
            "source_manifest": {
                "manifest_id": "SM-1",
                "version": 1,
                "source_artifact_ids": [
                    item["artifact_id"] for item in artifacts if item["kind"] == "FILE"
                ],
                "inventory_ids": ["A-stop-directory"],
                "absence_artifact_ids": [],
                "canonical_input_sha256": hashlib.sha256(
                    canonical(canonical_input)
                ).hexdigest(),
                "source_set_sha256": ZERO,
            },
            "blobs": blobs,
            "artifacts": artifacts,
            "git_observation": {
                "observation_id": "G-1",
                "repository_id": "EdgeLab",
                "head": copy.deepcopy(git_id),
                "origin_main": copy.deepcopy(git_id),
                "origin_url": "https://github.com/dylanlaewe/EdgeLab.git",
                "ancestry_left": copy.deepcopy(git_id),
                "ancestry_right": copy.deepcopy(git_id),
                "head_reachable": True,
                "observation_sha256": ZERO,
            },
            "engine_distribution": {
                "distribution_id": "ED-1",
                "working_directory": "replay/root",
                "environment": {
                    "PYTHONHASHSEED": "0",
                    "LC_ALL": "C.UTF-8",
                    "TZ": "UTC",
                    "PYTHONIOENCODING": "utf-8",
                },
                "packages": [
                    {
                        "distribution_id": "P-jsonschema",
                        "name": "jsonschema",
                        "version": "4.23.0",
                        "blob_id": package_digest,
                        "sha256": package_digest,
                        "source_type": "wheel",
                        "python": "3.13",
                        "platform": "any",
                    }
                ],
                "launcher_artifact_id": "A-launcher",
                "clock_shim_artifact_id": "A-clock",
                "git_shim_artifact_id": "A-git",
            },
            "import_manifest": {
                "manifest_id": "IM-1",
                "version": 1,
                "local_modules": [
                    {
                        "module": "edgelab.orchestration",
                        "artifact_id": "A-orchestration",
                        "replay_path": "replay/edgelab/orchestration.py",
                        "sha256": ZERO,
                    },
                    {
                        "module": "edgelab.validate",
                        "artifact_id": "A-validate",
                        "replay_path": "replay/edgelab/validate.py",
                        "sha256": ZERO,
                    },
                    {
                        "module": "edgelab.data_integrity",
                        "artifact_id": "A-data-integrity",
                        "replay_path": "replay/edgelab/data_integrity.py",
                        "sha256": ZERO,
                    },
                ],
                "external_imports": [
                    {"module": "jsonschema", "distribution_id": "P-jsonschema"}
                ],
                "digest": ZERO,
            },
            "validation_manifest": {
                "manifest_id": "VM-1",
                "version": 1,
                "schemas": [
                    {
                        "schema_id": "scheduler-state.schema.json",
                        "artifact_id": "A-scheduler-schema",
                        "replay_path": "replay/schemas/scheduler-state.schema.json",
                        "sha256": ZERO,
                        "references": [],
                    }
                ],
                "validator_distribution_id": "P-jsonschema",
                "digest": ZERO,
            },
            "raw_evidence": {
                **raw_mapping,
                "raw_bytes_base64": base64.b64encode(raw).decode(),
                "raw_byte_length": len(raw),
                "raw_sha256": hashlib.sha256(raw).hexdigest(),
            },
            "normalized_output": raw_mapping,
            "verification_binding": {
                "historical_result": "VALID",
                "currentness_target": {
                    "repository_id": "EdgeLab",
                    "runtime_id": "runtime-1",
                    "attachment_id": "attachment-1",
                    "task_id": "T-1",
                    "attempt": 1,
                },
            },
            "envelope_sha256": ZERO,
        }
        envelope["envelope_sha256"] = hashlib.sha256(
            canonical({k: v for k, v in envelope.items() if k != "envelope_sha256"})
        ).hexdigest()
        return envelope

    def test_complete_representative_is_structurally_satisfiable(self) -> None:
        self.assertEqual([], list(self.validator.iter_errors(self.representative())))

    def test_required_root_component_deletions_reject(self) -> None:
        for key in (
            "source_manifest",
            "blobs",
            "artifacts",
            "git_observation",
            "engine_distribution",
            "import_manifest",
            "validation_manifest",
            "raw_evidence",
            "verification_binding",
        ):
            value = self.representative()
            del value[key]
            with self.subTest(key=key):
                self.assertTrue(list(self.validator.iter_errors(value)))

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

    def test_v10_scheduler_fields_are_not_frozen_m02_fields(self) -> None:
        frozen = json.loads(
            subprocess.check_output(
                ["git", "show", f"{FREEZE}:orchestration/scheduler-state.json"],
                cwd=ROOT,
                text=True,
            )
        )
        required = set(self.schema["$defs"]["input"]["properties"]["scheduler"]["required"])
        invented = {"workflow", "execution", "review", "dispatch_generation", "fence"}
        self.assertTrue(invented <= required)
        self.assertTrue(invented.isdisjoint(frozen))

    def test_relationship_omits_heads_writer_and_claim_generation(self) -> None:
        relationship = self.schema["$defs"]["input"]["properties"]["relationship"][
            "properties"
        ]
        for field in (
            "writer_role",
            "assignment_head_sha256",
            "handoff_head_sha256",
            "claim_generation",
        ):
            self.assertNotIn(field, relationship)

    def test_dependency_does_not_bind_completion_content_to_task_bytes(self) -> None:
        dependency = self.schema["$defs"]["input"]["properties"]["dependencies"][
            "items"
        ]["properties"]
        self.assertNotIn("completion_content_sha256", dependency)
        self.assertNotIn("task_content_sha256", dependency)

    def test_capability_binding_omits_disposition_and_effects(self) -> None:
        capability = self.schema["$defs"]["input"]["properties"]["capabilities"][
            "items"
        ]
        self.assertEqual({"$ref": "#/$defs/record"}, capability)

    def test_blob_id_duplicates_can_be_structurally_distinct(self) -> None:
        value = self.representative()
        duplicate = copy.deepcopy(value["blobs"][0])
        duplicate["content_base64"] = base64.b64encode(b"different").decode()
        duplicate["byte_length"] = len(b"different")
        value["blobs"].append(duplicate)
        self.assertEqual([], list(self.validator.iter_errors(value)))

    def test_artifact_paths_and_directories_lack_structural_closure(self) -> None:
        file_value = {
            "kind": "FILE",
            "artifact_id": "A-1",
            "source_id": "S-1",
            "blob_id": ZERO,
            "path": "../../current-checkout",
            "raw_sha256": ZERO,
        }
        self.assertTrue(Draft202012Validator(self.artifact).is_valid(file_value))
        directory = {
            "kind": "DIRECTORY",
            "artifact_id": "D-1",
            "source_id": "S-D",
            "root": "../../outside",
            "members": [
                {
                    "member_kind": "FILE",
                    "relative_path": "z",
                    "artifact_id": "A-1",
                    "raw_sha256": ZERO,
                },
                {
                    "member_kind": "FILE",
                    "relative_path": "z",
                    "artifact_id": "A-1",
                    "raw_sha256": ZERO,
                },
            ],
            "inventory_sha256": ZERO,
        }
        self.assertTrue(Draft202012Validator(self.artifact).is_valid(directory))

    def test_absent_still_cannot_represent_normative_digest_inputs(self) -> None:
        absent = self.artifact["oneOf"][1]
        self.assertNotIn("source_class", absent["properties"])
        self.assertNotIn("absence_context", absent["properties"])

    def test_engine_does_not_bind_manifests_or_local_modules(self) -> None:
        properties = set(self.engine["properties"])
        self.assertTrue(
            {
                "import_manifest_id",
                "validation_manifest_id",
                "local_artifact_ids",
                "python_interpreter_artifact_id",
            }.isdisjoint(properties)
        )

    def test_workdir_and_environment_are_strict(self) -> None:
        workdir = self.engine["properties"]["working_directory"]
        validator = Draft202012Validator(workdir)
        self.assertTrue(validator.is_valid("replay/root"))
        for value in (1, None, {}, [], "/tmp/x", ".", "..", "a//b", "file:x", "C:/x"):
            self.assertFalse(validator.is_valid(value), value)
        environment = self.engine["properties"]["environment"]
        valid = {
            "PYTHONHASHSEED": "0",
            "LC_ALL": "C.UTF-8",
            "TZ": "UTC",
            "PYTHONIOENCODING": "utf-8",
        }
        self.assertTrue(Draft202012Validator(environment).is_valid(valid))
        for changed in ({}, {**valid, "PATH": "/tmp"}, {**valid, "TZ": "local"}):
            self.assertFalse(Draft202012Validator(environment).is_valid(changed))

    def test_import_and_validation_paths_still_accept_dot_segments(self) -> None:
        schemas = (
            self.import_manifest["properties"]["local_modules"]["items"]["properties"]["replay_path"],
            self.validation_manifest["properties"]["schemas"]["items"]["properties"]["replay_path"],
        )
        for schema in schemas:
            self.assertTrue(Draft202012Validator(schema).is_valid("replay/./x"))
            self.assertTrue(Draft202012Validator(schema).is_valid("replay//x"))

    def test_closure_digest_and_required_packages(self) -> None:
        fixture = load("docs/M0.2_STAGE1_DEPENDENCY_CLOSURE.v4.json")
        claimed = fixture.pop("closure_sha256")
        self.assertEqual(claimed, hashlib.sha256(canonical(fixture)).hexdigest())
        self.assertTrue(
            {
                "jsonschema",
                "jsonschema-specifications",
                "attrs",
                "referencing",
                "rpds-py",
            }
            <= set(fixture["packages"])
        )

    def test_currentness_target_omits_required_authority_dimensions(self) -> None:
        currentness = self.schema["$defs"]["currentness"]["properties"]
        for field in (
            "scheduler_generation",
            "dispatch_generation",
            "fence",
            "assignment_head_sha256",
            "handoff_head_sha256",
            "claim_generation",
            "project_head_sha256",
            "stop_inventory_sha256",
            "dependency_heads",
            "capability_heads",
            "inventory_ids",
            "git_observation_id",
        ):
            self.assertNotIn(field, currentness)

    def test_verification_result_successor_and_matrix_are_missing(self) -> None:
        self.assertFalse(
            (ROOT / "schemas/m0-2-decision-evidence-verification-result.v3.schema.json").exists()
        )
        self.assertFalse(
            (ROOT / "docs/M0.2_DECISION_EVIDENCE_ACCEPTANCE_MATRIX.v5.md").exists()
        )

    def test_current_result_still_accepts_deny_none(self) -> None:
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

    def test_v11_adopts_v10_and_preserves_scheduler_guards(self) -> None:
        text = (ROOT / "docs/M0.3A_TRANSACTIONAL_CONTRACT.v11.md").read_text()
        self.assertIn("adopt Envelope v10", text)
        for value in ("B0", "actor", "closed-claim/fence", "generation", "idempotency", "non-operational"):
            self.assertIn(value, text)

    def test_raw_shapes_remain_exact(self) -> None:
        deny = self.schema["$defs"]["denyEvidence"]
        dispatch = self.schema["$defs"]["dispatchEvidence"]
        self.assertNotIn("operation", deny["properties"])
        self.assertIn("operation", dispatch["required"])


if __name__ == "__main__":
    unittest.main()
