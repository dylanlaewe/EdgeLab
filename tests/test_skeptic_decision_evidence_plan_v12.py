"""Independent characterization of the V12/V13 planning package.

These probes preserve the H-M0-073 planning-review evidence.  They do not
implement an adapter, change frozen Stage 1, or redefine the desired contract.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
import subprocess
import unittest
import warnings
from pathlib import Path

from jsonschema import Draft202012Validator, RefResolver

from tests import test_m0_2_decision_evidence_v12_conformance as director_conformance


ROOT = Path(__file__).resolve().parents[1]
FREEZE = "bc3a40924ca580ca6eddc4c24e32ff99ddd95330"


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def record_digest(value: dict, field: str) -> str:
    copied = copy.deepcopy(value)
    copied.pop(field, None)
    return hashlib.sha256(canonical(copied)).hexdigest()


class SkepticDecisionEvidencePlanV12(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema_path = ROOT / "schemas/m0-2-decision-evidence-envelope.v12.schema.json"
        cls.schema = json.loads(cls.schema_path.read_text())
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            resolver = RefResolver(cls.schema_path.resolve().as_uri(), cls.schema)
        cls.validator = Draft202012Validator(cls.schema, resolver=resolver)
        cls.result_schema = json.loads(
            (ROOT / "schemas/m0-2-decision-evidence-verification-result.v3.schema.json").read_text()
        )
        cls.director = director_conformance.V12Conformance(
            methodName="test_complete_root_graph_resolves_without_ambient_runtime"
        )

    def fixture(self, decision: str = "dispatch") -> dict:
        return json.loads((ROOT / f"tests/fixtures/m0-2-v12-{decision}.json").read_text())

    @staticmethod
    def blobs(value: dict) -> dict[str, bytes]:
        return {
            item["blob_id"]: base64.b64decode(item["content_base64"], validate=True)
            for item in value["blobs"]
        }

    @staticmethod
    def artifacts(value: dict) -> dict[str, dict]:
        return {item["artifact_id"]: item for item in value["artifacts"]}

    @staticmethod
    def seal(value: dict) -> None:
        value["envelope_sha256"] = record_digest(value, "envelope_sha256")

    def assert_schema_valid(self, value: dict) -> None:
        self.assertEqual([], list(self.validator.iter_errors(value)))

    def test_golden_fixtures_are_structurally_valid_and_self_digests_recompute(self):
        for decision in ("dispatch", "deny"):
            value = self.fixture(decision)
            self.assert_schema_valid(value)
            self.assertEqual(record_digest(value, "envelope_sha256"), value["envelope_sha256"])

    def test_critical_logical_digests_recompute(self):
        value = self.fixture()
        for key, digest_field in (
            ("source_manifest", "source_set_sha256"),
            ("git_observation", "observation_sha256"),
            ("engine_distribution", "distribution_sha256"),
            ("import_manifest", "digest"),
            ("validation_manifest", "digest"),
        ):
            self.assertEqual(record_digest(value[key], digest_field), value[key][digest_field])
        directory = next(item for item in value["artifacts"] if item["kind"] == "DIRECTORY")
        absent = next(item for item in value["artifacts"] if item["kind"] == "ABSENT")
        self.assertEqual(
            hashlib.sha256(canonical(directory["members"])).hexdigest(),
            directory["inventory_sha256"],
        )
        self.assertEqual(
            record_digest(absent, "absence_assertion_sha256"),
            absent["absence_assertion_sha256"],
        )
        closure = json.loads((ROOT / "docs/M0.2_STAGE1_DEPENDENCY_CLOSURE.v4.json").read_text())
        self.assertEqual(record_digest(closure, "closure_sha256"), closure["closure_sha256"])

    def test_historical_authority_blobs_are_not_parseable_records(self):
        value = self.fixture()
        artifacts = self.artifacts(value)
        blobs = self.blobs(value)
        authority_ids = [
            "task",
            "assignment",
            "handoff",
            "project",
            "dependency-task",
            "completion",
            "capability",
        ]
        for artifact_id in authority_ids:
            raw = blobs[artifacts[artifact_id]["blob_id"]]
            with self.subTest(artifact_id=artifact_id):
                with self.assertRaises(json.JSONDecodeError):
                    json.loads(raw)

    def test_dispatch_fixture_cannot_be_a_frozen_stage1_dispatch(self):
        value = self.fixture()
        raw = value["raw_evidence"]
        self.assertEqual("SAFE_YIELD", raw["operation"])
        self.assertNotIn(raw["operation"], {"STATE_READ", "SCHEMA_WRITE", "SYNTHETIC_ASSERT"})
        self.assertIsNone(re.fullmatch(r"D-[0-9a-f]{32}", raw["decision_id"]))
        self.assertEqual("fixture decision", raw["reason"])

    def test_deny_fixture_is_not_a_replayed_frozen_denial(self):
        value = self.fixture("deny")
        raw = value["raw_evidence"]
        self.assertNotIn("operation", raw)
        self.assertIsNone(value["normalized_output"]["operation"])
        self.assertIsNone(re.fullmatch(r"D-[0-9a-f]{32}", raw["decision_id"]))
        self.assertEqual("fixture decision", raw["reason"])

    def test_scheduler_state_and_handoff_binding_evidence_are_absent(self):
        value = self.fixture()
        paths = {
            item.get("path")
            for item in value["artifacts"]
            if item["kind"] == "FILE"
        }
        historical_ids = set(value["source_manifest"]["source_artifact_ids"])
        self.assertNotIn("orchestration/scheduler-state.json", paths)
        self.assertFalse(any(path and "handoff-bindings" in path for path in paths))
        self.assertFalse(any("scheduler" in item for item in historical_ids))
        self.assertFalse(any("binding" in item for item in historical_ids))

    def test_stop_inventory_contains_task_not_a_stop_record(self):
        value = self.fixture()
        directory = next(item for item in value["artifacts"] if item["kind"] == "DIRECTORY")
        self.assertEqual("historical/stops", directory["root"])
        self.assertEqual(["task"], [item["artifact_id"] for item in directory["members"]])
        self.assertEqual(["task.json"], [item["relative_path"] for item in directory["members"]])

    def test_frozen_denial_context_inventory_is_not_represented(self):
        value = self.fixture("deny")
        paths = {
            item.get("path")
            for item in value["artifacts"]
            if item["kind"] == "FILE"
        }
        # Frozen _denial_context scans these collections, including every handoff.
        required_collections = (
            "docs/",
            "docs/handoffs/",
            "reports/stops/",
            "orchestration/assignments/",
            "orchestration/handoff-bindings/",
            "orchestration/tasks/",
            "orchestration/completions/",
            "orchestration/capabilities/",
        )
        self.assertTrue(all(not any(path and path.startswith(prefix) for path in paths) for prefix in required_collections))

    def test_engine_local_artifacts_are_not_frozen_implementation_bytes(self):
        value = self.fixture()
        artifacts = self.artifacts(value)
        blobs = self.blobs(value)
        mappings = {
            "orchestration": "src/edgelab/orchestration.py",
            "validate": "src/edgelab/validate.py",
            "data-integrity": "src/edgelab/data_integrity.py",
        }
        for artifact_id, repository_path in mappings.items():
            retained = blobs[artifacts[artifact_id]["blob_id"]]
            frozen = subprocess.check_output(["git", "show", f"{FREEZE}:{repository_path}"])
            with self.subTest(artifact_id=artifact_id):
                self.assertNotEqual(frozen, retained)
                self.assertTrue(retained.startswith(b"retained:"))

    def test_validation_artifacts_are_not_retained_json_schemas(self):
        value = self.fixture()
        artifacts = self.artifacts(value)
        blobs = self.blobs(value)
        for entry in value["validation_manifest"]["schemas"]:
            raw = blobs[artifacts[entry["artifact_id"]]["blob_id"]]
            with self.subTest(schema_id=entry["schema_id"]):
                with self.assertRaises(json.JSONDecodeError):
                    json.loads(raw)

    def test_package_blobs_are_not_offline_installable_archives(self):
        value = self.fixture()
        blobs = self.blobs(value)
        for package in value["engine_distribution"]["packages"]:
            raw = blobs[package["blob_id"]]
            with self.subTest(package=package["name"]):
                self.assertEqual("wheel", package["source_type"])
                self.assertFalse(raw.startswith(b"PK\x03\x04"))
                self.assertEqual("fixture-1", package["version"])

    def test_dependency_closure_is_only_a_digest_stub(self):
        value = self.fixture()
        self.assertEqual(
            {"closure_id", "version", "closure_sha256"},
            set(value["dependency_closure"]),
        )
        self.assertFalse(
            any(
                item["kind"] == "FILE" and "closure" in item["artifact_id"]
                for item in value["artifacts"]
            )
        )
        self.assertNotIn(value["dependency_closure"]["closure_sha256"], self.blobs(value))

    def test_conformance_resolver_accepts_duplicate_package_name(self):
        value = self.fixture()
        duplicate = copy.deepcopy(value["engine_distribution"]["packages"][0])
        duplicate["distribution_id"] = "dist-jsonschema-conflict"
        duplicate["version"] = "fixture-conflict"
        value["engine_distribution"]["packages"].append(duplicate)
        value["engine_distribution"]["distribution_sha256"] = record_digest(
            value["engine_distribution"], "distribution_sha256"
        )
        self.seal(value)
        self.assert_schema_valid(value)
        self.assertTrue(self.director.fail_graph(value))

    def test_conformance_resolver_accepts_artifact_root_escape(self):
        value = self.fixture()
        value["artifacts"][0]["path"] = "../escape/task.json"
        self.seal(value)
        self.assert_schema_valid(value)
        self.assertTrue(self.director.fail_graph(value))

    def test_conformance_resolver_accepts_absent_present_contradiction(self):
        value = self.fixture()
        directory = next(item for item in value["artifacts"] if item["kind"] == "DIRECTORY")
        task = next(item for item in value["artifacts"] if item["artifact_id"] == "task")
        directory["root"] = "historical"
        directory["members"].append(
            {
                "member_kind": "FILE",
                "relative_path": "receipt.json",
                "artifact_id": "task",
                "raw_sha256": task["raw_sha256"],
            }
        )
        directory["inventory_sha256"] = hashlib.sha256(canonical(directory["members"])).hexdigest()
        self.seal(value)
        self.assert_schema_valid(value)
        self.assertTrue(self.director.fail_graph(value))

    def test_conformance_resolver_accepts_dangling_absence_manifest_reference(self):
        value = self.fixture()
        value["source_manifest"]["absence_artifact_ids"] = ["missing-absence"]
        value["source_manifest"]["source_set_sha256"] = record_digest(
            value["source_manifest"], "source_set_sha256"
        )
        self.seal(value)
        self.assert_schema_valid(value)
        self.assertTrue(self.director.fail_graph(value))

    def test_conformance_resolver_accepts_wrong_git_ancestry_operands(self):
        value = self.fixture()
        value["git_observation"]["ancestry_left"]["value"] = "b" * 40
        value["git_observation"]["ancestry_right"]["value"] = "c" * 40
        value["git_observation"]["observation_sha256"] = record_digest(
            value["git_observation"], "observation_sha256"
        )
        self.seal(value)
        self.assert_schema_valid(value)
        self.assertTrue(self.director.fail_graph(value))

    def test_conformance_resolver_accepts_self_consistent_forged_raw_output(self):
        value = self.fixture()
        value["raw_evidence"]["decision_id"] = "forged-decision"
        value["raw_evidence"]["reason"] = "forged reason"
        raw = {
            key: value["raw_evidence"][key]
            for key in ("decision", "decision_id", "task_id", "reason", "execution_adapter", "operation")
        }
        encoded = canonical(raw)
        value["raw_evidence"]["bytes_base64"] = base64.b64encode(encoded).decode()
        value["raw_evidence"]["byte_length"] = len(encoded)
        value["raw_evidence"]["sha256"] = hashlib.sha256(encoded).hexdigest()
        value["normalized_output"] = raw
        self.seal(value)
        self.assert_schema_valid(value)
        self.assertTrue(self.director.fail_graph(value))

    def test_rehashed_currentness_mutation_still_passes_conformance_graph(self):
        value = self.fixture()
        historical = canonical(value["historical_input"])
        value["currentness_binding"]["claim_state"] = "REVOKED"
        value["currentness_binding"]["generations"]["scheduler"] += 100
        self.seal(value)
        self.assertEqual(historical, canonical(value["historical_input"]))
        self.assert_schema_valid(value)
        self.assertTrue(self.director.fail_graph(value))

    def test_currentness_schema_omits_required_authority_bindings(self):
        properties = self.schema["$defs"]["currentness"]["properties"]
        absent = {
            "assignment",
            "handoff",
            "claim",
            "project",
            "stops",
            "dependencies",
            "capabilities",
            "inventories",
            "git",
        }
        self.assertTrue(absent.isdisjoint(properties))
        self.assertNotIn("assignment_head", properties)
        self.assertNotIn("handoff_head", properties)

    def test_replay_path_schemas_remain_weaker_than_v12_rule(self):
        for manifest_name, collection in (
            ("import_manifest", "local_modules"),
            ("validation_manifest", "schemas"),
        ):
            for replay_path in ("replay/./module.py", "replay//module.py"):
                value = self.fixture()
                value[manifest_name][collection][0]["replay_path"] = replay_path
                value[manifest_name]["digest"] = record_digest(value[manifest_name], "digest")
                self.seal(value)
                with self.subTest(manifest=manifest_name, path=replay_path):
                    self.assert_schema_valid(value)
                    self.assertFalse(self.director.fail_graph(value))

    def test_duplicate_artifact_and_blob_ids_are_semantically_rejected(self):
        for collection in ("artifacts", "blobs"):
            value = self.fixture()
            duplicate = copy.deepcopy(value[collection][0])
            if collection == "artifacts":
                duplicate["path"] = "historical/conflict.json"
            else:
                duplicate["media_type"] = "application/conflict"
            value[collection].append(duplicate)
            self.seal(value)
            self.assert_schema_valid(value)
            self.assertFalse(self.director.fail_graph(value))

    def test_result_v3_rejects_requested_unsafe_authorization_combinations(self):
        check = Draft202012Validator(self.result_schema)
        safe = {
            "historical_status": "VALID",
            "currentness_status": "CURRENT",
            "runtime_compatible": True,
            "verifier_status": "PASS",
            "generation_match": True,
            "authorizing_use": "ALLOW",
            "reason_code": "NONE",
        }
        self.assertEqual([], list(check.iter_errors(safe)))
        unsafe = (
            dict(safe, historical_status="INVALID"),
            dict(safe, currentness_status="STALE"),
            dict(safe, currentness_status="UNKNOWN"),
            dict(safe, currentness_status="INCOMPATIBLE"),
            dict(safe, runtime_compatible=False),
            dict(safe, verifier_status="FAIL"),
            dict(safe, generation_match=False),
            dict(safe, authorizing_use="DENY"),
        )
        for result in unsafe:
            with self.subTest(result=result):
                self.assertTrue(list(check.iter_errors(result)))


if __name__ == "__main__":
    unittest.main()
