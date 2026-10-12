"""Focused Skeptic probes for the remediated trusted-evidence planning package.

Passing adversarial tests below preserve evidence that the published reference
accepts the characterized input; they are not assertions that acceptance is safe.
"""
from __future__ import annotations

import copy
import hashlib
import importlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

import tools.verify_trusted_authentic_capture as trusted
from tools.verify_currentness_reference import verify as verify_currentness


ROOT = Path(__file__).resolve().parents[1]
DISPATCH = ROOT / "tests/fixtures/authentic-stage1/dispatch"


def package_digest(path: Path) -> str:
    members = (
        (str(item.relative_to(path)) + ":" + hashlib.sha256(item.read_bytes()).hexdigest()).encode()
        for item in path.rglob("*")
        if item.is_file()
    )
    return hashlib.sha256(b"".join(sorted(members))).hexdigest()


def binding() -> dict:
    return {
        "repository": {"id": "repo", "generation": 1},
        "runtime": {"id": "runtime", "generation": 1},
        "task": {"task_id": "T", "attempt": 1, "scheduler_state": "READY"},
        "assignment": {"id": "A", "head": "a", "generation": 1},
        "handoff": {"id": "H", "head": "h", "generation": 1},
        "claim": {"id": "C", "state": "CLAIMED", "fence": 1},
        "project": {"id": "P", "head": "p", "generation": 1},
        "stops": [],
        "capabilities": [],
        "dependencies": [],
        "inventories": [],
        "git": {"head": "0" * 40, "origin_main": "0" * 40, "origin_url": "https://x"},
        "generations": {
            "repository": 1,
            "runtime": 1,
            "scheduler": 1,
            "dispatch": 1,
            "assignment": 1,
            "handoff": 1,
            "claim": 1,
            "fence": 1,
        },
    }


class TrustedEvidencePlanV14Skeptic(unittest.TestCase):
    def copied_fixture(self) -> tuple[tempfile.TemporaryDirectory, Path]:
        temporary = tempfile.TemporaryDirectory()
        fixture = Path(temporary.name) / "fixture"
        shutil.copytree(DISPATCH, fixture)
        return temporary, fixture

    def test_original_four_sidecars_are_trusted(self):
        fixtures = (
            DISPATCH,
            ROOT / "tests/fixtures/authentic-stage1/deny",
            ROOT / "tests/fixtures/authentic-stage1-dependency/satisfied",
            ROOT / "tests/fixtures/authentic-stage1-dependency/content-sha-denied",
        )
        self.assertEqual([trusted.verify(path) for path in fixtures], ["HISTORICALLY_VALID"] * 4)

    def test_director_reference_test_modules_register_no_unittest_tests(self):
        loader = unittest.defaultTestLoader
        for name in ("tests.test_trusted_authentic_capture", "tests.test_currentness_reference"):
            module = importlib.import_module(name)
            self.assertEqual(loader.loadTestsFromModule(module).countTestCases(), 0, name)

    def test_forged_result_and_repository_inventory_remain_trusted(self):
        temporary, fixture = self.copied_fixture()
        self.addCleanup(temporary.cleanup)
        sidecar = fixture / "authentic-capture.v1.json"
        capture = json.loads(sidecar.read_text())
        capture["result"] = {"decision": "DISPATCH", "operation": "FORGED", "authorized": True}
        capture["repository_inventory_sha256"] = "0" * 64
        sidecar.write_text(json.dumps(capture))
        self.assertEqual(trusted.verify(fixture), "HISTORICALLY_VALID")

    def test_package_mutation_with_recomputed_capture_hash_remains_trusted(self):
        temporary, fixture = self.copied_fixture()
        self.addCleanup(temporary.cleanup)
        changed = next((fixture / "packages/attrs").rglob("__init__.py"))
        changed.write_text(changed.read_text() + "\n# coordinated package forgery\n")
        sidecar = fixture / "authentic-capture.v1.json"
        capture = json.loads(sidecar.read_text())
        attrs = next(item for item in capture["packages"] if item["name"] == "attrs")
        attrs["files_sha256"] = package_digest(fixture / attrs["path"])
        sidecar.write_text(json.dumps(capture))
        self.assertEqual(trusted.verify(fixture), "HISTORICALLY_VALID")

    def test_unpinned_frozen_schema_mutation_remains_trusted(self):
        temporary, fixture = self.copied_fixture()
        self.addCleanup(temporary.cleanup)
        schema = fixture / "repository/schemas/orchestration-task.schema.json"
        schema.write_text(schema.read_text() + " ")
        self.assertEqual(trusted.verify(fixture), "HISTORICALLY_VALID")

    def test_package_closure_can_be_reduced_or_duplicate_a_name(self):
        for mutation in ("remove", "duplicate"):
            temporary, fixture = self.copied_fixture()
            self.addCleanup(temporary.cleanup)
            sidecar = fixture / "authentic-capture.v1.json"
            capture = json.loads(sidecar.read_text())
            if mutation == "remove":
                capture["packages"].pop()
            else:
                duplicate = copy.deepcopy(capture["packages"][0])
                duplicate["version"] = "attacker-version"
                capture["packages"].append(duplicate)
            sidecar.write_text(json.dumps(capture))
            self.assertEqual(trusted.verify(fixture), "HISTORICALLY_VALID", mutation)

    def test_incompatible_host_boundary_is_not_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            alternate_root = Path(directory)
            (alternate_root / "docs").mkdir()
            root_record = json.loads((ROOT / "docs/M0.2_STAGE1_TRUST_ROOT.v1.json").read_text())
            root_record["host_boundary"].update(
                {"python_major_minor": "0.0", "platform": "ImpossibleOS", "architecture": "none"}
            )
            (alternate_root / "docs/M0.2_STAGE1_TRUST_ROOT.v1.json").write_text(json.dumps(root_record))
            original = trusted.ROOT
            trusted.ROOT = alternate_root
            try:
                self.assertEqual(trusted.verify(DISPATCH), "HISTORICALLY_VALID")
            finally:
                trusted.ROOT = original

    def test_authentic_schema_omits_claimed_closed_evidence_graph(self):
        schema = json.loads((ROOT / "schemas/m0-2-authentic-capture.v1.schema.json").read_text())
        properties = set(schema["properties"])
        claimed = {
            "git_observation",
            "source_manifest",
            "artifacts",
            "blobs",
            "directories",
            "absence_assertions",
            "modules",
            "schemas",
            "engine_binding",
            "capture_sha256",
        }
        self.assertEqual(properties & claimed, set())

    def test_currentness_schema_omits_attachment_and_result_is_not_v3(self):
        snapshot_schema = json.loads((ROOT / "schemas/m0-2-currentness-snapshot.v1.schema.json").read_text())
        self.assertNotIn("attachment", snapshot_schema["properties"])
        result = verify_currentness("HISTORICALLY_VALID", binding(), {"snapshot": binding()})
        result_schema = json.loads(
            (ROOT / "schemas/m0-2-decision-evidence-verification-result.v3.schema.json").read_text()
        )
        errors = list(Draft202012Validator(result_schema).iter_errors(result))
        self.assertTrue(errors)

    def test_caller_supplied_and_generation_inconsistent_snapshot_can_allow(self):
        supplied = binding()
        supplied["repository"]["generation"] = 99
        result = verify_currentness("HISTORICALLY_VALID", supplied, {"snapshot": copy.deepcopy(supplied)})
        self.assertEqual((result["currentness_status"], result["authorization"]), ("CURRENT", "ALLOW"))

    def test_currentness_reference_has_no_authoritative_source_resolution_or_lock(self):
        source = (ROOT / "tools/verify_currentness_reference.py").read_text()
        self.assertIn("authority['snapshot']", source)
        for required in ("sqlite3", "fcntl", "git", "assignment", "handoff"):
            self.assertNotIn(required, source)

    def test_historical_invalid_still_denies(self):
        result = verify_currentness("INVALID", binding(), {"snapshot": binding()})
        self.assertEqual(result["authorization"], "DENY")


if __name__ == "__main__":
    unittest.main()
