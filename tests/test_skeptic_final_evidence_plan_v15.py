"""V15 regression probes; H-M0-080 changes only historical-verifier expectations."""
from __future__ import annotations

import copy
import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

import tools.resolve_authoritative_currentness as currentness
from tests.test_currentness_reference import B
from tools.generate_persisted_authentic_capture import generate
from tools.verify_authentic_history import verify_authentic_history


ROOT = Path(__file__).resolve().parents[1]
DISPATCH = ROOT / "tests/fixtures/authentic-stage1/dispatch"
V3 = json.loads((ROOT / "schemas/m0-2-decision-evidence-verification-result.v3.schema.json").read_text())


def package_digest(path: Path) -> str:
    members = (
        (str(item.relative_to(path)) + ":" + hashlib.sha256(item.read_bytes()).hexdigest()).encode()
        for item in path.rglob("*")
        if item.is_file()
    )
    return hashlib.sha256(b"".join(sorted(members))).hexdigest()


class FinalEvidencePlanV15Skeptic(unittest.TestCase):
    def copied_fixture(self) -> tuple[tempfile.TemporaryDirectory, Path]:
        temporary = tempfile.TemporaryDirectory()
        fixture = Path(temporary.name) / "fixture"
        shutil.copytree(DISPATCH, fixture)
        return temporary, fixture

    def source(self) -> tuple[tempfile.TemporaryDirectory, Path, dict]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        repository = copy.deepcopy(B)
        runtime = {
            "attachment_repository_id": "repo",
            "runtime": repository.pop("runtime"),
            "claim": repository.pop("claim"),
            "generations": {
                key: repository["generations"][key]
                for key in ("runtime", "scheduler", "dispatch", "claim", "fence")
            },
            "generation": 1,
        }
        (root / "repository.json").write_text(json.dumps(repository))
        (root / "runtime.json").write_text(json.dumps(runtime))
        return temporary, root, repository

    def test_four_canonical_histories_remain_valid(self):
        fixtures = (
            DISPATCH,
            ROOT / "tests/fixtures/authentic-stage1/deny",
            ROOT / "tests/fixtures/authentic-stage1-dependency/satisfied",
            ROOT / "tests/fixtures/authentic-stage1-dependency/content-sha-denied",
        )
        self.assertEqual(
            [verify_authentic_history(path)["status"] for path in fixtures],
            ["HISTORICALLY_VALID"] * 4,
        )

    def test_forged_output_is_rejected_by_composed_verifier(self):
        temporary, fixture = self.copied_fixture()
        self.addCleanup(temporary.cleanup)
        sidecar = fixture / "authentic-capture.v1.json"
        capture = json.loads(sidecar.read_text())
        capture["result"] = {"decision": "DISPATCH", "operation": "FORGED", "authorized": True}
        capture["repository_inventory_sha256"] = "0" * 64
        sidecar.write_text(json.dumps(capture))
        self.assertEqual(verify_authentic_history(fixture)["status"], "INVALID")

    def test_recomputed_package_forgery_is_rejected_by_composed_verifier(self):
        temporary, fixture = self.copied_fixture()
        self.addCleanup(temporary.cleanup)
        changed = next((fixture / "packages/attrs").rglob("__init__.py"))
        changed.write_text(changed.read_text() + "\n# coordinated package forgery\n")
        sidecar = fixture / "authentic-capture.v1.json"
        capture = json.loads(sidecar.read_text())
        attrs = next(item for item in capture["packages"] if item["name"] == "attrs")
        attrs["files_sha256"] = package_digest(fixture / attrs["path"])
        sidecar.write_text(json.dumps(capture))
        self.assertEqual(verify_authentic_history(fixture)["status"], "INVALID")

    def test_required_frozen_schema_forgery_is_rejected_by_composed_verifier(self):
        temporary, fixture = self.copied_fixture()
        self.addCleanup(temporary.cleanup)
        schema = fixture / "repository/schemas/orchestration-task.schema.json"
        schema.write_text(schema.read_text() + " ")
        self.assertEqual(verify_authentic_history(fixture)["status"], "INVALID")

    def test_tampered_runtime_trust_record_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            trust_path = Path(directory) / "trust.json"
            trust = json.loads((ROOT / "docs/M0.2_STAGE1_TRUST_ROOT.v1.json").read_text())
            trust["host_boundary"].update(
                {"platform": "ImpossibleOS", "architecture": "none", "git_model": "impossible-git"}
            )
            trust_path.write_text(json.dumps(trust))
            self.assertEqual(verify_authentic_history(DISPATCH, trusted_root=trust_path)["status"], "INVALID")

    def test_persisted_graph_has_deduplicated_blob_bytes(self):
        graph = generate(DISPATCH)
        self.assertTrue(graph["blobs"])
        self.assertTrue(all(set(blob) == {"id", "sha256", "byte_length", "bytes_b64"} for blob in graph["blobs"]))
        self.assertEqual(len(graph["blobs"]), len({blob["id"] for blob in graph["blobs"]}))
        self.assertEqual(graph["git"]["freeze_commit"], json.loads(
            (DISPATCH / "authentic-capture.v1.json").read_text()
        )["freeze_commit"])

    def test_historical_verifier_embeds_valid_v3_denial(self):
        result = verify_authentic_history(DISPATCH)
        self.assertFalse(list(Draft202012Validator(V3).iter_errors(result["authorization_result"])))
        self.assertEqual(result["authorization_result"]["currentness_status"], "UNKNOWN")
        self.assertEqual(result["authorization_result"]["authorizing_use"], "DENY")

    def test_currentness_positive_output_is_v3(self):
        temporary, source_root, _ = self.source()
        self.addCleanup(temporary.cleanup)
        result = currentness.resolve_and_verify_currentness("HISTORICALLY_VALID", B, source_root)
        self.assertFalse(list(Draft202012Validator(V3).iter_errors(result)))
        self.assertEqual(result["authorizing_use"], "ALLOW")

    def test_historical_invalid_currentness_output_is_not_v3(self):
        temporary, source_root, _ = self.source()
        self.addCleanup(temporary.cleanup)
        result = currentness.resolve_and_verify_currentness("INVALID", B, source_root)
        self.assertEqual(result["authorizing_use"], "DENY")
        self.assertTrue(list(Draft202012Validator(V3).iter_errors(result)))

    def test_repository_a_to_b_race_is_not_rechecked(self):
        temporary, source_root, _ = self.source()
        self.addCleanup(temporary.cleanup)
        original_load = currentness.load

        def racing_load(root, name):
            value = original_load(root, name)
            if name == "repository.json":
                changed = copy.deepcopy(value)
                changed["assignment"]["head"] = "state-b-after-read"
                (Path(root) / name).write_text(json.dumps(changed))
            return value

        currentness.load = racing_load
        try:
            result = currentness.resolve_and_verify_currentness("HISTORICALLY_VALID", B, source_root)
        finally:
            currentness.load = original_load
        self.assertEqual(result["authorizing_use"], "ALLOW")
        self.assertEqual(json.loads((source_root / "repository.json").read_text())["assignment"]["head"], "state-b-after-read")

    def test_generation_inconsistent_authority_and_binding_can_allow(self):
        temporary, source_root, repository = self.source()
        self.addCleanup(temporary.cleanup)
        repository["repository"]["generation"] = 99
        (source_root / "repository.json").write_text(json.dumps(repository))
        attacker_binding = copy.deepcopy(B)
        attacker_binding["repository"]["generation"] = 99
        result = currentness.resolve_and_verify_currentness(
            "HISTORICALLY_VALID", attacker_binding, source_root
        )
        self.assertEqual(result["authorizing_use"], "ALLOW")

    def test_resolver_uses_json_fixtures_without_sqlite_or_locking(self):
        source = (ROOT / "tools/resolve_authoritative_currentness.py").read_text()
        for required in ("sqlite3", "fcntl", "flock", "BEGIN", "attachment.json"):
            self.assertNotIn(required, source)
        self.assertIn("repository.json", source)
        self.assertIn("runtime.json", source)

    def test_trace_is_diagnostic_only_for_normal_current_case(self):
        temporary, source_root, _ = self.source()
        self.addCleanup(temporary.cleanup)
        authoritative, trace = currentness.resolve_with_trace("HISTORICALLY_VALID", B, source_root)
        closed = currentness.resolve_and_verify_currentness("HISTORICALLY_VALID", B, source_root)
        self.assertEqual(authoritative, closed)
        self.assertEqual(trace, [])


if __name__ == "__main__":
    unittest.main()
