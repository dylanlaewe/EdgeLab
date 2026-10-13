from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, RefResolver

from tools.generate_persisted_authentic_capture import cj, generate
from tools.reconstruct_persisted_history import validate_graph
from tools.verify_authentic_history import result, verify_authentic_history
from tools.verify_trusted_authentic_capture import package_digest


ROOT = Path(__file__).resolve().parents[1]
DISPATCH = ROOT / "tests/fixtures/authentic-stage1/dispatch"
FIXTURES = (
    DISPATCH,
    ROOT / "tests/fixtures/authentic-stage1/deny",
    ROOT / "tests/fixtures/authentic-stage1-dependency/satisfied",
    ROOT / "tests/fixtures/authentic-stage1-dependency/content-sha-denied",
)
EXPECTED = (
    "D-0a6e8268c4309df969a5384c4ce33063",
    "D-25150701cc9d3f301f686d420e407c2f",
    "D-03d6aa8e833902266a2547b9393ebd94",
    "D-dd4e6244a8643854f113bef4892a457d",
)
WRAPPER_SCHEMA = json.loads(
    (ROOT / "schemas/m0-2-historical-verification-result.v1.schema.json").read_text()
)
WRAPPER_RESOLVER = RefResolver((ROOT / "schemas").as_uri() + "/", WRAPPER_SCHEMA)
V3_SCHEMA = json.loads(
    (ROOT / "schemas/m0-2-decision-evidence-verification-result.v3.schema.json").read_text()
)


def schema_errors(record: dict) -> tuple[list, list]:
    wrapper = list(
        Draft202012Validator(WRAPPER_SCHEMA, resolver=WRAPPER_RESOLVER).iter_errors(record)
    )
    projection = list(Draft202012Validator(V3_SCHEMA).iter_errors(record["authorization_result"]))
    return wrapper, projection


def rehash_graph(graph: dict) -> None:
    graph["self_sha256"] = hashlib.sha256(
        cj({key: value for key, value in graph.items() if key != "self_sha256"}).encode()
    ).hexdigest()


class HistoricalVerifierAcceptance(unittest.TestCase):
    def copied_fixture(self) -> tuple[tempfile.TemporaryDirectory, Path]:
        temporary = tempfile.TemporaryDirectory()
        fixture = Path(temporary.name) / "fixture"
        shutil.copytree(DISPATCH, fixture)
        return temporary, fixture

    def assert_invalid(self, fixture: Path) -> dict:
        observed = verify_authentic_history(fixture)
        self.assertEqual(observed["status"], "INVALID")
        self.assertEqual(observed["authorization_result"]["authorizing_use"], "DENY")
        self.assertEqual(observed["authorization_result"]["currentness_status"], "UNKNOWN")
        self.assertEqual(schema_errors(observed), ([], []))
        return observed

    def test_four_reconstructed_histories_match_exact_stored_results(self):
        for fixture, decision_id in zip(FIXTURES, EXPECTED, strict=True):
            with self.subTest(fixture=fixture):
                expected = json.loads((fixture / "authentic-capture.v1.json").read_text())["result"]
                observed = verify_authentic_history(fixture)
                self.assertEqual(observed["status"], "HISTORICALLY_VALID")
                self.assertEqual(observed["evidence"]["decision_id"], decision_id)
                self.assertEqual(
                    observed["evidence"]["raw_result_sha256"],
                    hashlib.sha256(cj(expected).encode()).hexdigest(),
                )
                self.assertEqual(schema_errors(observed), ([], []))
                self.assertEqual(observed["authorization_result"]["historical_status"], "VALID")
                self.assertEqual(observed["authorization_result"]["currentness_status"], "UNKNOWN")
                self.assertEqual(observed["authorization_result"]["authorizing_use"], "DENY")

    def test_success_diagnostics_come_from_reconstructed_execution(self):
        observed = verify_authentic_history(DISPATCH)
        evidence = observed["evidence"]
        self.assertTrue(evidence["replay_root"].startswith("persisted-graph:"))
        self.assertTrue(any(item.startswith("edgelab:") for item in evidence["module_origins"]))
        self.assertTrue(
            any(item.startswith("edgelab.orchestration:") for item in evidence["module_origins"])
        )
        self.assertTrue(
            any("repository/schemas/orchestration-task.schema.json:" in item for item in evidence["schema_origins"])
        )
        for package in ("attr", "jsonschema", "jsonschema_specifications", "referencing", "rpds"):
            self.assertTrue(
                any(item == package or item.startswith(package + ".") for item in (value.split(":", 1)[0] for value in evidence["package_origins"])),
                package,
            )
        self.assertEqual(evidence["python"]["implementation"], "CPython")
        self.assertEqual(evidence["git"]["model"], "host-git-checked")
        self.assertEqual(evidence["git"]["origin_url"], "https://github.com/dylanlaewe/EdgeLab.git")
        self.assertEqual(len(evidence["git"]["replay_commit"]), 40)
        self.assertEqual(len(evidence["environment_sha256"]), 64)

    def test_direct_and_module_cli_return_schema_valid_json(self):
        environment = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
        commands = (
            [sys.executable, "tools/verify_authentic_history.py", str(DISPATCH)],
            [sys.executable, "-m", "tools.verify_authentic_history", str(DISPATCH)],
        )
        for command in commands:
            with self.subTest(command=command):
                completed = subprocess.run(
                    command, cwd=ROOT, env=environment, text=True, capture_output=True, check=True
                )
                observed = json.loads(completed.stdout)
                self.assertEqual(observed["status"], "HISTORICALLY_VALID")
                self.assertEqual(schema_errors(observed), ([], []))
                self.assertNotIn("Traceback", completed.stderr)

    def test_failure_constructor_is_closed_and_schema_valid(self):
        observed = result("INVALID", ["GRAPH_INVALID"])
        self.assertEqual(observed["evidence"]["package_origins"], [])
        self.assertEqual(schema_errors(observed), ([], []))

    def test_incompatible_runtime_boundary_returns_typed_denial(self):
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            trust = json.loads((ROOT / "docs/M0.2_STAGE1_TRUST_ROOT.v1.json").read_text())
            trust["host_boundary"]["platform"] = "ImpossibleOS"
            trust["root_sha256"] = hashlib.sha256(
                cj({key: value for key, value in trust.items() if key != "root_sha256"}).encode()
            ).hexdigest()
            trust_path = temporary / "trust.json"
            trust_path.write_text(json.dumps(trust))
            capture_root = json.loads(
                (ROOT / "docs/M0.2_HISTORICAL_CAPTURE_ROOT.v1.json").read_text()
            )
            capture_root["base_trusted_root_sha256"] = trust["root_sha256"]
            capture_root["root_sha256"] = hashlib.sha256(
                cj({key: value for key, value in capture_root.items() if key != "root_sha256"}).encode()
            ).hexdigest()
            capture_path = temporary / "captures.json"
            capture_path.write_text(json.dumps(capture_root))
            observed = verify_authentic_history(
                DISPATCH, trusted_root=trust_path, capture_trust_root=capture_path
            )
            self.assertEqual(observed["status"], "INCOMPATIBLE_RUNTIME")
            self.assertEqual(schema_errors(observed), ([], []))
            self.assertFalse(observed["authorization_result"]["runtime_compatible"])

    def test_malformed_self_rehashed_runtime_boundary_returns_typed_denial(self):
        for mutation in ("missing", "wrong-type"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                temporary = Path(directory)
                trust = json.loads((ROOT / "docs/M0.2_STAGE1_TRUST_ROOT.v1.json").read_text())
                if mutation == "missing":
                    trust.pop("host_boundary")
                else:
                    trust["host_boundary"]["python_major_minor"] = 313
                trust["root_sha256"] = hashlib.sha256(
                    cj({key: value for key, value in trust.items() if key != "root_sha256"}).encode()
                ).hexdigest()
                trust_path = temporary / "trust.json"
                trust_path.write_text(json.dumps(trust))

                capture_root = json.loads(
                    (ROOT / "docs/M0.2_HISTORICAL_CAPTURE_ROOT.v1.json").read_text()
                )
                capture_root["base_trusted_root_sha256"] = trust["root_sha256"]
                capture_root["root_sha256"] = hashlib.sha256(
                    cj(
                        {
                            key: value
                            for key, value in capture_root.items()
                            if key != "root_sha256"
                        }
                    ).encode()
                ).hexdigest()
                capture_path = temporary / "captures.json"
                capture_path.write_text(json.dumps(capture_root))

                observed = verify_authentic_history(
                    DISPATCH, trusted_root=trust_path, capture_trust_root=capture_path
                )
                self.assertEqual(observed["status"], "INVALID")
                self.assertEqual(observed["reason_codes"], ["TRUSTED_ROOT_MISMATCH"])
                self.assertEqual(schema_errors(observed), ([], []))
                self.assertEqual(observed["authorization_result"]["currentness_status"], "UNKNOWN")
                self.assertEqual(observed["authorization_result"]["authorizing_use"], "DENY")

    def test_coordinated_output_and_inventory_forgery_rejects(self):
        temporary, fixture = self.copied_fixture()
        self.addCleanup(temporary.cleanup)
        sidecar = fixture / "authentic-capture.v1.json"
        capture = json.loads(sidecar.read_text())
        capture["result"] = {"decision": "DISPATCH", "operation": "FORGED", "authorized": True}
        capture["repository_inventory_sha256"] = "0" * 64
        sidecar.write_text(json.dumps(capture))
        self.assert_invalid(fixture)

    def test_module_and_package_initializer_forgery_reject_before_execution(self):
        for relative in (
            "repository/src/edgelab/orchestration.py",
            "repository/src/edgelab/__init__.py",
        ):
            temporary, fixture = self.copied_fixture()
            self.addCleanup(temporary.cleanup)
            marker = Path(temporary.name) / "executed"
            path = fixture / relative
            path.write_text(path.read_text() + f"\nfrom pathlib import Path\nPath({str(marker)!r}).write_text('executed')\n")
            self.assert_invalid(fixture)
            self.assertFalse(marker.exists())

    def test_required_schema_forgery_rejects(self):
        temporary, fixture = self.copied_fixture()
        self.addCleanup(temporary.cleanup)
        schema = fixture / "repository/schemas/orchestration-task.schema.json"
        schema.write_text(schema.read_text() + " ")
        self.assert_invalid(fixture)

    def test_package_byte_forgery_with_local_rehash_rejects(self):
        temporary, fixture = self.copied_fixture()
        self.addCleanup(temporary.cleanup)
        changed = next((fixture / "packages/attrs").rglob("__init__.py"))
        changed.write_text(changed.read_text() + "\n# coordinated package forgery\n")
        sidecar = fixture / "authentic-capture.v1.json"
        capture = json.loads(sidecar.read_text())
        record = next(item for item in capture["packages"] if item["name"] == "attrs")
        record["files_sha256"] = package_digest(fixture / record["path"])
        sidecar.write_text(json.dumps(capture))
        self.assert_invalid(fixture)

    def test_package_closure_and_shadow_package_forgery_reject(self):
        for mutation in ("remove", "duplicate", "shadow"):
            temporary, fixture = self.copied_fixture()
            self.addCleanup(temporary.cleanup)
            sidecar = fixture / "authentic-capture.v1.json"
            capture = json.loads(sidecar.read_text())
            if mutation == "remove":
                capture["packages"].pop()
                sidecar.write_text(json.dumps(capture))
            elif mutation == "duplicate":
                capture["packages"].append(copy.deepcopy(capture["packages"][0]))
                sidecar.write_text(json.dumps(capture))
            else:
                shadow = fixture / "packages/evil/jsonschema"
                shadow.mkdir(parents=True)
                (shadow / "__init__.py").write_text("raise RuntimeError('shadow imported')\n")
            self.assert_invalid(fixture)

    def test_frozen_capture_intent_entrypoint_and_root_identity_forgery_reject(self):
        mutations = (
            ("freeze_commit", "0" * 40),
            ("capture_id", "AUTH-FORGED"),
            ("entrypoint", "edgelab.forged.decision"),
            ("trusted_root_id", "M0-2-STAGE1-TRUST-ROOT-FORGED"),
            ("intent", {"task_id": "T-UNKNOWN", "attempt": 1}),
        )
        for field, value in mutations:
            temporary, fixture = self.copied_fixture()
            self.addCleanup(temporary.cleanup)
            sidecar = fixture / "authentic-capture.v1.json"
            capture = json.loads(sidecar.read_text())
            capture[field] = value
            sidecar.write_text(json.dumps(capture))
            self.assert_invalid(fixture)


class PersistedGraphValidation(unittest.TestCase):
    def mutated(self) -> dict:
        return copy.deepcopy(generate(DISPATCH))

    def assert_graph_invalid(self, graph: dict) -> None:
        rehash_graph(graph)
        with self.assertRaises(ValueError):
            validate_graph(graph)

    def test_invalid_blob_base64_and_digest_reject(self):
        graph = self.mutated()
        graph["blobs"][0]["bytes_b64"] = "***"
        self.assert_graph_invalid(graph)
        graph = self.mutated()
        payload = base64.b64decode(graph["blobs"][0]["bytes_b64"])
        graph["blobs"][0]["bytes_b64"] = base64.b64encode(payload + b"x").decode()
        self.assert_graph_invalid(graph)

    def test_duplicate_blob_artifact_and_path_traversal_reject(self):
        graph = self.mutated()
        graph["blobs"].append(copy.deepcopy(graph["blobs"][0]))
        self.assert_graph_invalid(graph)
        graph = self.mutated()
        graph["artifacts"].append(copy.deepcopy(graph["artifacts"][0]))
        graph["source_manifest"].append(graph["artifacts"][0]["id"])
        self.assert_graph_invalid(graph)
        graph = self.mutated()
        artifact = graph["artifacts"][0]
        old_id = artifact["id"]
        artifact["path"] = "../escape"
        artifact["id"] = "FILE:../escape"
        graph["source_manifest"] = [artifact["id"] if item == old_id else item for item in graph["source_manifest"]]
        self.assert_graph_invalid(graph)

    def test_raw_result_directory_and_source_manifest_mismatch_reject(self):
        graph = self.mutated()
        graph["raw_result"]["canonical_json"] = "{}"
        self.assert_graph_invalid(graph)
        graph = self.mutated()
        graph["directories"][0]["members"].pop()
        self.assert_graph_invalid(graph)
        graph = self.mutated()
        graph["source_manifest"].pop()
        self.assert_graph_invalid(graph)


if __name__ == "__main__":
    unittest.main()
