from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from tools.verify_trusted_authentic_capture import package_digest, verify


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = (
    ROOT / "tests/fixtures/authentic-stage1/dispatch",
    ROOT / "tests/fixtures/authentic-stage1/deny",
    ROOT / "tests/fixtures/authentic-stage1-dependency/satisfied",
    ROOT / "tests/fixtures/authentic-stage1-dependency/content-sha-denied",
)


class TrustedAuthenticCapture(unittest.TestCase):
    def copied_fixture(self) -> tuple[tempfile.TemporaryDirectory, Path]:
        temporary = tempfile.TemporaryDirectory()
        fixture = Path(temporary.name) / "fixture"
        shutil.copytree(FIXTURES[0], fixture)
        return temporary, fixture

    def test_original_captures_match_external_capture_root(self):
        self.assertEqual([verify(fixture) for fixture in FIXTURES], ["HISTORICALLY_VALID"] * 4)

    def test_coordinated_module_and_result_forgery_fails(self):
        temporary, fixture = self.copied_fixture()
        self.addCleanup(temporary.cleanup)
        module = fixture / "repository/src/edgelab/orchestration.py"
        module.write_text(module.read_text().replace("repository-resolved", "forged-resolved"))
        sidecar = fixture / "authentic-capture.v1.json"
        capture = json.loads(sidecar.read_text())
        capture["result"]["reason"] = "forged-resolved synthetic task passed preflight"
        sidecar.write_text(json.dumps(capture))
        self.assertTrue(verify(fixture).startswith("INVALID:"))

    def test_forged_freeze_identity_fails(self):
        temporary, fixture = self.copied_fixture()
        self.addCleanup(temporary.cleanup)
        sidecar = fixture / "authentic-capture.v1.json"
        capture = json.loads(sidecar.read_text())
        capture["freeze_commit"] = "0" * 40
        sidecar.write_text(json.dumps(capture))
        self.assertTrue(verify(fixture).startswith("INVALID:"))

    def test_package_mutation_with_local_rehash_fails(self):
        temporary, fixture = self.copied_fixture()
        self.addCleanup(temporary.cleanup)
        changed = next((fixture / "packages/attrs").rglob("__init__.py"))
        changed.write_text(changed.read_text() + "\n# forged\n")
        sidecar = fixture / "authentic-capture.v1.json"
        capture = json.loads(sidecar.read_text())
        package = next(item for item in capture["packages"] if item["name"] == "attrs")
        package["files_sha256"] = package_digest(fixture / package["path"])
        sidecar.write_text(json.dumps(capture))
        self.assertTrue(verify(fixture).startswith("INVALID:"))

    def test_unpinned_required_schema_mutation_fails_via_external_inventory(self):
        temporary, fixture = self.copied_fixture()
        self.addCleanup(temporary.cleanup)
        schema = fixture / "repository/schemas/orchestration-task.schema.json"
        schema.write_text(schema.read_text() + " ")
        self.assertTrue(verify(fixture).startswith("INVALID:"))


if __name__ == "__main__":
    unittest.main()
