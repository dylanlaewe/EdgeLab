"""Skeptic characterization probes for the authentic Stage 1 planning package.

These tests preserve the published captures and exercise the reference replayer in
temporary copies.  A passing adversarial test records an accepted bypass; it does
not assert that the bypass is desirable behavior.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PYTHON = ROOT / ".venv/bin/python"
FREEZE = "bc3a40924ca580ca6eddc4c24e32ff99ddd95330"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _inventory(repository: Path) -> str:
    members = (
        (str(path.relative_to(repository)) + ":" + _sha(path)).encode()
        for path in repository.rglob("*")
        if path.is_file() and ".git" not in path.parts and "__pycache__" not in path.parts
    )
    return hashlib.sha256(b"".join(sorted(members))).hexdigest()


class AuthenticStage1PlanV13Skeptic(unittest.TestCase):
    def _isolated(self, family: str, name: str) -> tuple[tempfile.TemporaryDirectory, Path, Path]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name) / "root"
        (root / "tools").mkdir(parents=True)
        shutil.copy2(ROOT / "tools/replay_frozen_stage1_evidence.py", root / "tools")
        fixture_root = root / "tests/fixtures" / family
        fixture_root.mkdir(parents=True)
        shutil.copytree(ROOT / "tests/fixtures" / family / name, fixture_root / name)
        return temporary, root, fixture_root / name

    def _replay(self, root: Path, name: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(PYTHON), str(root / "tools/replay_frozen_stage1_evidence.py"), name],
            cwd=root,
            text=True,
            capture_output=True,
        )

    def _execute_retained(self, fixture: Path, manifest: dict) -> dict:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory) / "repository"
            shutil.copytree(fixture / "repository", repository)
            commands = (
                ["git", "init", "-q", str(repository)],
                ["git", "-C", str(repository), "config", "user.email", "replay@example.invalid"],
                ["git", "-C", str(repository), "config", "user.name", "replay"],
                ["git", "-C", str(repository), "add", "."],
                ["git", "-C", str(repository), "commit", "-qm", "replay"],
                ["git", "-C", str(repository), "remote", "add", "origin", "https://github.com/dylanlaewe/EdgeLab.git"],
                ["git", "-C", str(repository), "update-ref", "refs/remotes/origin/main", "HEAD"],
            )
            for command in commands:
                subprocess.run(command, check=True, capture_output=True)
            package_paths = [str(path) for path in (fixture / "packages").iterdir()]
            code = (
                "from pathlib import Path;import json;"
                "from edgelab.orchestration import decision;"
                "print(json.dumps(decision(Path('repository'),json.loads('''%s''')),"
                "sort_keys=True,separators=(',',':')))" % json.dumps(manifest["intent"])
            )
            environment = {
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONHASHSEED": "0",
                "LC_ALL": "C.UTF-8",
                "TZ": "UTC",
                "PYTHONIOENCODING": "utf-8",
                "PATH": os.environ["PATH"],
                "PYTHONPATH": os.pathsep.join([str(repository / "src"), *package_paths]),
            }
            return json.loads(
                subprocess.check_output(
                    [sys.executable, "-S", "-c", code], cwd=directory, env=environment, text=True
                )
            )

    def test_retained_decision_critical_source_matches_frozen_commit(self):
        paths = (
            "src/edgelab/orchestration.py",
            "schemas/orchestration-task.schema.json",
            "schemas/scheduler-state.schema.json",
        )
        for relative in paths:
            frozen = subprocess.check_output(["git", "show", f"{FREEZE}:{relative}"])
            retained = ROOT / "tests/fixtures/authentic-stage1/dispatch/repository" / relative
            self.assertEqual(retained.read_bytes(), frozen, relative)

    def test_exact_published_replays_still_pass(self):
        expected = {
            "dispatch": ("DISPATCH", "D-0a6e8268c4309df969a5384c4ce33063"),
            "deny": ("DENY", "D-25150701cc9d3f301f686d420e407c2f"),
            "dependency:satisfied": ("DISPATCH", "D-03d6aa8e833902266a2547b9393ebd94"),
            "dependency:content-sha-denied": ("DENY", "D-dd4e6244a8643854f113bef4892a457d"),
        }
        for name, pair in expected.items():
            process = subprocess.run(
                [str(PYTHON), str(ROOT / "tools/replay_frozen_stage1_evidence.py"), name],
                cwd=ROOT,
                text=True,
                capture_output=True,
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            result = json.loads(process.stdout)
            self.assertEqual((result["decision"], result["decision_id"]), pair)

    def test_self_consistent_forged_frozen_source_and_output_are_accepted(self):
        temporary, root, fixture = self._isolated("authentic-stage1", "dispatch")
        self.addCleanup(temporary.cleanup)
        source = fixture / "repository/src/edgelab/orchestration.py"
        source.write_text(
            source.read_text().replace(
                "repository-resolved synthetic task passed preflight",
                "self-consistent forged replay accepted",
            )
        )
        capture_path = fixture / "capture.json"
        capture = json.loads(capture_path.read_text())
        capture["repository_inventory_sha256"] = _inventory(fixture / "repository")
        capture["result"] = self._execute_retained(fixture, capture)
        capture_path.write_text(json.dumps(capture, indent=2) + "\n")
        process = self._replay(root, "dispatch")
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(json.loads(process.stdout)["reason"], "self-consistent forged replay accepted")

    def test_freeze_and_historical_git_labels_are_not_verified(self):
        temporary, root, fixture = self._isolated("authentic-stage1", "dispatch")
        self.addCleanup(temporary.cleanup)
        capture_path = fixture / "capture.json"
        capture = json.loads(capture_path.read_text())
        capture["freeze_commit"] = "f" * 40
        capture["head"] = "e" * 40
        capture["origin_main"] = "d" * 40
        capture_path.write_text(json.dumps(capture))
        process = self._replay(root, "dispatch")
        self.assertEqual(process.returncode, 0, process.stderr)

    def test_declared_runtime_package_hash_is_not_verified(self):
        temporary, root, fixture = self._isolated("authentic-stage1", "dispatch")
        self.addCleanup(temporary.cleanup)
        package_file = next((fixture / "packages/attrs").rglob("__init__.py"))
        package_file.write_text(package_file.read_text() + "\n# skeptic retained-package mutation\n")
        process = self._replay(root, "dispatch")
        self.assertEqual(process.returncode, 0, process.stderr)

    def test_dependency_capture_has_no_repository_or_package_binding(self):
        capture = json.loads(
            (ROOT / "tests/fixtures/authentic-stage1-dependency/satisfied/capture.json").read_text()
        )
        self.assertNotIn("repository_inventory_sha256", capture)
        self.assertNotIn("packages", capture)
        temporary, root, fixture = self._isolated("authentic-stage1-dependency", "satisfied")
        self.addCleanup(temporary.cleanup)
        source = fixture / "repository/src/edgelab/orchestration.py"
        source.write_text(source.read_text() + "\n# unbound retained-source mutation\n")
        process = self._replay(root, "dependency:satisfied")
        self.assertEqual(process.returncode, 0, process.stderr)

    def test_currentness_evidence_is_declarative_not_executable(self):
        matrix = (ROOT / "docs/M0.2_DECISION_EVIDENCE_ACCEPTANCE_MATRIX.v8.md").read_text()
        self.assertIn("A later implementation must add complete authoritative currentness checks", matrix)
        dependency = json.loads(
            (ROOT / "reports/authentic-stage1-dependency/currentness-results.v1.json").read_text()
        )
        non_dependency = json.loads(
            (ROOT / "reports/authentic-stage1-dependency/non-dependency-currentness-results.v1.json").read_text()
        )
        self.assertTrue(dependency)
        self.assertTrue(non_dependency)
        self.assertFalse((ROOT / "tools/verify_stage1_currentness.py").exists())

    def test_published_claimed_work_has_no_completion_and_promised_versions_are_absent(self):
        claim = json.loads((ROOT / "docs/handoffs/H-M0-074.v1.json").read_text())
        self.assertEqual(claim["status"], "CLAIMED")
        self.assertFalse((ROOT / "docs/handoffs/H-M0-074.v2.json").exists())
        self.assertFalse((ROOT / "schemas/m0-2-decision-evidence-envelope.v13.schema.json").exists())
        self.assertFalse((ROOT / "docs/M0.3A_TRANSACTIONAL_CONTRACT.v14.md").exists())


if __name__ == "__main__":
    unittest.main()
