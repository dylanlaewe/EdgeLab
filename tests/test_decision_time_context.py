from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from src.edgelab.decision_time_context import (
    CONTEXT_ID,
    ContextError,
    capture_context,
    compare_context,
    observe_context,
    verify_context_integrity,
)
from src.edgelab.transactional_scheduler import EXPECTED_REMOTE, Scheduler, digest
from src.edgelab.validate import ROOT


TASK_ID = "T-SYNTHETIC-001"


def encoded(value: dict) -> bytes:
    return json.dumps(value, indent=2, sort_keys=True).encode() + b"\n"


def create_task(scheduler: Scheduler, *, claim: bool = False) -> None:
    scheduler.initialize()
    response = scheduler.create_task(TASK_ID, digest({"test": "h-m0-188"}), owner="synthetic-director")
    if claim:
        before = response["tuple"]
        scheduler.transition(
            "CLAIM", TASK_ID,
            {"expected": before, "repository_generation": before["repository_generation"], "receipt_digest": before["decision_receipt_digest"], "actor": "synthetic-context"},
            operation_key="claim-context",
        )


class DecisionTimeContextTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp = tempfile.TemporaryDirectory()
        cls.runtime = Path(cls.temp.name) / "canonical-runtime"
        cls.scheduler = Scheduler(ROOT, cls.runtime)
        create_task(cls.scheduler, claim=True)
        cls.context = capture_context(cls.scheduler, TASK_ID)
        cls.raw = encoded(cls.context)
        cls.raw_sha = hashlib.sha256(cls.raw).hexdigest()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp.cleanup()

    def test_fresh_capture_reads_actual_sources_and_is_closed_deny_only(self) -> None:
        record = self.context
        self.assertEqual(record["context_id"], CONTEXT_ID)
        self.assertTrue(verify_context_integrity(record))
        self.assertEqual(record["verification"]["currentness_status"], "UNKNOWN")
        self.assertEqual(record["verification"]["authorizing_use"], "DENY")
        self.assertFalse(record["verification"]["authenticated_receipt"])
        self.assertFalse(record["observation_boundary"]["atomic_cross_system_snapshot"])
        self.assertEqual(record["actual_m0_2_decision_inputs"]["classification"], "ACTUAL_FROZEN_M0_2_INPUT_CLOSURE")
        self.assertTrue(record["actual_m0_2_decision_inputs"]["not_retrofitted"])
        locators = {item["locator"] for item in record["contextual_evidence"]["source_records"]}
        self.assertTrue({
            "docs/project-state.json",
            "orchestration/tasks/T-SYNTHETIC-001.v1.json",
            "orchestration/assignments/T-SYNTHETIC-001.v1.json",
            "orchestration/handoff-bindings/T-SYNTHETIC-001.v1.json",
            "docs/handoffs/H-M0-038.v2.json",
            "orchestration/capabilities/C-REPOSITORY-READ.json",
            "git:HEAD", "git:origin", "scheduler:bundle",
            "runtime:attachment.json", "sqlite:runtime.sqlite#locked-authority",
        }.issubset(locators))

    def test_unchanged_context_reproduces(self) -> None:
        result = compare_context(self.scheduler, self.raw, self.raw_sha)
        self.assertEqual(result["status"], "UNCHANGED_CONTEXT_UNKNOWN_DENY")
        self.assertEqual(result["changed_dimensions"], [])
        self.assertEqual(result["verification"]["authorizing_use"], "DENY")

    def test_tampered_incomplete_resealed_and_substituted_artifacts_reject(self) -> None:
        tampered = self.raw.replace(b"UNKNOWN", b"CURRENT", 1)
        self.assertEqual(compare_context(self.scheduler, tampered, self.raw_sha)["failure_reason"], "ARTIFACT_DIGEST_MISMATCH")

        incomplete = copy.deepcopy(self.context)
        incomplete["contextual_evidence"].pop("source_facts")
        incomplete["context_sha256"] = digest({key: value for key, value in incomplete.items() if key != "context_sha256"})
        raw = encoded(incomplete)
        result = compare_context(self.scheduler, raw, hashlib.sha256(raw).hexdigest())
        self.assertEqual(result["failure_reason"], "ARTIFACT_INTEGRITY_INVALID")

        resealed = copy.deepcopy(self.context)
        resealed["limitations"][0] = "context is authoritative"
        resealed["context_sha256"] = digest({key: value for key, value in resealed.items() if key != "context_sha256"})
        resealed_raw = encoded(resealed)
        self.assertEqual(compare_context(self.scheduler, resealed_raw, self.raw_sha)["failure_reason"], "ARTIFACT_DIGEST_MISMATCH")

        substituted = copy.deepcopy(self.context)
        substituted["task_id"] = "T-SUBSTITUTED"
        substituted["contextual_evidence"]["subject"]["task_id"] = "T-SUBSTITUTED"
        substituted["context_sha256"] = digest({key: value for key, value in substituted.items() if key != "context_sha256"})
        raw = encoded(substituted)
        self.assertEqual(compare_context(self.scheduler, raw, hashlib.sha256(raw).hexdigest())["failure_reason"], "ARTIFACT_INTEGRITY_INVALID")

    def test_legacy_frozen_capture_bytes_are_unchanged(self) -> None:
        historical = ROOT / self.context["actual_m0_2_decision_inputs"]["capture_fixture_path"] / "authentic-capture.v1.json"
        self.assertEqual(hashlib.sha256(historical.read_bytes()).hexdigest(), self.context["actual_m0_2_decision_inputs"]["capture_sidecar_sha256"])


class DisposableDriftTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp.name) / "repo"
        subprocess.run(["git", "clone", "--quiet", "--no-hardlinks", str(ROOT), str(self.repo)], check=True)
        subprocess.run(["git", "-C", str(self.repo), "remote", "set-url", "origin", EXPECTED_REMOTE], check=True)
        subprocess.run(["git", "-C", str(self.repo), "config", "user.email", "synthetic@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "config", "user.name", "Synthetic Test"], check=True)
        self.scheduler = Scheduler(self.repo, Path(self.temp.name) / "runtime")
        create_task(self.scheduler)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def artifact(self) -> tuple[bytes, str]:
        observed = observe_context(self.scheduler, TASK_ID)
        artifact = copy.deepcopy(DecisionTimeContextTests.context)
        artifact["contextual_evidence"] = {"classification": "SEPARATELY_OBSERVED_CONTEXT_NOT_DECISION_INPUT", **observed}
        artifact["context_sha256"] = digest({key: value for key, value in artifact.items() if key != "context_sha256"})
        self.assertTrue(verify_context_integrity(artifact, root=ROOT))
        raw = encoded(artifact)
        return raw, hashlib.sha256(raw).hexdigest()

    def mutate_json(self, relative: str, field: str, value: str) -> None:
        path = self.repo / relative
        record = json.loads(path.read_text())
        record[field] = value
        path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")

    def test_project_stop_assignment_handoff_and_dependency_capability_drift(self) -> None:
        cases = [
            ("docs/project-state.json", "status", "SYNTHETIC-DRIFT", "project_stop"),
            ("orchestration/assignments/T-SYNTHETIC-001.v1.json", "status", "SYNTHETIC-DRIFT", "assignment_handoff"),
            ("orchestration/capabilities/C-REPOSITORY-READ.json", "description", "SYNTHETIC-DRIFT", "dependency_capability"),
        ]
        for index, (path, field, value, expected) in enumerate(cases):
            with self.subTest(expected=expected):
                raw, pin = self.artifact()
                self.mutate_json(path, field, value + str(index))
                self.scheduler.import_repository([TASK_ID], reason="H-M0-188-DRIFT-TEST")
                result = compare_context(self.scheduler, raw, pin)
                self.assertEqual(result["status"], "DRIFT_DETECTED_DENY")
                self.assertIn(expected, result["changed_dimensions"])

    def test_git_head_and_runtime_generation_drift(self) -> None:
        raw, pin = self.artifact()
        subprocess.run(["git", "-C", str(self.repo), "commit", "--allow-empty", "-m", "synthetic head drift"], check=True, capture_output=True)
        result = compare_context(self.scheduler, raw, pin)
        self.assertEqual(result["status"], "DRIFT_DETECTED_DENY")
        self.assertIn("git_repository", result["changed_dimensions"])

        raw, pin = self.artifact()
        authority = observe_context(self.scheduler, TASK_ID)["subject"]
        with self.scheduler.connect(read_only=True) as connection:
            row = connection.execute("SELECT * FROM tasks WHERE task_id=?", (TASK_ID,)).fetchone()
            before = self.scheduler.tuple(row)
        self.scheduler.transition(
            "CLAIM", TASK_ID,
            {"expected": before, "repository_generation": before["repository_generation"], "receipt_digest": before["decision_receipt_digest"], "actor": "synthetic-drift"},
            operation_key="generation-drift",
        )
        result = compare_context(self.scheduler, raw, pin)
        self.assertEqual(result["status"], "DRIFT_DETECTED_DENY")
        self.assertIn("runtime_generation", result["changed_dimensions"])
        self.assertIn("attachment_task_attempt_claim_fence", result["changed_dimensions"])

    def test_read_recheck_race_rejects(self) -> None:
        def race() -> None:
            with self.scheduler.connect(read_only=True) as connection:
                row = connection.execute("SELECT * FROM tasks WHERE task_id=?", (TASK_ID,)).fetchone()
                before = self.scheduler.tuple(row)
            self.scheduler.transition(
                "CLAIM", TASK_ID,
                {"expected": before, "repository_generation": before["repository_generation"], "receipt_digest": before["decision_receipt_digest"], "actor": "synthetic-race"},
                operation_key="race-claim",
            )
        with self.assertRaisesRegex(ContextError, "OBSERVATION_RACE"):
            observe_context(self.scheduler, TASK_ID, after_first_read=race)


if __name__ == "__main__":
    unittest.main()
