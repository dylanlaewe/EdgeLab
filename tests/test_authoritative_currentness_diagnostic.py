"""Focused H-M0-187 currentness diagnostic regressions."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import src.edgelab.authoritative_currentness_diagnostic as diagnostic
from src.edgelab.authority_binding import compose_authority_binding
from src.edgelab.locked_authority import read_locked_authority
from src.edgelab.transactional_scheduler import Bundle, Scheduler, digest


ROOT = diagnostic.CANONICAL_ROOT
TOOL = ROOT / "tools/run_authoritative_currentness_diagnostic.py"
RECOVERY_TOOL = ROOT / "tools/run_recoverable_scheduler_research.py"


class AuthoritativeCurrentnessDiagnosticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._class_tmp = tempfile.TemporaryDirectory(prefix="edgelab-hm0187-base-")
        cls.base = Path(cls._class_tmp.name) / "runtime"
        interrupted = subprocess.run(
            [sys.executable, str(RECOVERY_TOOL), "--runtime-dir", str(cls.base),
             "--interrupt-after", "QUANT", "--format", "json"],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
        if interrupted.returncode != 0:
            raise RuntimeError(interrupted.stderr)
        resumed = subprocess.run(
            [sys.executable, str(RECOVERY_TOOL), "--runtime-dir", str(cls.base),
             "--resume", "--format", "json"],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
        if resumed.returncode != 0:
            raise RuntimeError(resumed.stderr)
        recovered = json.loads(resumed.stdout)
        if recovered["status"] != "COMPLETED" or recovered["recovered_from"] != "QUANT":
            raise RuntimeError("cold H-M0-186 fixture did not recover")

        scheduler = Scheduler(ROOT, cls.base)
        scheduler.create_task(
            diagnostic.DEFAULT_TASK_ID,
            "untrusted-diagnostic-receipt",
            "synthetic-diagnostic-owner",
        )
        row = cls._row(scheduler)
        scheduler.transition(
            "CLAIM",
            diagnostic.DEFAULT_TASK_ID,
            {
                "expected": scheduler.tuple(row),
                "repository_generation": row["repository_generation"],
                "receipt_digest": row["receipt_digest"],
                "actor": "diagnostic-synthetic-worker",
            },
            operation_key="diagnostic-subject-claim",
        )
        scheduler.startup()

    @classmethod
    def tearDownClass(cls):
        cls._class_tmp.cleanup()

    @staticmethod
    def _row(scheduler: Scheduler):
        connection = scheduler.connect(read_only=True)
        try:
            return connection.execute(
                "SELECT * FROM tasks WHERE task_id=?",
                (diagnostic.DEFAULT_TASK_ID,),
            ).fetchone()
        finally:
            connection.close()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="edgelab-hm0187-case-")
        self.addCleanup(self.tmp.cleanup)
        self.runtime = Path(self.tmp.name) / "runtime"
        shutil.copytree(self.base, self.runtime)
        self.scheduler = Scheduler(ROOT, self.runtime)

    def assert_closed(self, result: dict) -> None:
        schema = json.loads(
            (ROOT / diagnostic.RESULT_SCHEMA_PATH).read_text(encoding="utf-8")
        )
        from jsonschema import Draft202012Validator
        Draft202012Validator(schema).validate(result)
        self.assertEqual(result["verification"]["currentness_status"], "UNKNOWN")
        self.assertEqual(result["verification"]["verifier_status"], "FAIL")
        self.assertFalse(result["verification"]["generation_match"])
        self.assertEqual(result["verification"]["authorizing_use"], "DENY")
        self.assertEqual(
            result["result_sha256"],
            digest({key: value for key, value in result.items() if key != "result_sha256"}),
        )
        self.assertTrue(diagnostic.verify_diagnostic_integrity(result))

    def runtime_state(self):
        connection = self.scheduler.connect(read_only=True)
        try:
            dump = "\n".join(connection.iterdump())
        finally:
            connection.close()
        files = {
            path.name: (digest(path.read_bytes()), path.stat().st_mode & 0o777)
            for path in self.runtime.iterdir()
            if path.is_file()
        }
        return dump, files

    def test_cold_recovered_runtime_is_coherent_but_unknown_and_deny(self):
        before = self.runtime_state()
        first = diagnostic.diagnose_authoritative_currentness(self.scheduler)
        second = diagnostic.diagnose_authoritative_currentness(self.scheduler)
        after = self.runtime_state()
        self.assert_closed(first)
        self.assertEqual(first, second)
        self.assertEqual(before, after)
        self.assertEqual(first["status"], "COHERENT_UNKNOWN_DENY")
        self.assertEqual(first["verification"]["historical_status"], "VALID")
        self.assertEqual(first["attempt"], 1)
        self.assertEqual(len(first["verified_dimensions"]), 10)
        self.assertEqual(len(first["unknown_dimensions"]), 6)
        self.assertIn("authenticated_receipt_binding", first["unknown_dimensions"])
        self.assertEqual(first["current_observation"]["claim"]["fence"], 1)
        self.assertEqual(
            [stop["status"] for stop in first["current_observation"]["repository"]["stops"]["active"]],
            ["OPEN", "OPEN", "OPEN"],
        )

    def test_cli_reopens_actual_persisted_runtime_read_only(self):
        before = self.runtime_state()
        process = subprocess.run(
            [sys.executable, str(TOOL), "--runtime-dir", str(self.runtime), "--format", "json"],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        result = json.loads(process.stdout)
        self.assert_closed(result)
        self.assertEqual(result["status"], "COHERENT_UNKNOWN_DENY")
        self.assertEqual(self.runtime_state(), before)

    def test_missing_historical_evidence_fails_closed(self):
        result = diagnostic.diagnose_authoritative_currentness(
            self.scheduler, capture_id="MISSING-CAPTURE"
        )
        self.assert_closed(result)
        self.assertEqual(result["status"], "UNAVAILABLE")
        self.assertEqual(
            result["failure_reason"], "HISTORICAL_BINDING_CAPTURE_UNKNOWN"
        )
        self.assertEqual(result["verification"]["historical_status"], "INVALID")

    def test_changed_task_or_attempt_fails_closed(self):
        wrong_task = diagnostic.diagnose_authoritative_currentness(
            self.scheduler, task_id="T-SYNTHETIC-SCIENCE-PIPELINE-001"
        )
        self.assert_closed(wrong_task)
        self.assertEqual(
            wrong_task["failure_reason"], "HISTORICAL_BINDING_SUBJECT_MISMATCH"
        )

        row = self._row(self.scheduler)
        claim_id = row["claim_id"]
        fence = row["task_fence"]
        base = {
            "expected": self.scheduler.tuple(row),
            "repository_generation": row["repository_generation"],
            "receipt_digest": row["receipt_digest"],
            "claim_id": claim_id,
            "fence": fence,
        }
        self.scheduler.transition(
            "START", diagnostic.DEFAULT_TASK_ID, base,
            operation_key="test-attempt-start",
        )
        row = self._row(self.scheduler)
        self.scheduler.transition(
            "FAIL", diagnostic.DEFAULT_TASK_ID,
            {
                "expected": self.scheduler.tuple(row),
                "repository_generation": row["repository_generation"],
                "receipt_digest": row["receipt_digest"],
                "claim_id": row["claim_id"],
                "fence": row["task_fence"],
            },
            operation_key="test-attempt-fail",
        )
        row = self._row(self.scheduler)
        self.scheduler.transition(
            "RETRY", diagnostic.DEFAULT_TASK_ID,
            {
                "expected": self.scheduler.tuple(row),
                "repository_generation": row["repository_generation"],
                "receipt_digest": row["receipt_digest"],
                "retryable": True,
            },
            operation_key="test-attempt-retry",
        )
        changed_attempt = diagnostic.diagnose_authoritative_currentness(self.scheduler)
        self.assert_closed(changed_attempt)
        self.assertEqual(
            changed_attempt["failure_reason"], "HISTORICAL_BINDING_SUBJECT_MISMATCH"
        )

    def test_stale_runtime_generation_and_bundle_fail_closed(self):
        original = self.scheduler.bundle()
        changed = Bundle(
            original.commit, "f" * 64, original.project, original.stops,
            original.policy, original.tasks,
        )
        with patch.object(self.scheduler, "bundle", return_value=changed):
            self.scheduler.import_repository([diagnostic.DEFAULT_TASK_ID])
        result = diagnostic.diagnose_authoritative_currentness(self.scheduler)
        self.assert_closed(result)
        self.assertEqual(result["status"], "UNAVAILABLE")
        self.assertEqual(
            result["failure_reason"], "HISTORICAL_BINDING_RUNTIME_UNAVAILABLE"
        )

    def test_changed_repository_or_stop_observation_fails_closed(self):
        actual = diagnostic._repository_sources(self.scheduler)
        changed = copy.deepcopy(actual)
        changed["repository"]["stops"] = "f" * 64
        changed["stops"]["inventory_sha256"] = "f" * 64
        with patch.object(diagnostic, "_repository_sources", return_value=changed):
            result = diagnostic.diagnose_authoritative_currentness(self.scheduler)
        self.assert_closed(result)
        self.assertEqual(result["failure_reason"], "CURRENT_AUTHORITY_MISMATCH")

    def test_missing_required_source_mapping_remains_fail_closed(self):
        original = diagnostic._dimension_definitions

        def incomplete(*args, **kwargs):
            return original(*args, **kwargs)[:-1]

        with patch.object(diagnostic, "_dimension_definitions", side_effect=incomplete):
            result = diagnostic.diagnose_authoritative_currentness(self.scheduler)
        self.assert_closed(result)
        self.assertEqual(result["failure_reason"], "SOURCE_MAPPING_INCOMPLETE")

    def test_changed_state_between_observation_and_recheck_is_race(self):
        actual = read_locked_authority(self.scheduler, diagnostic.DEFAULT_TASK_ID)
        raced = copy.deepcopy(actual)
        raced["authority_sha256"] = "f" * 64
        with patch.object(
            diagnostic, "read_locked_authority", side_effect=[actual, raced]
        ):
            result = diagnostic.diagnose_authoritative_currentness(self.scheduler)
        self.assert_closed(result)
        self.assertEqual(result["failure_reason"], "OBSERVATION_RACE")

    def test_positive_authorizing_substitution_is_rejected(self):
        binding = compose_authority_binding(
            self.scheduler, diagnostic.DEFAULT_TASK_ID, diagnostic.DEFAULT_CAPTURE_ID
        )
        forged = copy.deepcopy(binding)
        forged["verification"].update({
            "currentness_status": "CURRENT",
            "verifier_status": "PASS",
            "generation_match": True,
            "authorizing_use": "ALLOW",
            "reason_code": "NONE",
        })
        forged["candidate_sha256"] = digest({
            key: value for key, value in forged.items() if key != "candidate_sha256"
        })
        with patch.object(
            diagnostic, "compose_authority_binding", return_value=forged
        ):
            result = diagnostic.diagnose_authoritative_currentness(self.scheduler)
        self.assert_closed(result)
        self.assertEqual(result["failure_reason"], "HISTORICAL_BINDING_INVALID")
        self.assertEqual(result["verification"]["authorizing_use"], "DENY")

        coherent = diagnostic.diagnose_authoritative_currentness(self.scheduler)
        coherent["verification"].update({
            "currentness_status": "CURRENT",
            "verifier_status": "PASS",
            "generation_match": True,
            "authorizing_use": "ALLOW",
            "reason_code": "NONE",
        })
        from jsonschema import Draft202012Validator
        schema = json.loads(
            (ROOT / diagnostic.RESULT_SCHEMA_PATH).read_text(encoding="utf-8")
        )
        with self.assertRaises(Exception):
            Draft202012Validator(schema).validate(coherent)

    def test_resealed_nested_semantic_substitutions_are_rejected(self):
        original = diagnostic.diagnose_authoritative_currentness(self.scheduler)

        def rejected(mutator) -> None:
            forged = copy.deepcopy(original)
            mutator(forged)
            forged["result_sha256"] = digest({
                key: value for key, value in forged.items()
                if key != "result_sha256"
            })
            self.assertFalse(diagnostic.verify_diagnostic_integrity(forged))

        rejected(lambda record: record["current_observation"].update(
            authorization="ALLOW"
        ))

        def promote_unknown(record):
            target = next(
                item for item in record["dimensions"]
                if item["id"] == "historical_project_stop_equality"
            )
            target["status"] = "VERIFIED"
            target["reason"] = "attacker promoted"
            target["evidence_sha256"] = "f" * 64
            record["unknown_dimensions"].remove(target["id"])
            record["verified_dimensions"].append(target["id"])

        rejected(promote_unknown)

        def substitute_mapping(record):
            source = next(
                item for item in record["trusted_sources"]
                if item["id"] == "authority-source-mapping"
            )
            source["locator"] = "attacker/mapping.md"
            source["sha256"] = "f" * 64

        rejected(substitute_mapping)
        rejected(lambda record: record.update(
            limitations=["attacker-safe-0", "attacker-safe-1", "attacker-safe-2", "attacker-safe-3", "attacker-safe-4"]
        ))
        rejected(lambda record: record.update(
            invalidators=["ATTACKER_REWRITES_GATING"]
        ))

    def test_repository_race_is_detected_without_mutation(self):
        first = diagnostic._repository_sources(self.scheduler)
        second = copy.deepcopy(first)
        second["source_inventory_sha256"] = "e" * 64
        before = self.runtime_state()
        with patch.object(
            diagnostic, "_repository_sources", side_effect=[first, second]
        ):
            result = diagnostic.diagnose_authoritative_currentness(self.scheduler)
        self.assert_closed(result)
        self.assertEqual(result["failure_reason"], "OBSERVATION_RACE")
        self.assertEqual(self.runtime_state(), before)


if __name__ == "__main__":
    unittest.main()
