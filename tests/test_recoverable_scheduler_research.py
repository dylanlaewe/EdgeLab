"""Cold-process recovery and fail-closed regressions for H-M0-186."""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import src.edgelab.recoverable_scheduler_research as recovery
from src.edgelab.transactional_scheduler import RuntimeUnavailable, Scheduler


ROOT = recovery.CANONICAL_ROOT
TOOL = ROOT / "tools/run_recoverable_scheduler_research.py"
H184_RESULT = ROOT / "reports/synthetic-research/H-M0-184-result.v1.json"
H186_RESULT = ROOT / "reports/synthetic-research/H-M0-186-result.v1.json"


class RecoverableSchedulerResearchTests(unittest.TestCase):
    def runtime_path(self, label: str) -> Path:
        path = Path(tempfile.mkdtemp(prefix=f"edgelab-hm0186-{label}-"))
        path.rmdir()
        self.addCleanup(lambda: shutil.rmtree(path, ignore_errors=True))
        return path

    def cli(self, runtime: Path, *arguments: str) -> dict:
        process = subprocess.run(
            [sys.executable, str(TOOL), "--runtime-dir", str(runtime), *arguments, "--format", "json"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        return json.loads(process.stdout)

    @staticmethod
    def task_event_count(runtime: Path) -> int:
        connection = sqlite3.connect(runtime / "runtime.sqlite")
        try:
            return connection.execute("SELECT COUNT(*) FROM task_events").fetchone()[0]
        finally:
            connection.close()

    def assert_cold_recovery(self, point: str, expected_resume: str) -> dict:
        runtime = self.runtime_path(point.lower())
        interrupted = self.cli(runtime, "--interrupt-after", point)
        self.assertEqual(interrupted["status"], "INTERRUPTED")
        self.assertEqual(interrupted["interruption_after"], point)
        self.assertEqual(interrupted["authorization"]["authorizing_use"], "DENY")

        completed = self.cli(runtime, "--resume")
        self.assertEqual(completed["status"], "COMPLETED")
        self.assertEqual(completed["recovered_from"], expected_resume)
        self.assertEqual(completed["coordinated_result"]["final_result"], "INSUFFICIENT_DATA")
        self.assertEqual(completed["coordinated_result"]["authorization"]["authorizing_use"], "DENY")
        self.assertFalse(completed["formal_skeptic_approval"])

        before = self.task_event_count(runtime)
        repeated = self.cli(runtime, "--resume")
        after = self.task_event_count(runtime)
        self.assertEqual(repeated["coordinated_result"], completed["coordinated_result"])
        self.assertEqual(after, before)
        return completed

    def test_actual_cold_process_recovery_after_research(self):
        completed = self.assert_cold_recovery("RESEARCH", "RESEARCH")
        retained = json.loads(H186_RESULT.read_text(encoding="utf-8"))
        expected = json.loads(H184_RESULT.read_text(encoding="utf-8"))
        self.assertEqual(completed, retained)
        self.assertEqual(completed["coordinated_result"], expected)

    def test_actual_cold_process_recovery_after_quant(self):
        self.assert_cold_recovery("QUANT", "QUANT")

    def test_actual_cold_process_recovery_during_native_review(self):
        self.assert_cold_recovery("REVIEW_ASSIGNED", "REVIEW_ASSIGNED")

    def test_actual_cold_process_recovery_after_downstream_task_creation(self):
        self.assert_cold_recovery("RISK_CREATED", "RISK")

    def test_stage_evaluation_occurs_only_after_scheduler_predecessor(self):
        runtime = self.runtime_path("stage-windows")
        original_data = recovery._data_stage
        original_quant = recovery._quant_stage
        original_skeptic = recovery._skeptic_stage
        observed = []

        def state():
            connection = sqlite3.connect(runtime / "runtime.sqlite")
            try:
                row = connection.execute(
                    "SELECT execution,review,continuations FROM tasks WHERE task_id=?",
                    (recovery.PIPELINE_TASK_ID,),
                ).fetchone()
                return row
            finally:
                connection.close()

        def checked_data(*args, **kwargs):
            self.assertEqual(state(), ("IN_PROGRESS", "NOT_REQUIRED", 1))
            observed.append("DATA")
            return original_data(*args, **kwargs)

        def checked_quant(*args, **kwargs):
            self.assertEqual(state(), ("IN_PROGRESS", "NOT_REQUIRED", 2))
            observed.append("QUANT")
            return original_quant(*args, **kwargs)

        def checked_skeptic(*args, **kwargs):
            self.assertEqual(state(), ("EXECUTION_COMPLETED", "REVIEWING", 3))
            observed.append("SKEPTIC")
            return original_skeptic(*args, **kwargs)

        with patch.object(recovery, "_data_stage", side_effect=checked_data), patch.object(
            recovery, "_quant_stage", side_effect=checked_quant
        ), patch.object(recovery, "_skeptic_stage", side_effect=checked_skeptic):
            result = recovery.run_recoverable_scheduler_research(runtime)
        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(observed, ["DATA", "QUANT", "SKEPTIC"])

    def test_claimed_pre_start_interruption_without_liveness_authority_fails_closed(self):
        runtime = self.runtime_path("claimed")
        package, _ = recovery._load_retained(ROOT)
        scheduler = Scheduler(ROOT, runtime)
        scheduler.initialize()
        receipt = recovery._pipeline_receipt(package)
        scheduler.create_task(
            recovery.PIPELINE_TASK_ID,
            receipt,
            "03 Research synthetic coordinator",
        )
        recovery._transition(
            scheduler,
            "CLAIM",
            recovery.PIPELINE_TASK_ID,
            {"actor": "synthetic-science-worker"},
            "test-interrupted-claim",
        )

        before = self.task_event_count(runtime)
        with self.assertRaises(recovery.RecoveryError) as raised:
            recovery.run_recoverable_scheduler_research(runtime, resume=True)
        self.assertEqual(
            raised.exception.code, "CLAIMED_WITHOUT_AUTHENTICATED_LIVENESS"
        )
        self.assertEqual(self.task_event_count(runtime), before)

    def test_changed_recorded_evidence_fails_before_next_transition(self):
        runtime = self.runtime_path("changed-evidence")
        recovery.run_recoverable_scheduler_research(runtime, interrupt_after="RESEARCH")
        original = recovery._stable_history

        def changed(scheduler, task_id):
            history = original(scheduler, task_id)
            if task_id == recovery.PIPELINE_TASK_ID:
                history["events"][-1]["output_evidence_sha256"] = "0" * 64
            return history

        with patch.object(recovery, "_stable_history", side_effect=changed):
            with self.assertRaises(recovery.RecoveryError) as raised:
                recovery.run_recoverable_scheduler_research(runtime, resume=True)
        self.assertEqual(raised.exception.code, "PIPELINE_HISTORY_MISMATCH")
        self.assertEqual(self.task_event_count(runtime), 4)

    def test_corrupted_event_history_fails_scheduler_startup_replay(self):
        runtime = self.runtime_path("corrupt")
        recovery.run_recoverable_scheduler_research(runtime, interrupt_after="RESEARCH")
        connection = sqlite3.connect(runtime / "runtime.sqlite")
        try:
            connection.execute(
                "UPDATE task_events SET payload=? WHERE task_id=? AND task_seq=4",
                ("{}", recovery.PIPELINE_TASK_ID),
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(RuntimeUnavailable):
            recovery.run_recoverable_scheduler_research(runtime, resume=True)

    def test_missing_history_fails_scheduler_startup_replay(self):
        runtime = self.runtime_path("missing")
        recovery.run_recoverable_scheduler_research(runtime, interrupt_after="RESEARCH")
        connection = sqlite3.connect(runtime / "runtime.sqlite")
        try:
            connection.execute(
                "DELETE FROM task_events WHERE task_id=? AND task_seq=4",
                (recovery.PIPELINE_TASK_ID,),
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(RuntimeUnavailable):
            recovery.run_recoverable_scheduler_research(runtime, resume=True)

    def test_stale_claim_materialization_fails_scheduler_startup_replay(self):
        runtime = self.runtime_path("stale-claim")
        recovery.run_recoverable_scheduler_research(runtime, interrupt_after="RESEARCH")
        connection = sqlite3.connect(runtime / "runtime.sqlite")
        try:
            connection.execute(
                "UPDATE claims SET actor='forged-worker' WHERE status='ACTIVE'"
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(RuntimeUnavailable):
            recovery.run_recoverable_scheduler_research(runtime, resume=True)

    def test_incompatible_task_generation_fails_scheduler_startup_replay(self):
        runtime = self.runtime_path("generation")
        recovery.run_recoverable_scheduler_research(runtime, interrupt_after="RESEARCH")
        connection = sqlite3.connect(runtime / "runtime.sqlite")
        try:
            connection.execute(
                "UPDATE tasks SET repository_generation=repository_generation+1 WHERE task_id=?",
                (recovery.PIPELINE_TASK_ID,),
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(RuntimeUnavailable):
            recovery.run_recoverable_scheduler_research(runtime, resume=True)

    def test_runtime_mode_and_unrecognized_task_fail_closed(self):
        missing = self.runtime_path("missing-runtime")
        with self.assertRaises(recovery.RecoveryError) as raised:
            recovery.run_recoverable_scheduler_research(missing, resume=True)
        self.assertEqual(raised.exception.code, "RUNTIME_MODE_MISMATCH")

        runtime = self.runtime_path("unexpected-task")
        scheduler = Scheduler(ROOT, runtime)
        scheduler.initialize()
        scheduler.create_task("T-UNRECOGNIZED", "receipt", "other")
        with self.assertRaises(recovery.RecoveryError) as raised:
            recovery.run_recoverable_scheduler_research(runtime, resume=True)
        self.assertEqual(raised.exception.code, "UNEXPECTED_TASK_IN_RUNTIME")


if __name__ == "__main__":
    unittest.main()
