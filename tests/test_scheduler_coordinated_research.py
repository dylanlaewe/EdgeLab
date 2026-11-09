"""Focused integration and adversarial tests for H-M0-184."""
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

import src.edgelab.scheduler_coordinated_research as coordinated
from src.edgelab.synthetic_research_experiment import SyntheticResearchError
from src.edgelab.transactional_scheduler import RuntimeUnavailable, Scheduler, digest


ROOT = coordinated.CANONICAL_ROOT
RESULT_PATH = ROOT / "reports/synthetic-research/H-M0-184-result.v1.json"
TOOL = ROOT / "tools/run_scheduler_coordinated_research.py"


class SchedulerCoordinatedResearchTests(unittest.TestCase):
    def runtime_path(self, label: str) -> Path:
        path = Path(tempfile.mkdtemp(prefix=f"edgelab-hm0184-{label}-"))
        path.rmdir()
        self.addCleanup(lambda: shutil.rmtree(path, ignore_errors=True))
        return path

    def assert_scheduler_code(self, code: str, callback) -> None:
        with self.assertRaises(coordinated.SchedulerResearchError) as raised:
            callback()
        self.assertEqual(raised.exception.code, code)

    def test_end_to_end_runs_are_deterministic_and_match_retained_result(self):
        expected = json.loads(RESULT_PATH.read_text(encoding="utf-8"))
        first = coordinated.run_scheduler_coordinated_research(self.runtime_path("one"))
        second = coordinated.run_scheduler_coordinated_research(self.runtime_path("two"))
        self.assertEqual(first, expected)
        self.assertEqual(second, expected)
        self.assertEqual(first["result_sha256"], digest({
            key: value for key, value in first.items() if key != "result_sha256"
        }))

    def test_scheduler_records_exact_stage_order_and_native_review(self):
        result = coordinated.run_scheduler_coordinated_research(self.runtime_path("order"))
        pipeline = result["task_histories"]["pipeline"]
        self.assertEqual(
            [event["event_type"] for event in pipeline["events"]],
            [
                "TASK_INITIALIZED", "CLAIM_ISSUED", "TASK_STARTED",
                "TASK_CONTINUED", "TASK_CONTINUED", "TASK_CONTINUED",
                "TASK_COMPLETED", "REVIEW_ASSIGNED", "REVIEW_APPROVED",
                "DIRECTOR_ROUTED",
            ],
        )
        self.assertEqual(
            [event.get("stage") for event in pipeline["events"] if event["event_type"] == "TASK_CONTINUED"],
            ["RESEARCH", "DATA", "QUANT"],
        )
        skeptic = result["stages"]["synthetic_skeptic"]
        self.assertEqual(pipeline["events"][8]["decision_digest"], skeptic["evidence_sha256"])
        self.assertFalse(skeptic["scheduler_binding"]["formal_approval"])

    def test_skeptic_evaluates_inside_active_native_review_assignment(self):
        runtime = self.runtime_path("review-window")
        original = coordinated._skeptic_stage
        observed = []

        def inspected(*args, **kwargs):
            connection = sqlite3.connect(runtime / "runtime.sqlite")
            try:
                task = connection.execute(
                    "SELECT workflow,execution,review,reviewer_id FROM tasks WHERE task_id=?",
                    (coordinated.PIPELINE_TASK_ID,),
                ).fetchone()
                reviews = connection.execute(
                    "SELECT actor,role,status FROM reviews WHERE task_id=?",
                    (coordinated.PIPELINE_TASK_ID,),
                ).fetchall()
                downstream = connection.execute(
                    "SELECT COUNT(*) FROM tasks WHERE task_id IN (?,?)",
                    (coordinated.RISK_TASK_ID, coordinated.DIRECTOR_TASK_ID),
                ).fetchone()[0]
            finally:
                connection.close()
            self.assertEqual(task[:3], ("ACTIVE", "EXECUTION_COMPLETED", "REVIEWING"))
            self.assertIsNotNone(task[3])
            self.assertEqual(
                reviews,
                [("synthetic-skeptic", "05 Skeptic synthetic non-formal", "ACTIVE")],
            )
            self.assertEqual(downstream, 0)
            observed.append("SYNTHETIC_SKEPTIC")
            return original(*args, **kwargs)

        with patch.object(coordinated, "_skeptic_stage", side_effect=inspected):
            coordinated.run_scheduler_coordinated_research(runtime)
        self.assertEqual(observed, ["SYNTHETIC_SKEPTIC"])

    def test_risk_and_director_receipts_bind_verified_predecessor_histories(self):
        result = coordinated.run_scheduler_coordinated_research(self.runtime_path("dependencies"))
        histories = result["task_histories"]
        stages = result["stages"]
        pipeline_sha = digest(histories["pipeline"])
        expected_risk = digest({
            "dependency_task": coordinated.PIPELINE_TASK_ID,
            "dependency_history_sha256": pipeline_sha,
            "quant_evidence_sha256": stages["quant"]["evidence_sha256"],
            "skeptic_evidence_sha256": stages["synthetic_skeptic"]["evidence_sha256"],
            "authorizing_use": "DENY",
        })
        self.assertEqual(histories["risk"]["receipt_digest"], expected_risk)
        risk_history_sha = digest(histories["risk"])
        expected_director = digest({
            "dependency_task": coordinated.RISK_TASK_ID,
            "dependency_history_sha256": risk_history_sha,
            "risk_evidence_sha256": stages["risk"]["evidence_sha256"],
            "pipeline_history_sha256": pipeline_sha,
            "authorizing_use": "DENY",
        })
        self.assertEqual(histories["director"]["receipt_digest"], expected_director)
        self.assertFalse(result["dependency_model"]["native_general_dependency_edge"])
        self.assertFalse(result["dependency_model"]["remediation_links_used_as_dependencies"])

    def test_risk_and_director_evaluate_inside_claimed_in_progress_tasks(self):
        runtime = self.runtime_path("claimed-stage-windows")
        original_risk = coordinated._risk_stage
        original_director = coordinated._director_stage
        observed = []

        def task_states():
            connection = sqlite3.connect(runtime / "runtime.sqlite")
            try:
                return {
                    row[0]: (row[1], row[2], row[3])
                    for row in connection.execute(
                        "SELECT task_id,workflow,execution,review FROM tasks"
                    )
                }
            finally:
                connection.close()

        def inspected_risk(*args, **kwargs):
            states = task_states()
            self.assertEqual(
                states[coordinated.RISK_TASK_ID],
                ("ACTIVE", "IN_PROGRESS", "NOT_REQUIRED"),
            )
            self.assertNotIn(coordinated.DIRECTOR_TASK_ID, states)
            observed.append("RISK")
            return original_risk(*args, **kwargs)

        def inspected_director(*args, **kwargs):
            states = task_states()
            self.assertEqual(
                states[coordinated.RISK_TASK_ID],
                ("CLOSED", "EXECUTION_COMPLETED", "NOT_REQUIRED"),
            )
            self.assertEqual(
                states[coordinated.DIRECTOR_TASK_ID],
                ("ACTIVE", "IN_PROGRESS", "NOT_REQUIRED"),
            )
            observed.append("DIRECTOR")
            return original_director(*args, **kwargs)

        with patch.object(coordinated, "_risk_stage", side_effect=inspected_risk), patch.object(
            coordinated, "_director_stage", side_effect=inspected_director
        ):
            coordinated.run_scheduler_coordinated_research(runtime)
        self.assertEqual(observed, ["RISK", "DIRECTOR"])

    def test_missing_pipeline_stage_blocks_risk_task_creation(self):
        runtime = self.runtime_path("missing-stage")
        original = coordinated._stable_history

        def missing_data(scheduler, task_id):
            history = original(scheduler, task_id)
            if task_id == coordinated.PIPELINE_TASK_ID:
                history["events"] = [
                    event for event in history["events"]
                    if event.get("stage") != "DATA"
                ]
            return history

        with patch.object(coordinated, "_stable_history", side_effect=missing_data):
            self.assert_scheduler_code(
                "PIPELINE_HISTORY_MISMATCH",
                lambda: coordinated.run_scheduler_coordinated_research(runtime),
            )
        connection = sqlite3.connect(runtime / "runtime.sqlite")
        try:
            task_ids = [row[0] for row in connection.execute("SELECT task_id FROM tasks")]
        finally:
            connection.close()
        self.assertEqual(task_ids, [coordinated.PIPELINE_TASK_ID])

    def test_altered_quant_output_rejects_before_quant_event(self):
        runtime = self.runtime_path("altered-quant")
        original = coordinated._quant_evaluate

        def altered(*args, **kwargs):
            result = original(*args, **kwargs)
            result["net_roi"] = "9.999999"
            return result

        with patch.object(coordinated, "_quant_evaluate", side_effect=altered):
            self.assert_scheduler_code(
                "ALTERED_STAGE_EVIDENCE",
                lambda: coordinated.run_scheduler_coordinated_research(runtime),
            )
        connection = sqlite3.connect(runtime / "runtime.sqlite")
        try:
            stages = []
            for (payload,) in connection.execute(
                "SELECT payload FROM task_events WHERE event_type='TASK_CONTINUED' ORDER BY task_seq"
            ):
                stages.append(json.loads(payload)["request"]["request"]["stage"])
        finally:
            connection.close()
        self.assertEqual(stages, ["RESEARCH", "DATA"])

    def test_future_leakage_blocks_data_and_all_downstream_stages(self):
        runtime = self.runtime_path("future-leak")
        original_read = coordinated.read

        def altered_read(path):
            value = original_read(path)
            if Path(path).resolve() == (ROOT / coordinated.INPUT_PATH).resolve():
                value["primary_observations"][0]["signal_published_at"] = "2026-01-03T10:11:00Z"
            return value

        with patch.object(coordinated, "read", side_effect=altered_read):
            with self.assertRaises(SyntheticResearchError) as raised:
                coordinated.run_scheduler_coordinated_research(runtime)
        self.assertEqual(raised.exception.code, "FUTURE_LEAKAGE")
        connection = sqlite3.connect(runtime / "runtime.sqlite")
        try:
            task_ids = [row[0] for row in connection.execute("SELECT task_id FROM tasks")]
        finally:
            connection.close()
        self.assertEqual(task_ids, [coordinated.PIPELINE_TASK_ID])

    def test_inconsistent_review_decision_fails_pipeline_history_check(self):
        result = json.loads(RESULT_PATH.read_text(encoding="utf-8"))
        history = json.loads(json.dumps(result["task_histories"]["pipeline"]))
        history["events"][8]["decision_digest"] = "0" * 64
        stages = result["stages"]
        self.assert_scheduler_code(
            "PIPELINE_HISTORY_MISMATCH",
            lambda: coordinated._verify_pipeline_history(
                history,
                history["receipt_digest"],
                stages["research"]["evidence_sha256"],
                stages["data"]["evidence_sha256"],
                stages["quant"]["evidence_sha256"],
                stages["synthetic_skeptic"]["evidence_sha256"],
                result["task_histories"]["pipeline"]["events"][9]["routing_evidence"],
            ),
        )

    def test_scheduler_replay_rejects_mutated_event_evidence(self):
        runtime = self.runtime_path("mutation")
        coordinated.run_scheduler_coordinated_research(runtime)
        connection = sqlite3.connect(runtime / "runtime.sqlite")
        try:
            row = connection.execute(
                "SELECT event_id,payload FROM task_events WHERE task_id=? AND task_seq=6",
                (coordinated.PIPELINE_TASK_ID,),
            ).fetchone()
            payload = json.loads(row[1])
            payload["request"]["request"]["output_evidence_sha256"] = "0" * 64
            connection.execute(
                "UPDATE task_events SET payload=? WHERE event_id=?",
                (json.dumps(payload), row[0]),
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaisesRegex(RuntimeUnavailable, "event digest mutation"):
            Scheduler(ROOT, runtime).startup()

    def test_missing_result_schema_fails_before_runtime_creation(self):
        runtime = self.runtime_path("missing-schema")
        with patch.object(
            coordinated,
            "RESULT_SCHEMA_PATH",
            Path("schemas/nonexistent-coordinated-result.schema.json"),
        ):
            with self.assertRaises(SyntheticResearchError) as raised:
                coordinated.run_scheduler_coordinated_research(runtime)
        self.assertEqual(raised.exception.code, "MISSING_SCHEMA")
        self.assertFalse(runtime.exists())

    def test_cli_json_and_human_outputs_are_reproducible(self):
        expected = json.loads(RESULT_PATH.read_text(encoding="utf-8"))
        json_run = subprocess.run(
            [sys.executable, str(TOOL), "--runtime-dir", str(self.runtime_path("cli-json")), "--format", "json"],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(json.loads(json_run.stdout), expected)
        text_run = subprocess.run(
            [sys.executable, str(TOOL), "--runtime-dir", str(self.runtime_path("cli-text")), "--format", "text"],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertIn("Scientific result: INSUFFICIENT_DATA", text_run.stdout)
        self.assertIn("Native general dependency edge: unavailable", text_run.stdout)
        self.assertIn("Authorization: DENY", text_run.stdout)

    def test_every_authority_projection_remains_deny(self):
        result = coordinated.run_scheduler_coordinated_research(self.runtime_path("deny"))
        self.assertEqual(result["authorization"]["authorizing_use"], "DENY")
        self.assertEqual(result["stages"]["risk"]["evidence"]["status"], "DENY")
        self.assertEqual(
            result["stages"]["director"]["evidence"]["output"]["authorization"],
            "DENY",
        )
        self.assertFalse(result["formal_skeptic_approval"])
        self.assertEqual(result["final_result"], "INSUFFICIENT_DATA")


if __name__ == "__main__":
    unittest.main()
