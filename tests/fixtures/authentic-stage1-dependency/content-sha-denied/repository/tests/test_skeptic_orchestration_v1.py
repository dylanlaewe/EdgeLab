"""Versioned Skeptic adversarial probes for the M0.2 mock-only orchestrator.

These probes preserve demonstrated behavior.  Tests named ``demonstrates`` are
expected to pass when they reproduce a governance weakness; they are evidence,
not assertions that the behavior is desirable.
"""
from __future__ import annotations

import tempfile
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from src.edgelab.orchestration import EXPECTED_REMOTE, completion, decision
from src.edgelab.validate import ROOT, read, validate_record


class SkepticOrchestrationV1(unittest.TestCase):
    def task(self, **changes):
        task = {
            "task_id": "T-SYNTHETIC-1",
            "milestone": "M0.2",
            "action_classification": "SYNTHETIC_TEST",
            "assigned_role": "00 Director",
            "status": "QUEUED",
            "dependencies": [],
            "handoff_ref": "docs/handoffs/H-M0-027.v2.json",
            "attempt": 1,
            "review_required": True,
            "reviewer_role": "05 Skeptic",
        }
        task.update(changes)
        return task

    def state_and_stop(self):
        return read(ROOT / "docs/project-state.json"), read(
            ROOT / "reports/stops/STOP-M0-001.v1.json"
        )

    def test_action_default_denials_and_valid_control(self):
        self.assertEqual(decision(ROOT, self.task(), completed=set())["decision"], "DISPATCH")
        schema_valid_other = self.task(
            schema_version=1,
            action_classification="OTHER",
            created_at="2026-09-29T00:00:00Z",
            updated_at="2026-09-29T00:00:00Z",
            blocking_reason=None,
            completion_evidence=[],
        )
        validate_record("orchestration-task", schema_valid_other)
        self.assertEqual(decision(ROOT, schema_valid_other, completed=set())["decision"], "DENY")
        for value in (
            None,
            "",
            7,
            "synthetic_test",
            " SYNTHETIC_TEST",
            "SYNTHETIC-TEST",
            "SYNTHETIC_TЕST",  # Cyrillic lookalike E.
            "OTHER",
            "DEPRECATED_SYNTHETIC_TEST",
            "SCOUT_DISCOVERY",
            "EXTERNAL_INGESTION",
            "RESEARCH_CAMPAIGN",
            "QUANT_REAL_EXPERIMENT",
            "PAPER_PORTFOLIO",
            "LIVE_EXECUTION",
            "CAPITAL_MUTATION",
            "PLUGIN_INSTALL",
            "CREDENTIAL_PROVISIONING",
            "NETWORK_EXECUTION_ADAPTER",
            "EXTERNAL_SOURCE_ACQUISITION",
        ):
            self.assertEqual(
                decision(ROOT, self.task(action_classification=value), completed=set())["decision"],
                "DENY",
            )

    def test_demonstrates_schema_and_semantic_label_bypass(self):
        incomplete = {
            "task_id": "REAL-WORK-DISGUISED",
            "milestone": "M0.2",
            "action_classification": "SYNTHETIC_TEST",
            "handoff_ref": "docs/handoffs/H-M0-027.v2.json",
            "operation": "LIVE_EXECUTION",
            "payload": {"source": "external-sports-market", "network": True},
        }
        result = decision(ROOT, incomplete, completed=set())
        self.assertEqual(result["decision"], "DISPATCH")
        self.assertEqual(result["execution_adapter"], "MOCK_ONLY")

    def test_project_state_is_reread_but_only_two_fields_are_checked(self):
        state, stop = self.state_and_stop()
        with patch("src.edgelab.orchestration.read", side_effect=[state, stop, {**state, "phase": "M1"}, stop]):
            self.assertEqual(decision(ROOT, self.task(), completed=set())["decision"], "DISPATCH")
            self.assertEqual(decision(ROOT, self.task(), completed=set())["decision"], "DENY")
        for bad in (
            {**state, "status": "M0_APPROVED"},
            {**state, "phase": "M1"},
            {**state, "phase": "UNKNOWN"},
            {},
        ):
            with patch("src.edgelab.orchestration.read", side_effect=[bad, stop]):
                self.assertEqual(decision(ROOT, self.task(), completed=set())["decision"], "DENY")
        minimal = {"phase": "M0", "status": "BLOCKED_FOR_APPROVAL_REMEDIATION_ALLOWED"}
        with patch("src.edgelab.orchestration.read", side_effect=[minimal, {"status": "OPEN"}]):
            self.assertEqual(decision(ROOT, self.task(), completed=set())["decision"], "DISPATCH")

    def test_stop_missing_malformed_or_fake_clear_denies_but_incomplete_open_passes(self):
        state, stop = self.state_and_stop()
        for bad_stop in ({}, {**stop, "status": "RESOLVED"}, {**stop, "status": "UNKNOWN"}):
            with patch("src.edgelab.orchestration.read", side_effect=[state, bad_stop]):
                self.assertEqual(decision(ROOT, self.task(), completed=set())["decision"], "DENY")
        with patch("src.edgelab.orchestration.read", side_effect=[state, {"status": "OPEN"}]):
            self.assertEqual(decision(ROOT, self.task(), completed=set())["decision"], "DISPATCH")
        with patch("src.edgelab.orchestration.read", side_effect=FileNotFoundError("missing")):
            self.assertEqual(decision(ROOT, self.task(), completed=set())["decision"], "DENY")

    def test_demonstrates_conflicting_stop_head_is_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "AGENTS.md").write_text("copied marker")
            (root / "PROJECT_CONSTITUTION.md").write_text("copied marker")
            (root / "docs").mkdir()
            (root / "reports/stops").mkdir(parents=True)
            (root / "docs/project-state.json").write_text(
                '{"phase":"M0","status":"BLOCKED_FOR_APPROVAL_REMEDIATION_ALLOWED"}'
            )
            (root / "reports/stops/STOP-M0-001.v1.json").write_text('{"status":"OPEN"}')
            (root / "reports/stops/STOP-M0-001.v2.json").write_text('{"status":"RESOLVED"}')
            with patch("src.edgelab.orchestration._remote", return_value=EXPECTED_REMOTE):
                self.assertEqual(decision(root, self.task(), completed=set())["decision"], "DISPATCH")

    def test_repository_wrong_remote_missing_markers_and_missing_git_deny(self):
        with patch("src.edgelab.orchestration._remote", return_value="https://example.invalid/EdgeLab.git"):
            self.assertEqual(decision(ROOT, self.task(), completed=set())["decision"], "DENY")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch("src.edgelab.orchestration._remote", return_value=EXPECTED_REMOTE):
                self.assertEqual(decision(root, self.task(), completed=set())["decision"], "DENY")
            (root / "AGENTS.md").write_text("marker")
            (root / "PROJECT_CONSTITUTION.md").write_text("marker")
            self.assertEqual(decision(root, self.task(), completed=set())["decision"], "DENY")

    def test_demonstrates_copied_repository_identity_and_symlink_alias_pass(self):
        state, stop = self.state_and_stop()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "copied-edgelab"
            root.mkdir()
            (root / "AGENTS.md").write_text("copied marker")
            (root / "PROJECT_CONSTITUTION.md").write_text("copied marker")
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(["git", "-C", str(root), "remote", "add", "origin", EXPECTED_REMOTE], check=True)
            alias = Path(tmp) / "alias"
            alias.symlink_to(root, target_is_directory=True)
            with patch("src.edgelab.orchestration.read", side_effect=[state, stop, state, stop]):
                self.assertEqual(decision(root, self.task(), completed=set())["decision"], "DISPATCH")
                self.assertEqual(decision(alias, self.task(), completed=set())["decision"], "DISPATCH")

    def test_demonstrates_hard_coded_stale_assignment_and_ignored_task_state(self):
        self.assertEqual(decision(ROOT, self.task(handoff_ref="docs/handoffs/H-M0-027.v2.json"), completed=set())["decision"], "DISPATCH")
        self.assertEqual(decision(ROOT, self.task(handoff_ref="docs/handoffs/H-M0-027.v4.json"), completed=set())["decision"], "DENY")
        for changes in (
            {"attempt": 0},
            {"attempt": -1},
            {"status": "COMPLETED"},
            {"status": "REJECTED"},
            {"assigned_role": "unrecognized alias"},
        ):
            self.assertEqual(decision(ROOT, self.task(**changes), completed=set())["decision"], "DISPATCH")

    def test_demonstrates_caller_controlled_writer_coordination(self):
        self.assertEqual(decision(ROOT, self.task(), completed=set(), writer_task="OTHER")["decision"], "DENY")
        self.assertEqual(decision(ROOT, self.task(), completed=set(), writer_task=None)["decision"], "DISPATCH")
        self.assertEqual(decision(ROOT, self.task(), completed=set(), writer_task=self.task()["task_id"])["decision"], "DISPATCH")

    def test_demonstrates_caller_controlled_dependency_completion(self):
        dependency_task = self.task(dependencies=["FAILED-OR-NONEXISTENT"])
        self.assertEqual(decision(ROOT, dependency_task, completed=set())["decision"], "DENY")
        self.assertEqual(decision(ROOT, dependency_task, completed={"FAILED-OR-NONEXISTENT"})["decision"], "DISPATCH")
        self_dependency = self.task(dependencies=[self.task()["task_id"]])
        self.assertEqual(decision(ROOT, self_dependency, completed={self.task()["task_id"]})["decision"], "DISPATCH")

    def test_demonstrates_completion_accepts_unverified_assertions(self):
        task = self.task(status="QUEUED", attempt=1)
        with self.assertRaises(ValueError):
            completion(task, claim_task=task["task_id"], evidence=[])
        with self.assertRaises(ValueError):
            completion(task, claim_task="OTHER", evidence=["exists"])
        self.assertEqual(completion(task, claim_task=task["task_id"], evidence=["human says done"]), "ROUTE_INDEPENDENT_REVIEW")
        self.assertEqual(completion(task, claim_task=task["task_id"], evidence=["another task artifact"], reviewer_decision="REJECT"), "ROUTE_REMEDIATION")
        self.assertEqual(completion(task, claim_task=task["task_id"], evidence=["not landed"], reviewer_decision="APPROVE"), "READY_FOR_DIRECTOR_GATE")

    def test_demonstrates_review_identity_and_review_requirement_bypasses(self):
        alias = self.task(assigned_role="00 Director", reviewer_role="Director alias")
        self.assertEqual(decision(ROOT, alias, completed=set())["decision"], "DISPATCH")
        omitted = self.task(review_required=False, reviewer_role=None)
        self.assertEqual(decision(ROOT, omitted, completed=set())["decision"], "DISPATCH")
        self.assertEqual(completion(omitted, claim_task=omitted["task_id"], evidence=["x"]), "COMPLETED")
        self.assertEqual(completion(self.task(), claim_task=self.task()["task_id"], evidence=["x"], reviewer_decision="REJECT"), "ROUTE_REMEDIATION")
        self.assertEqual(completion(self.task(), claim_task=self.task()["task_id"], evidence=["x"], reviewer_decision="APPROVE"), "READY_FOR_DIRECTOR_GATE")

    def test_director_gate_is_a_route_string_and_does_not_release_state(self):
        before = (ROOT / "docs/project-state.json").read_bytes()
        route = completion(self.task(), claim_task=self.task()["task_id"], evidence=["x"], reviewer_decision="APPROVE")
        self.assertEqual(route, "READY_FOR_DIRECTOR_GATE")
        self.assertEqual((ROOT / "docs/project-state.json").read_bytes(), before)

    def test_demonstrates_optional_and_incomplete_capability_enforcement(self):
        operational_payload = self.task(operation="PLUGIN_INSTALL", capability_id="unknown")
        self.assertEqual(decision(ROOT, operational_payload, completed=set(), capability=None)["decision"], "DISPATCH")
        approved_network = {
            "approval_status": "APPROVED",
            "revoked": False,
            "executable_code": False,
            "network_required": True,
            "credential_required": True,
            "security_review": "UNREVIEWED",
            "trust_status": "UNKNOWN",
        }
        self.assertEqual(decision(ROOT, operational_payload, completed=set(), capability=approved_network)["decision"], "DISPATCH")
        for capability in (
            {"approval_status": "UNAPPROVED", "revoked": False, "executable_code": False},
            {"approval_status": "APPROVED", "revoked": True, "executable_code": False},
            {"approval_status": "APPROVED", "revoked": False, "executable_code": True},
        ):
            self.assertEqual(decision(ROOT, self.task(), completed=set(), capability=capability)["decision"], "DENY")

    def test_mock_only_decision_has_no_task_execution_side_effect(self):
        with patch("src.edgelab.orchestration.subprocess.run") as run:
            run.return_value.stdout = EXPECTED_REMOTE
            state, stop = self.state_and_stop()
            with patch("src.edgelab.orchestration.read", side_effect=[state, stop]):
                result = decision(ROOT, self.task(), completed=set())
        self.assertEqual(result["execution_adapter"], "MOCK_ONLY")
        run.assert_called_once_with(
            ["git", "-C", str(ROOT), "remote", "get-url", "origin"],
            text=True,
            capture_output=True,
            check=False,
        )


if __name__ == "__main__":
    unittest.main()
