"""Focused independent probes for H-M0-028.v3 remediation.

Tests named ``demonstrates`` preserve a successful adversarial reproduction.
They pass when the current implementation exhibits the documented weakness.
All mutations occur in temporary synthetic repository fixtures.
"""
from __future__ import annotations

import copy
import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.edgelab.orchestration import EXPECTED_REMOTE, completion, decision
from src.edgelab.validate import ROOT, read


INTENT = {"task_id": "T-SYNTHETIC-001", "attempt": 1}


class SkepticOrchestrationV3(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        for relative in (
            "docs/project-state.json",
            "reports/stops/STOP-M0-001.v1.json",
            "orchestration/scheduler-state.json",
            "orchestration/tasks/T-SYNTHETIC-001.v1.json",
            "schemas/project-state.schema.json",
            "schemas/stop.schema.json",
            "schemas/orchestration-task.schema.json",
            "schemas/scheduler-state.schema.json",
            "schemas/capability-registry.schema.json",
        ):
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, target)
        return temporary, root

    @staticmethod
    def write(path: Path, value: dict):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")

    @staticmethod
    def sha256(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def state(self, root: Path) -> dict:
        return read(root / "orchestration/scheduler-state.json")

    def task(self, root: Path) -> dict:
        return read(root / "orchestration/tasks/T-SYNTHETIC-001.v1.json")

    def save_state(self, root: Path, state: dict, *, refresh_project=True, refresh_stops=True):
        if refresh_project:
            state["project_state"]["sha256"] = self.sha256(root / state["project_state"]["ref"])
        if refresh_stops:
            for item in state["stops"]:
                item["sha256"] = self.sha256(root / item["ref"])
        self.write(root / "orchestration/scheduler-state.json", state)

    def decide(self, root: Path, intent=None, **legacy):
        with patch("src.edgelab.orchestration.ROOT", root), patch(
            "src.edgelab.orchestration._remote", return_value=EXPECTED_REMOTE
        ), patch("src.edgelab.orchestration._is_ancestor_of_remote_main", return_value=True):
            return decision(root, INTENT if intent is None else intent, **legacy)

    def test_positive_authoritative_task_dispatches_mock_only(self):
        result = decision(ROOT, INTENT)
        self.assertEqual(result["decision"], "DISPATCH")
        self.assertEqual(result["execution_adapter"], "MOCK_ONLY")
        self.assertEqual(result["operation"], "SYNTHETIC_ASSERT")

    def test_caller_legacy_envelope_and_semantic_overrides_deny(self):
        for intent in (
            {**INTENT, "action_classification": "SYNTHETIC_TEST"},
            {**INTENT, "assigned_role": "00 Director"},
            {**INTENT, "capability": {"safe": True}},
            {**INTENT, "effects": ["REPOSITORY_READ"]},
            {**INTENT, "reviewer_role": "05 Skeptic"},
            {"task_id": "bad", "attempt": 1},
        ):
            self.assertEqual(decision(ROOT, intent)["decision"], "DENY")
        for legacy in ({"completed": {"fake"}}, {"writer_task": "none"}, {"approved": True}):
            self.assertEqual(decision(ROOT, INTENT, **legacy)["decision"], "DENY")

    def test_demonstrates_boolean_attempt_is_accepted_as_attempt_one(self):
        result = decision(ROOT, {"task_id": "T-SYNTHETIC-001", "attempt": True})
        self.assertEqual(result["decision"], "DISPATCH")

    def test_authoritative_task_schema_rejects_disguised_operational_semantics(self):
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        baseline = self.task(root)
        mutations = (
            {"effects": ["NETWORK"]},
            {"credential_required": True},
            {"operation": "EXTERNAL_SOURCE_ACQUISITION"},
            {"operation": "LIVE_EXECUTION"},
            {"effects": ["CAPITAL_MUTATION"]},
            {"assigned_role": "02 Scout"},
            {"reviewer_role": "00 Director"},
        )
        for mutation in mutations:
            self.write(root / "orchestration/tasks/T-SYNTHETIC-001.v1.json", {**baseline, **mutation})
            self.assertEqual(self.decide(root)["decision"], "DENY")

    def test_demonstrates_completed_yielded_claim_still_dispatches(self):
        completion_handoff = read(ROOT / "docs/handoffs/H-M0-028.v3.json")
        scheduler = read(ROOT / "orchestration/scheduler-state.json")
        self.assertEqual(completion_handoff["status"], "COMPLETED")
        self.assertIn("yields the writer slot", completion_handoff["next_action"])
        self.assertEqual(scheduler["claims"]["T-SYNTHETIC-001"]["status"], "ACTIVE")
        self.assertEqual(decision(ROOT, INTENT)["decision"], "DISPATCH")

    def test_claim_mutations_deny_but_currentness_is_not_derived(self):
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        for mutation in (
            {"status": "RELEASED"},
            {"attempt": 2},
            {"role": "05 Skeptic"},
            {"handoff_ref": "docs/handoffs/H-M0-028.v3.json"},
            {"generation": 2},
        ):
            state = self.state(root)
            state["claims"]["T-SYNTHETIC-001"].update(mutation)
            self.save_state(root, state)
            self.assertEqual(self.decide(root)["decision"], "DENY")
            shutil.copy2(ROOT / "orchestration/scheduler-state.json", root / "orchestration/scheduler-state.json")

    def test_exact_project_and_named_stop_mutations_deny(self):
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        project_path = root / "docs/project-state.json"
        project_path.write_bytes(project_path.read_bytes() + b"\n")
        self.assertEqual(self.decide(root)["decision"], "DENY")
        shutil.copy2(ROOT / "docs/project-state.json", project_path)
        stop_path = root / "reports/stops/STOP-M0-001.v1.json"
        stop_path.write_bytes(stop_path.read_bytes() + b"\n")
        self.assertEqual(self.decide(root)["decision"], "DENY")
        stop_path.unlink()
        self.assertEqual(self.decide(root)["decision"], "DENY")

    def test_demonstrates_second_open_stop_id_is_ignored(self):
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        second = read(ROOT / "reports/stops/STOP-M0-001.v1.json")
        second["id"] = "STOP-M0-002"
        second["reason"] = "Synthetic second OPEN STOP must deny all sandbox dispatch."
        self.write(root / "reports/stops/STOP-M0-002.v1.json", second)
        self.assertEqual(self.decide(root)["decision"], "DISPATCH")

    def test_conflicting_version_of_named_stop_denies(self):
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        stop = read(ROOT / "reports/stops/STOP-M0-001.v1.json")
        stop["version"] = 2
        self.write(root / "reports/stops/STOP-M0-001.v2.json", stop)
        self.assertEqual(self.decide(root)["decision"], "DENY")

    def test_repository_identity_contains_copy_and_allows_legitimate_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            copied = Path(directory) / "EdgeLab"
            copied.mkdir()
            with patch("src.edgelab.orchestration._remote", return_value=EXPECTED_REMOTE), patch(
                "src.edgelab.orchestration._is_ancestor_of_remote_main", return_value=True
            ):
                self.assertEqual(decision(copied, INTENT)["decision"], "DENY")
            alias = Path(directory) / "alias"
            alias.symlink_to(ROOT, target_is_directory=True)
            self.assertEqual(decision(alias, INTENT)["decision"], "DISPATCH")
        with patch("src.edgelab.orchestration._remote", return_value="git@github.com:dylanlaewe/EdgeLab.git"):
            self.assertEqual(decision(ROOT, INTENT)["decision"], "DENY")
        with patch("src.edgelab.orchestration._is_ancestor_of_remote_main", return_value=False):
            self.assertEqual(decision(ROOT, INTENT)["decision"], "DENY")

    def test_demonstrates_nonexistent_completed_dependency_dispatches(self):
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        task = self.task(root)
        task["dependencies"] = ["T-NONEXISTENT"]
        self.write(root / "orchestration/tasks/T-SYNTHETIC-001.v1.json", task)
        state = self.state(root)
        state["completed_tasks"] = ["T-NONEXISTENT"]
        self.save_state(root, state)
        self.assertEqual(self.decide(root)["decision"], "DISPATCH")

    def test_demonstrates_two_node_dependency_cycle_dispatches(self):
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        first = self.task(root)
        first["dependencies"] = ["T-SYNTHETIC-002"]
        self.write(root / "orchestration/tasks/T-SYNTHETIC-001.v1.json", first)
        second = {**copy.deepcopy(first), "task_id": "T-SYNTHETIC-002", "dependencies": ["T-SYNTHETIC-001"]}
        self.write(root / "orchestration/tasks/T-SYNTHETIC-002.v1.json", second)
        state = self.state(root)
        state["tasks"]["T-SYNTHETIC-002"] = "orchestration/tasks/T-SYNTHETIC-002.v1.json"
        state["completed_tasks"] = ["T-SYNTHETIC-002"]
        self.save_state(root, state)
        self.assertEqual(self.decide(root)["decision"], "DISPATCH")

    def test_completion_and_review_are_unconditionally_fail_closed(self):
        attacks = (
            {"evidence": ["prose"]},
            {"completed": True},
            {"approved": True},
            {"rejected": True},
            {"reviewer": "00 Director"},
            {"reviewer": "Skeptic alias", "approval": {"looks": "valid"}},
        )
        for attack in attacks:
            with self.assertRaisesRegex(ValueError, "FUTURE_GATE"):
                completion(ROOT, INTENT, **attack)

    def test_demonstrates_empty_capability_binding_dispatches(self):
        task = read(ROOT / "orchestration/tasks/T-SYNTHETIC-001.v1.json")
        self.assertEqual(task["effects"], ["REPOSITORY_READ"])
        self.assertEqual(task["capability_refs"], [])
        self.assertEqual(decision(ROOT, INTENT)["decision"], "DISPATCH")

    def test_demonstrates_safe_flagged_prohibited_capability_semantics_dispatch(self):
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        task = self.task(root)
        task["capability_refs"] = ["C-DISGUISED"]
        self.write(root / "orchestration/tasks/T-SYNTHETIC-001.v1.json", task)
        capability = {
            "schema_version": 1,
            "capability_id": "C-DISGUISED",
            "name": "disguised operational capability",
            "source_repository": "synthetic",
            "source_owner": "synthetic",
            "pinned_version": "1",
            "provenance": "synthetic fixture",
            "intended_roles": ["00 Director"],
            "capabilities": ["PLUGIN_INSTALL", "MCP", "SPORTS_SOURCE_ACQUISITION"],
            "permissions": ["REPOSITORY_READ"],
            "network_required": False,
            "external_dependencies": [],
            "credential_required": False,
            "executable_code": False,
            "security_review": "REVIEWED",
            "trust_status": "TRUSTED",
            "approval_status": "APPROVED",
            "update_policy": "pinned",
            "revoked": False,
        }
        self.write(root / "orchestration/capabilities/C-DISGUISED.json", capability)
        self.assertEqual(self.decide(root)["decision"], "DISPATCH")

    def test_decision_id_is_stable_but_not_content_bound_or_authenticated(self):
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        original = self.decide(root)
        repeated = self.decide(root)
        self.assertEqual(original["decision_id"], repeated["decision_id"])
        task = self.task(root)
        task["operation"] = "STATE_READ"
        self.write(root / "orchestration/tasks/T-SYNTHETIC-001.v1.json", task)
        changed_task = self.decide(root)
        self.assertEqual(changed_task["decision"], "DISPATCH")
        self.assertEqual(original["decision_id"], changed_task["decision_id"])
        project = read(root / "docs/project-state.json")
        self.write(root / "docs/project-state.json", project)
        state = self.state(root)
        self.save_state(root, state)
        changed_head = self.decide(root)
        self.assertEqual(original["decision_id"], changed_head["decision_id"])
        denial = self.decide(root, {"task_id": "T-UNKNOWN", "attempt": 1})
        self.assertNotIn("decision_id", denial)


if __name__ == "__main__":
    unittest.main()
