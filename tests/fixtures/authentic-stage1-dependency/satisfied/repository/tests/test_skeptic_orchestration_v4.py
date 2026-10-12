"""Focused independent probes for H-M0-030.v3 residual remediation.

Tests named ``demonstrates`` preserve a successful adversarial reproduction.
All repository mutations occur in temporary synthetic fixtures.
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


class SkepticOrchestrationV4(unittest.TestCase):
    def fixture(self, *, before_completion=True):
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        paths = [
            "docs/project-state.json",
            "docs/handoffs/H-M0-030.v1.json",
            "docs/handoffs/H-M0-030.v2.json",
            "docs/handoffs/H-M0-030.v3.json",
            "reports/stops/STOP-M0-001.v1.json",
            "orchestration/scheduler-state.json",
            "orchestration/tasks/T-SYNTHETIC-001.v1.json",
            "orchestration/capabilities/C-REPOSITORY-READ.json",
            "schemas/project-state.schema.json",
            "schemas/stop.schema.json",
            "schemas/orchestration-task.schema.json",
            "schemas/scheduler-state.schema.json",
            "schemas/capability-registry.schema.json",
        ]
        for relative in paths:
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, target)
        if before_completion:
            (root / "docs/handoffs/H-M0-030.v3.json").unlink()
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

    def capability(self, root: Path) -> dict:
        return read(root / "orchestration/capabilities/C-REPOSITORY-READ.json")

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

    def add_stop(self, root: Path, stop: dict, filename: str):
        path = root / "reports/stops" / filename
        self.write(path, stop)
        state = self.state(root)
        state["stops"].append({"ref": str(path.relative_to(root)), "sha256": self.sha256(path)})
        self.save_state(root, state, refresh_stops=False)

    def add_dependency(self, root: Path, *, status="COMPLETED", evidence=None, attempt=1):
        primary = self.task(root)
        primary["dependencies"] = ["T-DEPENDENCY"]
        self.write(root / "orchestration/tasks/T-SYNTHETIC-001.v1.json", primary)
        dependency = {
            **copy.deepcopy(primary),
            "task_id": "T-DEPENDENCY",
            "status": status,
            "dependencies": [],
            "attempt": attempt,
            "completion_evidence": ["synthetic-evidence"] if evidence is None else evidence,
        }
        self.write(root / "orchestration/tasks/T-DEPENDENCY.v1.json", dependency)
        state = self.state(root)
        state["tasks"]["T-DEPENDENCY"] = "orchestration/tasks/T-DEPENDENCY.v1.json"
        self.save_state(root, state)
        return dependency

    def test_strict_attempt_boundary_closes_boolean_and_numeric_coercion(self):
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        self.assertEqual(self.decide(root)["decision"], "DISPATCH")
        for attempt in (True, False, "1", 1.0, 0, -1, 2147483648, 10**100):
            self.assertEqual(self.decide(root, {"task_id": "T-SYNTHETIC-001", "attempt": attempt})["decision"], "DENY")
        state = self.state(root)
        state["generation"] = True
        self.write(root / "orchestration/scheduler-state.json", state)
        self.assertEqual(self.decide(root)["decision"], "DENY")

    def test_completed_real_claim_and_stale_scheduler_claim_deny(self):
        self.assertEqual(read(ROOT / "docs/handoffs/H-M0-030.v3.json")["status"], "COMPLETED")
        self.assertEqual(read(ROOT / "orchestration/scheduler-state.json")["claims"]["T-SYNTHETIC-001"]["status"], "ACTIVE")
        self.assertEqual(decision(ROOT, INTENT)["decision"], "DENY")

    def test_precompletion_claim_dispatches_then_completion_denies(self):
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        self.assertEqual(self.decide(root)["decision"], "DISPATCH")
        shutil.copy2(ROOT / "docs/handoffs/H-M0-030.v3.json", root / "docs/handoffs/H-M0-030.v3.json")
        self.assertEqual(self.decide(root)["decision"], "DENY")

    def test_claim_and_task_mismatches_deny(self):
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        for mutation in (
            {"attempt": 2},
            {"role": "05 Skeptic"},
            {"status": "RELEASED"},
            {"handoff_ref": "docs/handoffs/H-M0-030.v1.json"},
        ):
            state = self.state(root)
            state["claims"]["T-SYNTHETIC-001"].update(mutation)
            self.save_state(root, state)
            self.assertEqual(self.decide(root)["decision"], "DENY")
            shutil.copy2(ROOT / "orchestration/scheduler-state.json", root / "orchestration/scheduler-state.json")

    def test_demonstrates_fresh_unrelated_claim_handoff_can_authorize_task(self):
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        unrelated_ref = "docs/handoffs/H-M0-099.v1.json"
        self.write(root / unrelated_ref, {"id": "H-M0-099", "version": 1, "status": "CLAIMED"})
        task = self.task(root)
        task["handoff_ref"] = unrelated_ref
        self.write(root / "orchestration/tasks/T-SYNTHETIC-001.v1.json", task)
        state = self.state(root)
        state["claims"]["T-SYNTHETIC-001"]["handoff_ref"] = unrelated_ref
        self.save_state(root, state)
        self.assertEqual(self.decide(root)["decision"], "DISPATCH")

    def test_complete_stop_namespace_add_change_remove_fail_closed(self):
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        self.assertEqual(self.decide(root)["decision"], "DISPATCH")
        extra = read(ROOT / "reports/stops/STOP-M0-001.v1.json")
        extra["id"] = "STOP-M0-002"
        extra["reason"] = "Synthetic unknown-applicability OPEN STOP"
        extra_path = root / "reports/stops/STOP-M0-002.v1.json"
        self.write(extra_path, extra)
        self.assertEqual(self.decide(root)["decision"], "DENY")
        state = self.state(root)
        state["stops"].append({"ref": str(extra_path.relative_to(root)), "sha256": self.sha256(extra_path)})
        self.save_state(root, state, refresh_stops=False)
        self.assertEqual(self.decide(root)["decision"], "DENY")
        extra_path.unlink()
        self.assertEqual(self.decide(root)["decision"], "DENY")

    def test_cleared_additional_stop_and_supersession_are_accepted(self):
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        audit = root / "reports/audit/A-SYNTHETIC.json"
        self.write(audit, {})
        old = read(ROOT / "reports/stops/STOP-M0-001.v1.json")
        old.update({"id": "STOP-M0-002", "version": 1, "reason": "old synthetic stop"})
        self.add_stop(root, old, "STOP-M0-002.v1.json")
        newer = {**old, "version": 2, "status": "RESOLVED", "resolution_event_ref": "reports/audit/A-SYNTHETIC.json"}
        self.add_stop(root, newer, "STOP-M0-002.v2.json")
        self.assertEqual(self.decide(root)["decision"], "DISPATCH")

    def test_malformed_and_duplicate_stop_heads_deny(self):
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        malformed = root / "reports/stops/STOP-MALFORMED.v1.json"
        self.write(malformed, {"status": "OPEN"})
        state = self.state(root)
        state["stops"].append({"ref": str(malformed.relative_to(root)), "sha256": self.sha256(malformed)})
        self.save_state(root, state, refresh_stops=False)
        self.assertEqual(self.decide(root)["decision"], "DENY")

        temporary2, root2 = self.fixture()
        self.addCleanup(temporary2.cleanup)
        duplicate = read(ROOT / "reports/stops/STOP-M0-001.v1.json")
        self.add_stop(root2, duplicate, "STOP-DUPLICATE.v1.json")
        self.assertEqual(self.decide(root2)["decision"], "DENY")

    def test_dependencies_require_existing_completed_acyclic_tasks(self):
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        primary = self.task(root)
        primary["dependencies"] = ["T-MISSING"]
        self.write(root / "orchestration/tasks/T-SYNTHETIC-001.v1.json", primary)
        self.assertEqual(self.decide(root)["decision"], "DENY")

        for status in ("QUEUED", "BLOCKED"):
            temporary2, root2 = self.fixture()
            self.addCleanup(temporary2.cleanup)
            self.add_dependency(root2, status=status)
            self.assertEqual(self.decide(root2)["decision"], "DENY")

    def test_self_two_node_and_transitive_cycles_deny(self):
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        task = self.task(root)
        task["dependencies"] = [task["task_id"]]
        self.write(root / "orchestration/tasks/T-SYNTHETIC-001.v1.json", task)
        self.assertEqual(self.decide(root)["decision"], "DENY")

        temporary2, root2 = self.fixture()
        self.addCleanup(temporary2.cleanup)
        dep = self.add_dependency(root2)
        dep["dependencies"] = ["T-SYNTHETIC-001"]
        self.write(root2 / "orchestration/tasks/T-DEPENDENCY.v1.json", dep)
        self.assertEqual(self.decide(root2)["decision"], "DENY")

        temporary3, root3 = self.fixture()
        self.addCleanup(temporary3.cleanup)
        dep1 = self.add_dependency(root3)
        dep1["dependencies"] = ["T-DEPENDENCY-2"]
        self.write(root3 / "orchestration/tasks/T-DEPENDENCY.v1.json", dep1)
        dep2 = {**copy.deepcopy(dep1), "task_id": "T-DEPENDENCY-2", "dependencies": ["T-DEPENDENCY"]}
        self.write(root3 / "orchestration/tasks/T-DEPENDENCY-2.v1.json", dep2)
        state = self.state(root3)
        state["tasks"]["T-DEPENDENCY-2"] = "orchestration/tasks/T-DEPENDENCY-2.v1.json"
        self.save_state(root3, state)
        self.assertEqual(self.decide(root3)["decision"], "DENY")

    def test_caller_completion_ids_have_no_effect(self):
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        primary = self.task(root)
        primary["dependencies"] = ["T-MISSING"]
        self.write(root / "orchestration/tasks/T-SYNTHETIC-001.v1.json", primary)
        self.assertEqual(self.decide(root, completed={"T-MISSING"})["decision"], "DENY")

    def test_demonstrates_arbitrary_string_manufactures_dependency_completion(self):
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        self.add_dependency(root, evidence=["human says complete"], attempt=999)
        self.assertEqual(self.decide(root)["decision"], "DISPATCH")

    def test_demonstrates_superseded_dependency_version_is_accepted(self):
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        old = self.add_dependency(root)
        newer = {**copy.deepcopy(old), "status": "BLOCKED", "completion_evidence": []}
        self.write(root / "orchestration/tasks/T-DEPENDENCY.v2.json", newer)
        self.assertEqual(self.decide(root)["decision"], "DISPATCH")

    def test_authoritative_repository_read_capability_is_safe(self):
        capability = read(ROOT / "orchestration/capabilities/C-REPOSITORY-READ.json")
        self.assertEqual(capability["capability_id"], "C-REPOSITORY-READ")
        self.assertEqual(capability["semantic_types"], ["REPOSITORY_READ"])
        self.assertEqual(capability["permissions"], ["REPOSITORY_READ"])
        self.assertEqual(capability["security_review"], "REVIEWED")
        self.assertEqual(capability["trust_status"], "TRUSTED")
        self.assertEqual(capability["approval_status"], "APPROVED")
        self.assertFalse(capability["revoked"] or capability["executable_code"] or capability["credential_required"] or capability["network_required"])
        self.assertEqual(capability["external_dependencies"], [])

    def test_missing_unknown_ambiguous_and_unsafe_capabilities_deny(self):
        mutations = (
            {"network_required": True},
            {"credential_required": True},
            {"executable_code": True},
            {"revoked": True},
            {"semantic_types": ["PLUGIN_INSTALL"]},
            {"semantic_types": ["SKILL_ACTIVATE"]},
            {"semantic_types": ["MCP"]},
            {"semantic_types": ["EXTERNAL_EXECUTION"]},
            {"semantic_types": ["SPORTS_SOURCE_ACQUISITION"]},
            {"semantic_types": ["EXTERNAL_DATA_INGESTION"]},
            {"semantic_types": ["PAPER"]},
            {"semantic_types": ["LIVE"]},
            {"semantic_types": ["CAPITAL_MUTATION"]},
            {"semantic_types": ["VENUE"]},
            {"semantic_types": ["ACCOUNT"]},
        )
        for mutation in mutations:
            temporary, root = self.fixture()
            self.addCleanup(temporary.cleanup)
            capability = self.capability(root)
            capability.update(mutation)
            self.write(root / "orchestration/capabilities/C-REPOSITORY-READ.json", capability)
            self.assertEqual(self.decide(root)["decision"], "DENY")

        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        task = self.task(root)
        task["capability_refs"] = []
        self.write(root / "orchestration/tasks/T-SYNTHETIC-001.v1.json", task)
        self.assertEqual(self.decide(root)["decision"], "DENY")
        task["capability_refs"] = ["C-UNKNOWN"]
        self.write(root / "orchestration/tasks/T-SYNTHETIC-001.v1.json", task)
        self.assertEqual(self.decide(root)["decision"], "DENY")

        temporary2, root2 = self.fixture()
        self.addCleanup(temporary2.cleanup)
        duplicate = self.capability(root2)
        self.write(root2 / "orchestration/capabilities/C-DUPLICATE.json", duplicate)
        self.assertEqual(self.decide(root2)["decision"], "DENY")

    def test_caller_safe_capability_cannot_override_authoritative_unsafe_record(self):
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        capability = self.capability(root)
        capability["network_required"] = True
        self.write(root / "orchestration/capabilities/C-REPOSITORY-READ.json", capability)
        result = self.decide(root, capability={"network_required": False})
        self.assertEqual(result["decision"], "DENY")

    def test_demonstrates_legacy_capability_semantics_can_contradict_safe_semantic_types(self):
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        capability = self.capability(root)
        capability["capabilities"] = ["PLUGIN_INSTALL", "MCP", "LIVE", "CAPITAL_MUTATION"]
        capability["permissions"] = ["REPOSITORY_READ", "EXTERNAL_EXECUTION"]
        self.write(root / "orchestration/capabilities/C-REPOSITORY-READ.json", capability)
        self.assertEqual(self.decide(root)["decision"], "DISPATCH")

    def test_receipt_changes_for_bound_project_stop_writer_and_attempt(self):
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        original = self.decide(root)["decision_id"]

        project = read(root / "docs/project-state.json")
        self.write(root / "docs/project-state.json", project)
        state = self.state(root)
        self.save_state(root, state)
        self.assertNotEqual(original, self.decide(root)["decision_id"])

        temporary_stop, root_stop = self.fixture()
        self.addCleanup(temporary_stop.cleanup)
        stop = read(root_stop / "reports/stops/STOP-M0-001.v1.json")
        stop["reason"] = "changed STOP content"
        self.write(root_stop / "reports/stops/STOP-M0-001.v1.json", stop)
        state_stop = self.state(root_stop)
        self.save_state(root_stop, state_stop)
        self.assertNotEqual(original, self.decide(root_stop)["decision_id"])

        temporary2, root2 = self.fixture()
        self.addCleanup(temporary2.cleanup)
        state2 = self.state(root2)
        state2["generation"] = 2
        state2["claims"]["T-SYNTHETIC-001"]["generation"] = 2
        self.save_state(root2, state2)
        self.assertNotEqual(original, self.decide(root2)["decision_id"])

        temporary3, root3 = self.fixture()
        self.addCleanup(temporary3.cleanup)
        task3 = self.task(root3)
        task3["attempt"] = 2
        self.write(root3 / "orchestration/tasks/T-SYNTHETIC-001.v1.json", task3)
        state3 = self.state(root3)
        state3["claims"]["T-SYNTHETIC-001"]["attempt"] = 2
        self.save_state(root3, state3)
        self.assertNotEqual(original, self.decide(root3, {"task_id": "T-SYNTHETIC-001", "attempt": 2})["decision_id"])

    def test_demonstrates_dispatch_receipt_omits_task_capability_dependency_and_handoff_content(self):
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        original = self.decide(root)["decision_id"]
        task = self.task(root)
        task["operation"] = "STATE_READ"
        self.write(root / "orchestration/tasks/T-SYNTHETIC-001.v1.json", task)
        self.assertEqual(original, self.decide(root)["decision_id"])

        capability = self.capability(root)
        capability["name"] = "changed safe capability content"
        self.write(root / "orchestration/capabilities/C-REPOSITORY-READ.json", capability)
        self.assertEqual(original, self.decide(root)["decision_id"])

        handoff = read(root / "docs/handoffs/H-M0-030.v2.json")
        handoff["request"] = "changed assignment content"
        self.write(root / "docs/handoffs/H-M0-030.v2.json", handoff)
        self.assertEqual(original, self.decide(root)["decision_id"])

        dependency = self.add_dependency(root)
        with_dependency = self.decide(root)["decision_id"]
        dependency["completion_evidence"] = ["different evidence"]
        self.write(root / "orchestration/tasks/T-DEPENDENCY.v1.json", dependency)
        self.assertEqual(with_dependency, self.decide(root)["decision_id"])

    def test_demonstrates_denial_receipt_omits_subject_and_state_when_reason_matches(self):
        first = decision(ROOT, {"task_id": "T-UNKNOWN-A", "attempt": 1})
        second = decision(ROOT, {"task_id": "T-UNKNOWN-B", "attempt": 999})
        self.assertEqual(first["decision"], "DENY")
        self.assertEqual(first["reason"], second["reason"])
        self.assertEqual(first["decision_id"], second["decision_id"])
        different_reason = decision(ROOT, {"task_id": "T-UNKNOWN-A"})
        self.assertNotEqual(first["reason"], different_reason["reason"])
        self.assertNotEqual(first["decision_id"], different_reason["decision_id"])

    def test_repository_containment_and_completion_fail_closed_regressions(self):
        with tempfile.TemporaryDirectory() as directory:
            copied = Path(directory) / "EdgeLab"
            copied.mkdir()
            with patch("src.edgelab.orchestration._remote", return_value=EXPECTED_REMOTE), patch(
                "src.edgelab.orchestration._is_ancestor_of_remote_main", return_value=True
            ):
                self.assertEqual(decision(copied, INTENT)["decision"], "DENY")
        with patch("src.edgelab.orchestration._remote", return_value="wrong"):
            self.assertEqual(decision(ROOT, INTENT)["decision"], "DENY")
        with patch("src.edgelab.orchestration._is_ancestor_of_remote_main", return_value=False):
            self.assertEqual(decision(ROOT, INTENT)["decision"], "DENY")
        for payload in ({"evidence": ["prose"]}, {"approved": True}, {"rejected": True}):
            with self.assertRaisesRegex(ValueError, "FUTURE_GATE"):
                completion(ROOT, INTENT, **payload)


if __name__ == "__main__":
    unittest.main()
