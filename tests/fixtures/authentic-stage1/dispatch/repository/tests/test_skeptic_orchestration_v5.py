"""Final focused Skeptic probes for the H-M0-032.v3 consolidation.

Successful ``demonstrates`` tests preserve residual vulnerabilities.  Every
mutation is confined to a temporary repository fixture.
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


class SkepticOrchestrationV5(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        paths = (
            "docs/project-state.json",
            "docs/handoffs/H-M0-032.v1.json",
            "docs/handoffs/H-M0-032.v2.json",
            "reports/stops/STOP-M0-001.v1.json",
            "orchestration/scheduler-state.json",
            "orchestration/tasks/T-SYNTHETIC-001.v1.json",
            "orchestration/capabilities/C-REPOSITORY-READ.json",
            "schemas/project-state.schema.json",
            "schemas/stop.schema.json",
            "schemas/handoff.schema.json",
            "schemas/orchestration-task.schema.json",
            "schemas/scheduler-state.schema.json",
            "schemas/capability-registry.schema.json",
        )
        for relative in paths:
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, target)
        return temporary, root

    @staticmethod
    def write(path: Path, value: dict, *, sorted_keys=True):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, sort_keys=sorted_keys), encoding="utf-8")

    @staticmethod
    def digest(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def state(self, root: Path) -> dict:
        return read(root / "orchestration/scheduler-state.json")

    def task(self, root: Path) -> dict:
        return read(root / "orchestration/tasks/T-SYNTHETIC-001.v1.json")

    def capability(self, root: Path) -> dict:
        return read(root / "orchestration/capabilities/C-REPOSITORY-READ.json")

    def save_state(self, root: Path, state: dict, *, project=True, stops=True):
        if project:
            state["project_state"]["sha256"] = self.digest(root / state["project_state"]["ref"])
        if stops:
            for item in state["stops"]:
                item["sha256"] = self.digest(root / item["ref"])
        self.write(root / "orchestration/scheduler-state.json", state)

    def decide(self, root: Path, intent=None, **legacy):
        with patch("src.edgelab.orchestration.ROOT", root), patch(
            "src.edgelab.orchestration._remote", return_value=EXPECTED_REMOTE
        ), patch("src.edgelab.orchestration._is_ancestor_of_remote_main", return_value=True):
            return decision(root, INTENT if intent is None else intent, **legacy)

    def add_dependency(self, root: Path, *, status="COMPLETED", evidence=None, attempt=1):
        primary = self.task(root)
        primary["dependencies"] = ["T-DEPENDENCY"]
        self.write(root / "orchestration/tasks/T-SYNTHETIC-001.v1.json", primary)
        dependency = copy.deepcopy(primary)
        dependency.update(
            task_id="T-DEPENDENCY",
            status=status,
            dependencies=[],
            attempt=attempt,
            completion_evidence=["synthetic-evidence"] if evidence is None else evidence,
        )
        self.write(root / "orchestration/tasks/T-DEPENDENCY.v1.json", dependency)
        state = self.state(root)
        state["tasks"]["T-DEPENDENCY"] = "orchestration/tasks/T-DEPENDENCY.v1.json"
        self.save_state(root, state)
        return dependency

    def test_positive_sequence_dispatches_then_completed_handoff_denies(self):
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        self.assertEqual(self.decide(root)["decision"], "DISPATCH")
        shutil.copy2(ROOT / "docs/handoffs/H-M0-032.v3.json", root / "docs/handoffs/H-M0-032.v3.json")
        self.assertEqual(self.decide(root)["decision"], "DENY")
        self.assertEqual(decision(ROOT, INTENT)["decision"], "DENY")

    def test_assignment_malformed_minimal_unrelated_stale_completed_and_wrong_writer_deny(self):
        for mutation in (
            {"attempt": 2},
            {"role": "05 Skeptic"},
            {"status": "RELEASED"},
            {"handoff_ref": "docs/handoffs/H-M0-032.v1.json"},
        ):
            temporary, root = self.fixture()
            self.addCleanup(temporary.cleanup)
            state = self.state(root)
            state["claims"]["T-SYNTHETIC-001"].update(mutation)
            self.save_state(root, state)
            self.assertEqual(self.decide(root)["decision"], "DENY")

        for replacement in (
            {"id": "H-M0-032", "version": 2, "status": "CLAIMED"},
            {**read(ROOT / "docs/handoffs/H-M0-032.v2.json"), "id": "H-M0-099"},
            {**read(ROOT / "docs/handoffs/H-M0-032.v2.json"), "sender": "05 Skeptic"},
            {**read(ROOT / "docs/handoffs/H-M0-032.v2.json"), "status": "COMPLETED"},
        ):
            temporary, root = self.fixture()
            self.addCleanup(temporary.cleanup)
            self.write(root / "docs/handoffs/H-M0-032.v2.json", replacement)
            self.assertEqual(self.decide(root)["decision"], "DENY")

    def test_demonstrates_schema_valid_altered_handoff_has_no_task_or_attempt_binding(self):
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        handoff = read(root / "docs/handoffs/H-M0-032.v2.json")
        handoff["request"] = "Claim unrelated T-OTHER attempt 77 for a different scope."
        handoff["work_done"] = "00 Director claims unrelated work; no T-SYNTHETIC-001 assignment."
        handoff["evidence_refs"] = ["docs/handoffs/H-M0-032.v1.json"]
        handoff["completion_criteria"] = ["Unrelated work only."]
        self.write(root / "docs/handoffs/H-M0-032.v2.json", handoff)
        self.assertEqual(self.decide(root)["decision"], "DISPATCH")

    def test_dependencies_missing_incomplete_blocked_and_cycles_deny(self):
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        task = self.task(root)
        task["dependencies"] = ["T-MISSING"]
        self.write(root / "orchestration/tasks/T-SYNTHETIC-001.v1.json", task)
        self.assertEqual(self.decide(root)["decision"], "DENY")
        for status in ("QUEUED", "BLOCKED"):
            temporary, root = self.fixture()
            self.addCleanup(temporary.cleanup)
            self.add_dependency(root, status=status)
            self.assertEqual(self.decide(root)["decision"], "DENY")
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        task = self.task(root)
        task["dependencies"] = [task["task_id"]]
        self.write(root / "orchestration/tasks/T-SYNTHETIC-001.v1.json", task)
        self.assertEqual(self.decide(root)["decision"], "DENY")
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        dep = self.add_dependency(root)
        dep["dependencies"] = ["T-SYNTHETIC-001"]
        self.write(root / "orchestration/tasks/T-DEPENDENCY.v1.json", dep)
        self.assertEqual(self.decide(root)["decision"], "DENY")

    def test_caller_cannot_supply_or_omit_authoritative_dependency_state(self):
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        task = self.task(root)
        task["dependencies"] = ["T-MISSING"]
        self.write(root / "orchestration/tasks/T-SYNTHETIC-001.v1.json", task)
        self.assertEqual(self.decide(root, completed={"T-MISSING"})["decision"], "DENY")
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        self.add_dependency(root)
        self.assertEqual(self.decide(root, dependencies={})["decision"], "DENY")

    def test_demonstrates_prose_only_wrong_attempt_dependency_completion_dispatches(self):
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        self.add_dependency(root, evidence=["human says complete"], attempt=999)
        self.assertEqual(self.decide(root)["decision"], "DISPATCH")

    def test_demonstrates_noncurrent_dependency_versions_dispatch(self):
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        old = self.add_dependency(root)
        newer = {**copy.deepcopy(old), "status": "BLOCKED", "completion_evidence": []}
        self.write(root / "orchestration/tasks/T-DEPENDENCY.v2.json", newer)
        self.assertEqual(self.decide(root)["decision"], "DISPATCH")
        newer.update(status="COMPLETED", completion_evidence=["new prose"])
        self.write(root / "orchestration/tasks/T-DEPENDENCY.v2.json", newer)
        self.assertEqual(self.decide(root)["decision"], "DISPATCH")

    def test_unified_capability_channels_and_unsafe_variants_deny(self):
        mutations = (
            {"capabilities": ["LIVE"]},
            {"permissions": ["EXTERNAL_EXECUTION"]},
            {"semantic_types": ["LIVE"], "capabilities": ["REPOSITORY_READ"], "permissions": ["REPOSITORY_READ"]},
            {"network_required": True}, {"credential_required": True}, {"executable_code": True},
            {"external_dependencies": ["outside"]}, {"revoked": True},
            {"trust_status": "UNKNOWN"}, {"security_review": "UNREVIEWED"}, {"approval_status": "UNAPPROVED"},
        )
        prohibited = ("PLUGIN_INSTALL", "PLUGIN_ACTIVATE", "SKILL_INSTALL", "SKILL_ACTIVATE", "MCP", "NETWORK", "CREDENTIAL", "EXTERNAL_EXECUTION", "SPORTS_SOURCE_ACQUISITION", "EXTERNAL_DATA_INGESTION", "PAPER", "LIVE", "CAPITAL_MUTATION", "VENUE", "ACCOUNT")
        for mutation in mutations + tuple({"semantic_types": [p], "capabilities": [p], "permissions": [p]} for p in prohibited):
            temporary, root = self.fixture()
            self.addCleanup(temporary.cleanup)
            capability = self.capability(root)
            capability.update(mutation)
            self.write(root / "orchestration/capabilities/C-REPOSITORY-READ.json", capability)
            self.assertEqual(self.decide(root)["decision"], "DENY")

    def test_missing_unknown_duplicate_and_caller_capabilities_deny(self):
        for refs in ([], ["C-UNKNOWN"], ["C-REPOSITORY-READ", "C-REPOSITORY-READ"]):
            temporary, root = self.fixture()
            self.addCleanup(temporary.cleanup)
            task = self.task(root)
            task["capability_refs"] = refs
            self.write(root / "orchestration/tasks/T-SYNTHETIC-001.v1.json", task)
            self.assertEqual(self.decide(root)["decision"], "DENY")
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        capability = self.capability(root)
        capability["network_required"] = True
        self.write(root / "orchestration/capabilities/C-REPOSITORY-READ.json", capability)
        self.assertEqual(self.decide(root, capability={"network_required": False})["decision"], "DENY")

    def test_authoritative_capability_is_coherent_and_positive(self):
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        capability = self.capability(root)
        self.assertEqual(set(capability["semantic_types"]), set(capability["capabilities"]))
        self.assertEqual(set(capability["semantic_types"]), set(capability["permissions"]))
        self.assertEqual(capability["semantic_types"], ["REPOSITORY_READ"])
        self.assertFalse(capability["network_required"] or capability["credential_required"] or capability["executable_code"] or capability["revoked"])
        self.assertEqual(self.decide(root)["decision"], "DISPATCH")

    def test_receipt_is_deterministic_canonical_and_binds_represented_context(self):
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        original = self.decide(root)
        self.assertEqual(original, self.decide(root))
        state = self.state(root)
        self.write(root / "orchestration/scheduler-state.json", state, sorted_keys=False)
        self.assertEqual(original["decision_id"], self.decide(root)["decision_id"])
        task = self.task(root)
        task["operation"] = "STATE_READ"
        self.write(root / "orchestration/tasks/T-SYNTHETIC-001.v1.json", task)
        self.assertNotEqual(original["decision_id"], self.decide(root)["decision_id"])

    def test_receipt_changes_for_attempt_owner_handoff_claim_project_stop_and_decision(self):
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        original = self.decide(root)["decision_id"]
        handoff = read(root / "docs/handoffs/H-M0-032.v2.json")
        handoff["request"] += " changed"
        self.write(root / "docs/handoffs/H-M0-032.v2.json", handoff)
        self.assertNotEqual(original, self.decide(root)["decision_id"])

        for kind in ("attempt", "claim", "project", "stop"):
            temporary, root = self.fixture()
            self.addCleanup(temporary.cleanup)
            if kind == "attempt":
                task = self.task(root); task["attempt"] = 2
                self.write(root / "orchestration/tasks/T-SYNTHETIC-001.v1.json", task)
                state = self.state(root); state["claims"]["T-SYNTHETIC-001"]["attempt"] = 2; self.save_state(root, state)
                result = self.decide(root, {"task_id": "T-SYNTHETIC-001", "attempt": 2})
            elif kind == "claim":
                state = self.state(root); state["generation"] = 2; state["claims"]["T-SYNTHETIC-001"]["generation"] = 2; self.save_state(root, state)
                result = self.decide(root)
            elif kind == "project":
                project = read(root / "docs/project-state.json"); self.write(root / "docs/project-state.json", project)
                state = self.state(root); self.save_state(root, state); result = self.decide(root)
            else:
                stop = read(root / "reports/stops/STOP-M0-001.v1.json"); stop["reason"] += " changed"
                self.write(root / "reports/stops/STOP-M0-001.v1.json", stop)
                state = self.state(root); self.save_state(root, state); result = self.decide(root)
            self.assertEqual(result["decision"], "DISPATCH")
            self.assertNotEqual(original, result["decision_id"])
        denied = self.decide(root, {"task_id": "T-UNKNOWN", "attempt": 1})
        self.assertNotEqual(original, denied["decision_id"])

    def test_denied_subject_and_reason_are_bound(self):
        first = decision(ROOT, {"task_id": "T-UNKNOWN-A", "attempt": 1})
        second = decision(ROOT, {"task_id": "T-UNKNOWN-B", "attempt": 1})
        malformed = decision(ROOT, {"task_id": "T-UNKNOWN-A"})
        self.assertEqual(first["reason"], second["reason"])
        self.assertNotEqual(first["decision_id"], second["decision_id"])
        self.assertNotEqual(first["reason"], malformed["reason"])
        self.assertNotEqual(first["decision_id"], malformed["decision_id"])

    def test_demonstrates_receipt_omits_capability_and_dependency_record_content(self):
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        original = self.decide(root)["decision_id"]
        capability = self.capability(root)
        capability["name"] = "different safe content"
        self.write(root / "orchestration/capabilities/C-REPOSITORY-READ.json", capability)
        self.assertEqual(original, self.decide(root)["decision_id"])
        dependency = self.add_dependency(root)
        with_dependency = self.decide(root)["decision_id"]
        dependency["completion_evidence"] = ["different evidence"]
        self.write(root / "orchestration/tasks/T-DEPENDENCY.v1.json", dependency)
        self.assertEqual(with_dependency, self.decide(root)["decision_id"])

    def test_demonstrates_denial_receipt_omits_changed_authoritative_state(self):
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        project = read(root / "docs/project-state.json")
        project["status"] = "ACTIVE"
        self.write(root / "docs/project-state.json", project)
        state = self.state(root); self.save_state(root, state)
        first = self.decide(root)
        project["status"] = "PAUSED"
        self.write(root / "docs/project-state.json", project)
        state = self.state(root); self.save_state(root, state)
        second = self.decide(root)
        self.assertEqual(first["reason"], second["reason"])
        self.assertEqual(first["decision_id"], second["decision_id"])

    def test_strict_attempt_stop_containment_and_completion_regressions(self):
        temporary, root = self.fixture()
        self.addCleanup(temporary.cleanup)
        for attempt in (True, False, "1", 1.0, 0, -1, 2147483648):
            self.assertEqual(self.decide(root, {"task_id": "T-SYNTHETIC-001", "attempt": attempt})["decision"], "DENY")
        extra = read(root / "reports/stops/STOP-M0-001.v1.json")
        extra.update(id="STOP-M0-002", reason="unknown open stop")
        self.write(root / "reports/stops/STOP-M0-002.v1.json", extra)
        self.assertEqual(self.decide(root)["decision"], "DENY")
        with tempfile.TemporaryDirectory() as directory:
            copied = Path(directory) / "EdgeLab"; copied.mkdir()
            with patch("src.edgelab.orchestration._remote", return_value=EXPECTED_REMOTE), patch("src.edgelab.orchestration._is_ancestor_of_remote_main", return_value=True):
                self.assertEqual(decision(copied, INTENT)["decision"], "DENY")
        with patch("src.edgelab.orchestration._remote", return_value="wrong"):
            self.assertEqual(decision(ROOT, INTENT)["decision"], "DENY")
        with patch("src.edgelab.orchestration._is_ancestor_of_remote_main", return_value=False):
            self.assertEqual(decision(ROOT, INTENT)["decision"], "DENY")
        with self.assertRaisesRegex(ValueError, "FUTURE_GATE"):
            completion(ROOT, INTENT, evidence=["prose"])


if __name__ == "__main__":
    unittest.main()
