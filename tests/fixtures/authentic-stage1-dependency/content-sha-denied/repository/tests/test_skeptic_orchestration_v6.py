"""Bounded-acceptance probes for H-M0-034.v3.

Tests named ``demonstrates`` preserve successful current-contract attacks.  All
mutations occur in temporary fixtures and no executor is attached.
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


class SkepticOrchestrationV6(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        paths = (
            "docs/project-state.json",
            "docs/handoffs/H-M0-034.v1.json",
            "docs/handoffs/H-M0-034.v2.json",
            "reports/stops/STOP-M0-001.v1.json",
            "orchestration/scheduler-state.json",
            "orchestration/tasks/T-SYNTHETIC-001.v1.json",
            "orchestration/assignments/T-SYNTHETIC-001.v1.json",
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
    def write(path: Path, value: dict, *, sort_keys=True):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, sort_keys=sort_keys), encoding="utf-8")

    @staticmethod
    def digest(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def state(self, root: Path) -> dict:
        return read(root / "orchestration/scheduler-state.json")

    def task(self, root: Path) -> dict:
        return read(root / "orchestration/tasks/T-SYNTHETIC-001.v1.json")

    def assignment(self, root: Path) -> dict:
        return read(root / "orchestration/assignments/T-SYNTHETIC-001.v1.json")

    def capability(self, root: Path) -> dict:
        return read(root / "orchestration/capabilities/C-REPOSITORY-READ.json")

    def save_state(self, root: Path, state: dict):
        state["project_state"]["sha256"] = self.digest(root / state["project_state"]["ref"])
        for item in state["stops"]:
            item["sha256"] = self.digest(root / item["ref"])
        self.write(root / "orchestration/scheduler-state.json", state)

    def decide(self, root: Path, intent=None, **legacy):
        with patch("src.edgelab.orchestration.ROOT", root), patch(
            "src.edgelab.orchestration._remote", return_value=EXPECTED_REMOTE
        ), patch("src.edgelab.orchestration._is_ancestor_of_remote_main", return_value=True):
            return decision(root, INTENT if intent is None else intent, **legacy)

    def add_dependency(self, root: Path, *, version=1, status="COMPLETED", attempt=1,
                       evidence=True, task_id="T-DEPENDENCY"):
        primary = self.task(root)
        primary["dependencies"] = [task_id]
        self.write(root / "orchestration/tasks/T-SYNTHETIC-001.v1.json", primary)
        ref = f"orchestration/tasks/{task_id}.v{version}.json"
        evidence_ref = f"orchestration/completions/{task_id}.v{version}.json"
        dep = copy.deepcopy(primary)
        dep.update(task_id=task_id, status=status, dependencies=[], attempt=attempt,
                   completion_evidence=[evidence_ref] if evidence else [])
        self.write(root / ref, dep)
        if evidence:
            record = {"schema_version": 1, "task_id": task_id, "attempt": attempt,
                      "task_ref": ref, "status": "COMPLETED",
                      "content_sha256": self.digest(root / ref)}
            self.write(root / evidence_ref, record)
        state = self.state(root)
        state["tasks"][task_id] = ref
        self.save_state(root, state)
        return dep, ref, evidence_ref

    def test_positive_precompletion_dispatch_then_completion_denies(self):
        temporary, root = self.fixture(); self.addCleanup(temporary.cleanup)
        result = self.decide(root)
        self.assertEqual((result["decision"], result["execution_adapter"]), ("DISPATCH", "MOCK_ONLY"))
        shutil.copy2(ROOT / "docs/handoffs/H-M0-034.v3.json", root / "docs/handoffs/H-M0-034.v3.json")
        self.assertEqual(self.decide(root)["decision"], "DENY")
        self.assertEqual(decision(ROOT, INTENT)["decision"], "DENY")

    def test_assignment_exact_fields_and_claim_contradictions_deny(self):
        mutations = (
            {"task_id": "T-OTHER"}, {"attempt": 2}, {"owner": "05 Skeptic"},
            {"milestone": "M0.3"}, {"handoff_ref": "docs/handoffs/H-M0-034.v1.json"},
            {"claim_generation": 2}, {"status": "COMPLETED"},
        )
        for mutation in mutations:
            temporary, root = self.fixture(); self.addCleanup(temporary.cleanup)
            record = self.assignment(root); record.update(mutation)
            self.write(root / "orchestration/assignments/T-SYNTHETIC-001.v1.json", record)
            self.assertEqual(self.decide(root)["decision"], "DENY")
        for mutation in ({"attempt": 2}, {"role": "05 Skeptic"}, {"generation": 2},
                         {"status": "RELEASED"}, {"handoff_ref": "docs/handoffs/H-M0-034.v1.json"}):
            temporary, root = self.fixture(); self.addCleanup(temporary.cleanup)
            state = self.state(root); state["claims"]["T-SYNTHETIC-001"].update(mutation); self.save_state(root, state)
            self.assertEqual(self.decide(root)["decision"], "DENY")

    def test_assignment_copied_or_missing_denies(self):
        temporary, root = self.fixture(); self.addCleanup(temporary.cleanup)
        (root / "orchestration/assignments/T-SYNTHETIC-001.v1.json").unlink()
        self.assertEqual(self.decide(root)["decision"], "DENY")
        temporary, root = self.fixture(); self.addCleanup(temporary.cleanup)
        record = self.assignment(root); record["extra"] = "copied altered content"
        self.write(root / "orchestration/assignments/T-SYNTHETIC-001.v1.json", record)
        self.assertEqual(self.decide(root)["decision"], "DENY")

    def test_demonstrates_superseding_assignment_is_ignored(self):
        temporary, root = self.fixture(); self.addCleanup(temporary.cleanup)
        newer = self.assignment(root); newer["status"] = "COMPLETED"
        self.write(root / "orchestration/assignments/T-SYNTHETIC-001.v2.json", newer)
        self.assertEqual(self.decide(root)["decision"], "DISPATCH")

    def test_demonstrates_handoff_can_describe_another_task(self):
        temporary, root = self.fixture(); self.addCleanup(temporary.cleanup)
        handoff = read(root / "docs/handoffs/H-M0-034.v2.json")
        handoff["request"] = "Claim unrelated T-OTHER attempt 77 only."
        handoff["work_done"] = "No assignment for T-SYNTHETIC-001 exists in this handoff."
        self.write(root / "docs/handoffs/H-M0-034.v2.json", handoff)
        self.assertEqual(self.decide(root)["decision"], "DISPATCH")

    def test_dependency_correct_current_completed_head_dispatches(self):
        temporary, root = self.fixture(); self.addCleanup(temporary.cleanup)
        self.add_dependency(root)
        self.assertEqual(self.decide(root)["decision"], "DISPATCH")

    def test_dependency_prose_wrong_attempt_hash_unrelated_and_missing_deny(self):
        temporary, root = self.fixture(); self.addCleanup(temporary.cleanup)
        _, _, evidence_ref = self.add_dependency(root)
        self.write(root / evidence_ref, {"claim": "human says complete"})
        self.assertEqual(self.decide(root)["decision"], "DENY")
        for mutation in ({"attempt": 999}, {"task_id": "T-OTHER"}, {"content_sha256": "0" * 64}):
            temporary, root = self.fixture(); self.addCleanup(temporary.cleanup)
            _, _, evidence_ref = self.add_dependency(root)
            record = read(root / evidence_ref); record.update(mutation); self.write(root / evidence_ref, record)
            self.assertEqual(self.decide(root)["decision"], "DENY")
        temporary, root = self.fixture(); self.addCleanup(temporary.cleanup)
        task = self.task(root); task["dependencies"] = ["T-MISSING"]
        self.write(root / "orchestration/tasks/T-SYNTHETIC-001.v1.json", task)
        self.assertEqual(self.decide(root)["decision"], "DENY")

    def test_dependency_stale_v1_against_v2_variants_denies_and_current_v2_succeeds(self):
        for status, evidence in (("BLOCKED", False), ("COMPLETED", False), ("COMPLETED", True)):
            temporary, root = self.fixture(); self.addCleanup(temporary.cleanup)
            self.add_dependency(root, version=1)
            self.add_dependency(root, version=2, status=status, evidence=evidence)
            state = self.state(root); state["tasks"]["T-DEPENDENCY"] = "orchestration/tasks/T-DEPENDENCY.v1.json"; self.save_state(root, state)
            self.assertEqual(self.decide(root)["decision"], "DENY")
        temporary, root = self.fixture(); self.addCleanup(temporary.cleanup)
        self.add_dependency(root, version=1)
        self.add_dependency(root, version=2)
        self.assertEqual(self.decide(root)["decision"], "DISPATCH")

    def test_demonstrates_lexicographic_dependency_head_accepts_stale_v2_over_v10(self):
        temporary, root = self.fixture(); self.addCleanup(temporary.cleanup)
        self.add_dependency(root, version=2)
        self.add_dependency(root, version=10, status="BLOCKED", evidence=False)
        state = self.state(root); state["tasks"]["T-DEPENDENCY"] = "orchestration/tasks/T-DEPENDENCY.v2.json"; self.save_state(root, state)
        self.assertEqual(self.decide(root)["decision"], "DISPATCH")

    def test_dependency_path_identity_and_cycles_deny(self):
        temporary, root = self.fixture(); self.addCleanup(temporary.cleanup)
        _, ref, _ = self.add_dependency(root)
        wrong = root / "orchestration/tasks/T-OTHER.v1.json"; shutil.copy2(root / ref, wrong)
        state = self.state(root); state["tasks"]["T-DEPENDENCY"] = str(wrong.relative_to(root)); self.save_state(root, state)
        self.assertEqual(self.decide(root)["decision"], "DENY")
        temporary, root = self.fixture(); self.addCleanup(temporary.cleanup)
        task = self.task(root); task["dependencies"] = [task["task_id"]]
        self.write(root / "orchestration/tasks/T-SYNTHETIC-001.v1.json", task)
        self.assertEqual(self.decide(root)["decision"], "DENY")
        temporary, root = self.fixture(); self.addCleanup(temporary.cleanup)
        dep, ref, evidence_ref = self.add_dependency(root); dep["dependencies"] = ["T-SYNTHETIC-001"]
        self.write(root / ref, dep)
        evidence = read(root / evidence_ref); evidence["content_sha256"] = self.digest(root / ref); self.write(root / evidence_ref, evidence)
        self.assertEqual(self.decide(root)["decision"], "DENY")

        temporary, root = self.fixture(); self.addCleanup(temporary.cleanup)
        first, first_ref, first_evidence_ref = self.add_dependency(root, task_id="T-DEPENDENCY-A")
        first["dependencies"] = ["T-DEPENDENCY-B"]
        self.write(root / first_ref, first)
        first_evidence = read(root / first_evidence_ref)
        first_evidence["content_sha256"] = self.digest(root / first_ref)
        self.write(root / first_evidence_ref, first_evidence)
        second = copy.deepcopy(first)
        second.update(task_id="T-DEPENDENCY-B", dependencies=["T-DEPENDENCY-A"],
                      completion_evidence=["orchestration/completions/T-DEPENDENCY-B.v1.json"])
        second_ref = "orchestration/tasks/T-DEPENDENCY-B.v1.json"
        self.write(root / second_ref, second)
        self.write(root / "orchestration/completions/T-DEPENDENCY-B.v1.json", {
            "schema_version": 1, "task_id": "T-DEPENDENCY-B", "attempt": second["attempt"],
            "task_ref": second_ref, "status": "COMPLETED", "content_sha256": self.digest(root / second_ref),
        })
        state = self.state(root); state["tasks"]["T-DEPENDENCY-B"] = second_ref; self.save_state(root, state)
        self.assertEqual(self.decide(root)["decision"], "DENY")

    def test_receipt_determinism_ordering_and_represented_inputs(self):
        temporary, root = self.fixture(); self.addCleanup(temporary.cleanup)
        original = self.decide(root)["decision_id"]
        self.assertEqual(original, self.decide(root)["decision_id"])
        state = self.state(root); self.write(root / "orchestration/scheduler-state.json", state, sort_keys=False)
        self.assertEqual(original, self.decide(root)["decision_id"])
        handoff = read(root / "docs/handoffs/H-M0-034.v2.json"); handoff["request"] += " canonical change"
        self.write(root / "docs/handoffs/H-M0-034.v2.json", handoff)
        self.assertNotEqual(original, self.decide(root)["decision_id"])

    def test_receipt_changes_for_task_assignment_capability_claim_project_and_stop(self):
        mutations = ("task", "assignment", "capability", "claim", "project", "stop")
        for kind in mutations:
            temporary, root = self.fixture(); self.addCleanup(temporary.cleanup)
            original = self.decide(root)["decision_id"]
            if kind == "task":
                task = self.task(root); task["operation"] = "STATE_READ"; self.write(root / "orchestration/tasks/T-SYNTHETIC-001.v1.json", task)
            elif kind == "assignment":
                assignment = self.assignment(root); assignment["status"] = "COMPLETED"; self.write(root / "orchestration/assignments/T-SYNTHETIC-001.v1.json", assignment)
            elif kind == "capability":
                capability = self.capability(root); capability["name"] = "changed safe capability"; self.write(root / "orchestration/capabilities/C-REPOSITORY-READ.json", capability)
            elif kind == "claim":
                state = self.state(root); state["generation"] = 2; state["claims"]["T-SYNTHETIC-001"]["generation"] = 2; self.save_state(root, state)
                assignment = self.assignment(root); assignment["claim_generation"] = 2; self.write(root / "orchestration/assignments/T-SYNTHETIC-001.v1.json", assignment)
            elif kind == "project":
                project = read(root / "docs/project-state.json"); self.write(root / "docs/project-state.json", project)
                state = self.state(root); self.save_state(root, state)
            else:
                stop = read(root / "reports/stops/STOP-M0-001.v1.json"); stop["reason"] += " changed"; self.write(root / "reports/stops/STOP-M0-001.v1.json", stop)
                state = self.state(root); self.save_state(root, state)
            self.assertNotEqual(original, self.decide(root)["decision_id"])

    def test_receipt_changes_for_dependency_task_and_completion_semantics(self):
        temporary, root = self.fixture(); self.addCleanup(temporary.cleanup)
        dep, ref, evidence_ref = self.add_dependency(root)
        original = self.decide(root)["decision_id"]
        dep["attempt"] = 2; self.write(root / ref, dep)
        evidence = read(root / evidence_ref); evidence["attempt"] = 2; evidence["content_sha256"] = self.digest(root / ref); self.write(root / evidence_ref, evidence)
        self.assertEqual(self.decide(root)["decision"], "DISPATCH")
        self.assertNotEqual(original, self.decide(root)["decision_id"])

    def test_denied_subject_and_reason_are_bound(self):
        a = decision(ROOT, {"task_id": "T-UNKNOWN-A", "attempt": 1})
        b = decision(ROOT, {"task_id": "T-UNKNOWN-B", "attempt": 1})
        c = decision(ROOT, {"task_id": "T-UNKNOWN-A"})
        self.assertEqual(a["reason"], b["reason"]); self.assertNotEqual(a["decision_id"], b["decision_id"])
        self.assertNotEqual(a["reason"], c["reason"]); self.assertNotEqual(a["decision_id"], c["decision_id"])

    def test_demonstrates_denial_receipt_omits_changed_authoritative_state(self):
        temporary, root = self.fixture(); self.addCleanup(temporary.cleanup)
        project = read(root / "docs/project-state.json"); project["status"] = "ACTIVE"
        self.write(root / "docs/project-state.json", project); state = self.state(root); self.save_state(root, state)
        first = self.decide(root)
        project["status"] = "PAUSED"; self.write(root / "docs/project-state.json", project); state = self.state(root); self.save_state(root, state)
        second = self.decide(root)
        self.assertEqual(first["reason"], second["reason"])
        self.assertEqual(first["decision_id"], second["decision_id"])

    def test_closed_finding_regressions(self):
        temporary, root = self.fixture(); self.addCleanup(temporary.cleanup)
        for attempt in (True, False, "1", 1.0, 0, -1, 2147483648):
            self.assertEqual(self.decide(root, {"task_id": "T-SYNTHETIC-001", "attempt": attempt})["decision"], "DENY")
        extra = read(root / "reports/stops/STOP-M0-001.v1.json"); extra.update(id="STOP-M0-002", reason="unknown open stop")
        self.write(root / "reports/stops/STOP-M0-002.v1.json", extra)
        self.assertEqual(self.decide(root)["decision"], "DENY")
        with patch("src.edgelab.orchestration._remote", return_value="wrong"):
            self.assertEqual(decision(ROOT, INTENT)["decision"], "DENY")
        with patch("src.edgelab.orchestration._is_ancestor_of_remote_main", return_value=False):
            self.assertEqual(decision(ROOT, INTENT)["decision"], "DENY")
        with self.assertRaisesRegex(ValueError, "FUTURE_GATE"):
            completion(ROOT, INTENT, evidence=["prose"])

    def test_unified_capability_regression(self):
        for mutation in ({"capabilities": ["LIVE"]}, {"permissions": ["MCP"]},
                         {"semantic_types": ["NETWORK"], "capabilities": ["NETWORK"], "permissions": ["NETWORK"]},
                         {"revoked": True}, {"network_required": True}):
            temporary, root = self.fixture(); self.addCleanup(temporary.cleanup)
            capability = self.capability(root); capability.update(mutation)
            self.write(root / "orchestration/capabilities/C-REPOSITORY-READ.json", capability)
            self.assertEqual(self.decide(root)["decision"], "DENY")
        for refs in ([], ["C-UNKNOWN"], ["C-REPOSITORY-READ", "C-REPOSITORY-READ"]):
            temporary, root = self.fixture(); self.addCleanup(temporary.cleanup)
            task = self.task(root); task["capability_refs"] = refs
            self.write(root / "orchestration/tasks/T-SYNTHETIC-001.v1.json", task)
            self.assertEqual(self.decide(root)["decision"], "DENY")


if __name__ == "__main__":
    unittest.main()
