"""Final-tree owner checks for the M0.2 mock-only preflight."""
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.edgelab.orchestration import EXPECTED_REMOTE, decision
from src.edgelab.validate import ROOT, read


class FinalOrchestrationTests(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory(); root = Path(temporary.name)
        for rel in ("docs/project-state.json", "docs/handoffs/H-M0-034.v1.json", "docs/handoffs/H-M0-034.v2.json", "reports/stops/STOP-M0-001.v1.json", "orchestration/scheduler-state.json", "orchestration/tasks/T-SYNTHETIC-001.v1.json", "orchestration/assignments/T-SYNTHETIC-001.v1.json", "orchestration/capabilities/C-REPOSITORY-READ.json", "schemas/project-state.schema.json", "schemas/stop.schema.json", "schemas/handoff.schema.json", "schemas/orchestration-task.schema.json", "schemas/scheduler-state.schema.json", "schemas/capability-registry.schema.json"):
            target=root/rel; target.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(ROOT/rel,target)
        return temporary, root
    def decide(self, root, intent):
        with patch("src.edgelab.orchestration.ROOT",root), patch("src.edgelab.orchestration._remote",return_value=EXPECTED_REMOTE), patch("src.edgelab.orchestration._is_ancestor_of_remote_main",return_value=True): return decision(root,intent)
    def test_final_tree_completed_claim_denies(self): self.assertEqual(decision(ROOT,{"task_id":"T-SYNTHETIC-001","attempt":1})["decision"],"DENY")
    def test_precompletion_bound_fixture_dispatches_and_receipts_differ(self):
        temporary,root=self.fixture(); self.addCleanup(temporary.cleanup)
        good=self.decide(root,{"task_id":"T-SYNTHETIC-001","attempt":1}); self.assertEqual(good["decision"],"DISPATCH")
        bad=self.decide(root,{"task_id":"T-UNKNOWN","attempt":1}); self.assertEqual(bad["decision"],"DENY"); self.assertNotEqual(good["decision_id"],bad["decision_id"])
    def test_boolean_attempt_denies(self):
        temporary,root=self.fixture(); self.addCleanup(temporary.cleanup)
        self.assertEqual(self.decide(root,{"task_id":"T-SYNTHETIC-001","attempt":True})["decision"],"DENY")
