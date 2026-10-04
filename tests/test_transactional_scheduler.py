"""M0.3A synthetic runtime acceptance: no workers, network, executor, or capital."""
from __future__ import annotations
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.edgelab.transactional_scheduler import Scheduler, RuntimeUnavailable, Bundle
from src.edgelab.validate import ROOT

class SchedulerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.s=Scheduler(ROOT,Path(self.tmp.name)/"runtime"); self.s.initialize(); self.s.create_task("T","receipt")
    def row(self):
        c=self.s.connect(); r=c.execute("select * from tasks where task_id='T'").fetchone(); c.close(); return r
    def req(self):
        r=self.row(); return {"expected":self.s.tuple(r),"repository_generation":r["repository_generation"],"receipt_digest":r["receipt_digest"]}
    def claim(self): return self.s.transition("CLAIM","T",{**self.req(),"actor":"worker"},operation_key="claim")
    def test_configuration_attachment_and_genesis(self):
        self.s.startup(); self.assertEqual(json.loads(self.s.attachment.read_text())["m0_2_freeze_commit"],"bc3a40924ca580ca6eddc4c24e32ff99ddd95330")
        self.s.attachment.unlink()
        with self.assertRaises(RuntimeUnavailable): self.s.startup()
    def test_double_claim_fence_and_lost_response_idempotency(self):
        claimed=self.claim(); claim=claimed["tuple"]
        with self.assertRaises(RuntimeUnavailable): self.s.transition("CLAIM","T",{**self.req(),"actor":"other"},operation_key="claim-2")
        start_request={**self.req(),"claim_id":claim["active_claim_id"],"fence":claim["task_fence"]}
        with self.assertRaises(ConnectionError): self.s.transition("START","T",start_request,operation_key="start",inject="after_commit")
        retry=self.s.transition("START","T",start_request,operation_key="start")
        self.assertEqual(retry["tuple"]["execution"],"IN_PROGRESS")
        self.s.transition("CONTINUE","T",{**self.req(),"claim_id":claim["active_claim_id"],"fence":claim["task_fence"]},operation_key="continue")
        current=self.req(); self.s.transition("YIELD","T",{**current,"claim_id":claim["active_claim_id"],"fence":claim["task_fence"]},operation_key="yield")
        with self.assertRaises(RuntimeUnavailable): self.s.transition("CONTINUE","T",{**self.req(),"claim_id":claim["active_claim_id"],"fence":claim["task_fence"]},operation_key="stale")
    def test_transaction_failures_are_atomic(self):
        before=self.row()["scheduler_generation"]
        for point in ("before_event","after_event","after_state","after_idempotency"):
            with self.assertRaises(RuntimeError): self.s.transition("CLAIM","T",{**self.req(),"actor":"worker"},operation_key="x"+point,inject=point)
            self.assertEqual(self.row()["scheduler_generation"],before)
    def test_complete_review_route_and_terminal(self):
        c=self.claim()["tuple"]; self.s.transition("START","T",{**self.req(),"claim_id":c["active_claim_id"],"fence":c["task_fence"]},operation_key="start")
        r=self.req(); self.s.transition("COMPLETE","T",{**r,"claim_id":r["expected"]["active_claim_id"],"fence":r["expected"]["task_fence"]},operation_key="complete")
        a=self.s.transition("ASSIGN_REVIEW","T",{**self.req(),"actor":"reviewer","role":"skeptic"},operation_key="assign")["tuple"]
        approved=self.s.transition("APPROVE","T",{**self.req(),"reviewer_id":a["reviewer_assignment_id"]},operation_key="approve")["tuple"]
        self.assertEqual(approved["review"],"APPROVED")
        self.s.transition("ROUTE","T",{**self.req(),"routing_evidence":"synthetic"},operation_key="route")
        with self.assertRaises(RuntimeUnavailable): self.s.transition("REJECT","T",{**self.req(),"reviewer_id":"x"},operation_key="resurrect")
    def test_recovery_retry_governance_and_replay(self):
        c=self.claim()["tuple"]; self.s.transition("RECOVER","T",{**self.req(),"liveness_evidence":"synthetic"},operation_key="recover")
        c=self.s.transition("CLAIM","T",{**self.req(),"actor":"worker"},operation_key="claim-again")["tuple"]; self.s.transition("FAIL","T",{**self.req(),"claim_id":c["active_claim_id"],"fence":c["task_fence"]},operation_key="fail")
        self.s.transition("RETRY","T",{**self.req(),"retryable":True},operation_key="retry")
        self.s.transition("GOVERNANCE_BLOCK","T",self.req(),operation_key="block")
        self.s.transition("REVALIDATE","T",self.req(),operation_key="revalidate"); self.s.startup()
    def test_backup_export_and_corruption_fail_closed(self):
        backup=Path(self.tmp.name)/"backup.sqlite"; digest=self.s.backup(backup); self.assertEqual(len(digest),64)
        export=self.s.export(Path(self.tmp.name)/"export.json"); self.assertNotIn("checkout_local_nonce",json.dumps(export)); self.assertEqual(len(export["snapshot_digest"]),64)
        c=self.s.connect(); c.execute("update task_events set prev_task_digest='bad' where task_seq=1"); c.commit(); c.close()
        with self.assertRaises(RuntimeUnavailable): self.s.startup()
    def test_wrong_repo_and_generation_stale_deny(self):
        with patch.object(self.s,"bundle",side_effect=RuntimeUnavailable("wrong repository")):
            with self.assertRaises(RuntimeUnavailable): self.s.transition("CLAIM","T",{**self.req(),"actor":"x"},operation_key="bad")
        r=self.req(); r["repository_generation"]+=1
        with self.assertRaises(RuntimeUnavailable): self.s.transition("CLAIM","T",{**r,"actor":"x"},operation_key="stale")
    def test_remediation_is_two_event_atomic_and_replayable(self):
        c=self.claim()["tuple"]; self.s.transition("START","T",{**self.req(),"claim_id":c["active_claim_id"],"fence":c["task_fence"]},operation_key="start")
        r=self.req(); self.s.transition("COMPLETE","T",{**r,"claim_id":r["expected"]["active_claim_id"],"fence":r["expected"]["task_fence"]},operation_key="complete")
        a=self.s.transition("ASSIGN_REVIEW","T",{**self.req(),"actor":"reviewer","role":"skeptic"},operation_key="assign")["tuple"]
        self.s.transition("REMEDIATE","T",{**self.req(),"reviewer_id":a["reviewer_assignment_id"]},operation_key="remediate")
        request={"expected":self.req()["expected"],"repository_generation":self.req()["repository_generation"],"decision_digest":"d"*64,"receipt_digest":"child","owner":"owner"}
        with self.assertRaises(RuntimeError): self.s.create_remediation("T","C",request,operation_key="link-fail",inject="after_event")
        c=self.s.connect(); self.assertIsNone(c.execute("select 1 from tasks where task_id='C'").fetchone()); c.close()
        result=self.s.create_remediation("T","C",request,operation_key="link")
        self.assertEqual(len(result["relationship_id"]),36); self.s.startup()
        c=self.s.connect(); self.assertEqual(c.execute("select count(*) from task_events where task_id in ('T','C')").fetchone()[0],8); self.assertEqual(c.execute("select count(*) from remediation_links").fetchone()[0],1); c.close()
    def test_migration_success_failure_and_schema_denial(self):
        backup=Path(self.tmp.name)/"migration.sqlite"; self.s.migrate(1,"a"*64,backup)
        c=self.s.connect(); self.assertEqual(c.execute("select count(*) from migration_ledger").fetchone()[0],1); c.close()
        with self.assertRaises(RuntimeError): self.s.migrate(1,"b"*64,Path(self.tmp.name)/"failed.sqlite",inject=True)
        self.s.startup()
        for version in (0,2):
            with self.assertRaises(RuntimeUnavailable): self.s.migrate(version,"c"*64,backup)
    def test_final_bundle_recheck_and_generation_advance(self):
        original=self.s.bundle(); changed=Bundle(original.commit,"f"*64,original.project,original.stops,original.policy,original.tasks)
        with patch.object(self.s,"bundle",side_effect=[original,changed]):
            with self.assertRaises(RuntimeUnavailable): self.s.transition("CLAIM","T",{**self.req(),"actor":"worker"},operation_key="toctou")
        self.assertEqual(self.row()["execution"],"CLAIMABLE")
        self.s.import_repository(["T"]); self.assertEqual(self.row()["repository_generation"],0)
        with patch.object(self.s,"bundle",return_value=changed): self.s.import_repository(["T"])
        self.assertEqual(self.row()["repository_generation"],1)

if __name__ == "__main__": unittest.main()
