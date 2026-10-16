"""M0.3A synthetic runtime acceptance: no workers, network, executor, or capital."""
from __future__ import annotations
import inspect
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator, RefResolver

import src.edgelab.authority_binding as authority_binding
from src.edgelab.authority_binding import compose_authority_binding, verify_binding_integrity
from src.edgelab.locked_authority import read_locked_authority
from src.edgelab.transactional_scheduler import Scheduler, RuntimeUnavailable, Bundle, digest
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
        approved=self.s.transition("APPROVE","T",{**self.req(),"reviewer_id":a["reviewer_assignment_id"],"decision_digest":"a"*64},operation_key="approve")["tuple"]
        self.assertEqual(approved["review"],"APPROVED")
        self.s.transition("ROUTE","T",{**self.req(),"routing_evidence":"synthetic"},operation_key="route")
        with self.assertRaises(RuntimeUnavailable): self.s.transition("REJECT","T",{**self.req(),"reviewer_id":"x"},operation_key="resurrect")
    def test_recovery_retry_governance_and_replay(self):
        c=self.claim()["tuple"]; self.s.transition("RECOVER","T",{**self.req(),"liveness_evidence":"synthetic"},operation_key="recover")
        c=self.s.transition("CLAIM","T",{**self.req(),"actor":"worker"},operation_key="claim-again")["tuple"]; self.s.transition("FAIL","T",{**self.req(),"claim_id":c["active_claim_id"],"fence":c["task_fence"]},operation_key="fail")
        self.s.transition("RETRY","T",{**self.req(),"retryable":True},operation_key="retry")
        self.s.transition("GOVERNANCE_BLOCK","T",self.req(),operation_key="block")
        self.s.transition("REVALIDATE","T",self.req(),operation_key="revalidate"); self.s.startup()
    def test_writer_request_domains_are_exact_and_replayable(self):
        malformed=self.req(); malformed["expected"]={**malformed["expected"],"scheduler_generation":False}; malformed["repository_generation"]=False
        with self.assertRaisesRegex(RuntimeUnavailable,"stale tuple"):
            self.s.transition("CLAIM","T",{**malformed,"actor":"worker"},operation_key="boolean-cas")
        with self.assertRaisesRegex(RuntimeUnavailable,"task identity"): self.s.create_task("","receipt")
        with self.assertRaisesRegex(RuntimeUnavailable,"origin binding"):
            self.s.transition("INITIALIZE","U",{"receipt_digest":"receipt","owner":"owner","extra":"denied"},operation_key="extra-origin")

        claim=self.claim()["tuple"]
        with self.assertRaises(RuntimeUnavailable):
            self.s.transition("RECOVER","T",{**self.req(),"liveness_evidence":{"documented":False}},operation_key="untyped-liveness")
        with self.assertRaisesRegex(RuntimeUnavailable,"worker fence"):
            self.s.transition("START","T",{**self.req(),"claim_id":claim["active_claim_id"],"fence":True},operation_key="boolean-fence")
        self.s.transition("START","T",{**self.req(),"claim_id":claim["active_claim_id"],"fence":claim["task_fence"]},operation_key="start")
        current=self.req()
        with self.assertRaisesRegex(RuntimeUnavailable,"completion mode"):
            self.s.transition("COMPLETE","T",{**current,"claim_id":current["expected"]["active_claim_id"],"fence":current["expected"]["task_fence"],"close":"false"},operation_key="string-close")
        current=self.req(); self.s.transition("FAIL","T",{**current,"claim_id":current["expected"]["active_claim_id"],"fence":current["expected"]["task_fence"]},operation_key="fail")
        with self.assertRaises(RuntimeUnavailable): self.s.transition("RETRY","T",{**self.req(),"retryable":1},operation_key="numeric-retry")

        original=self.s.bundle(); changed=Bundle(original.commit,"f"*64,original.project,original.stops,original.policy,original.tasks)
        with patch.object(self.s,"bundle",return_value=changed):
            with self.assertRaisesRegex(RuntimeUnavailable,"import binding"): self.s.import_repository(["T"],reason="")
        self.s.startup()
    def test_backup_export_and_corruption_fail_closed(self):
        backup=Path(self.tmp.name)/"backup.sqlite"; digest=self.s.backup(backup); self.assertEqual(len(digest),64)
        export=self.s.export(Path(self.tmp.name)/"export.json"); self.assertNotIn("checkout_local_nonce",json.dumps(export)); self.assertEqual(len(export["snapshot_digest"]),64)
        c=self.s.connect(); c.execute("update task_events set prev_task_digest='bad' where task_seq=1"); c.commit(); c.close()
        with self.assertRaises(RuntimeUnavailable): self.s.startup()
    def test_replay_detects_event_digest_and_materialized_state_mutation(self):
        c=self.s.connect(); c.execute("update tasks set scheduler_generation=99 where task_id='T'"); c.commit(); c.close()
        with self.assertRaisesRegex(RuntimeUnavailable,"replay/materialized"): self.s.startup()
        self.tmp.cleanup(); self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.s=Scheduler(ROOT,Path(self.tmp.name)/"runtime"); self.s.initialize(); self.s.create_task("T","receipt")
        c=self.s.connect(); c.execute("update task_events set payload='{}' where task_seq=1"); c.commit(); c.close()
        with self.assertRaisesRegex(RuntimeUnavailable,"event digest"): self.s.startup()
    def test_replay_rejects_task_event_task_and_attempt_substitution(self):
        c=self.s.connect(); c.execute("update task_events set task_id='OTHER' where task_seq=1"); c.commit(); c.close()
        with self.assertRaisesRegex(RuntimeUnavailable,"task inventory"): self.s.startup()
        self.tmp.cleanup(); self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.s=Scheduler(ROOT,Path(self.tmp.name)/"runtime"); self.s.initialize(); self.s.create_task("T","receipt")
        c=self.s.connect(); c.execute("update task_events set attempt=99 where task_seq=1"); c.commit(); c.close()
        with self.assertRaisesRegex(RuntimeUnavailable,"attempt mismatch"): self.s.startup()
    def test_replay_rejects_missing_and_eventless_task_materialization(self):
        c=self.s.connect(); c.execute("delete from tasks where task_id='T'"); c.commit(); c.close()
        with self.assertRaisesRegex(RuntimeUnavailable,"task inventory"): self.s.startup()
        self.tmp.cleanup(); self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.s=Scheduler(ROOT,Path(self.tmp.name)/"runtime"); self.s.initialize(); self.s.create_task("T","receipt")
        c=self.s.connect(); c.execute("INSERT INTO tasks SELECT 'EXTRA',attempt,workflow,execution,review,scheduler_generation,dispatch_generation,task_fence,claim_id,reviewer_id,continuations,repository_generation,receipt_digest,owner,reviewer,predecessor_task,successor_task FROM tasks WHERE task_id='T'"); c.commit(); c.close()
        with self.assertRaisesRegex(RuntimeUnavailable,"task inventory"): self.s.startup()
    def test_replay_rejects_before_after_discontinuity_even_when_rehashed(self):
        self.claim(); c=self.s.connect(); row=c.execute("select * from task_events where task_id='T' order by task_seq desc limit 1").fetchone()
        before=json.loads(row["before_json"]); before["scheduler_generation"]=99
        rebuilt={"id":row["event_id"],"n":row["global_seq"],"seq":row["task_seq"],"type":row["event_type"],"before":before,"after":json.loads(row["after_json"]),"payload":json.loads(row["payload"]),"prev":row["prev_task_digest"]}
        event_digest=digest(rebuilt)
        c.execute("update task_events set before_json=?,event_digest=? where event_id=?",(json.dumps(before),event_digest,row["event_id"])); c.execute("update meta set v=? where k='global_head_digest'",(json.dumps(event_digest),)); c.commit(); c.close()
        with self.assertRaisesRegex(RuntimeUnavailable,"before/after discontinuity"): self.s.startup()
    def test_replay_rejects_rehashed_advanced_origin_tuple(self):
        c=self.s.connect(); row=c.execute("select * from task_events where task_id='T' and task_seq=1").fetchone(); after=json.loads(row["after_json"])
        after.update({"workflow":"DIRECTOR_GATE_READY","execution":"EXECUTION_COMPLETED","review":"APPROVED","scheduler_generation":777})
        rebuilt={"id":row["event_id"],"n":row["global_seq"],"seq":row["task_seq"],"type":row["event_type"],"before":None,"after":after,"payload":json.loads(row["payload"]),"prev":row["prev_task_digest"]}; event_digest=digest(rebuilt)
        c.execute("update task_events set after_json=?,event_digest=? where event_id=?",(json.dumps(after),event_digest,row["event_id"])); c.execute("update tasks set workflow=?,execution=?,review=?,scheduler_generation=? where task_id='T'",(after["workflow"],after["execution"],after["review"],after["scheduler_generation"])); c.execute("update meta set v=? where k='global_head_digest'",(json.dumps(event_digest),)); c.commit(); c.close()
        with self.assertRaisesRegex(RuntimeUnavailable,"origin tuple"): self.s.startup()
    def test_wrong_repo_and_generation_stale_deny(self):
        with patch.object(self.s,"bundle",side_effect=RuntimeUnavailable("wrong repository")):
            with self.assertRaises(RuntimeUnavailable): self.s.transition("CLAIM","T",{**self.req(),"actor":"x"},operation_key="bad")
        r=self.req(); r["repository_generation"]+=1
        with self.assertRaises(RuntimeUnavailable): self.s.transition("CLAIM","T",{**r,"actor":"x"},operation_key="stale")
    def test_remediation_is_two_event_atomic_and_replayable(self):
        c=self.claim()["tuple"]; self.s.transition("START","T",{**self.req(),"claim_id":c["active_claim_id"],"fence":c["task_fence"]},operation_key="start")
        r=self.req(); self.s.transition("COMPLETE","T",{**r,"claim_id":r["expected"]["active_claim_id"],"fence":r["expected"]["task_fence"]},operation_key="complete")
        a=self.s.transition("ASSIGN_REVIEW","T",{**self.req(),"actor":"reviewer","role":"skeptic"},operation_key="assign")["tuple"]
        self.s.transition("REMEDIATE","T",{**self.req(),"reviewer_id":a["reviewer_assignment_id"],"decision_digest":"d"*64},operation_key="remediate")
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
        self.s.startup()
        c=self.s.connect(); event=c.execute("select * from task_events where task_id='T' order by task_seq desc limit 1").fetchone(); c.close()
        self.assertEqual(event["event_type"],"REPOSITORY_GENERATION_APPLIED")
        self.assertEqual(json.loads(event["before_json"])["repository_generation"],0)
        self.assertEqual(json.loads(event["after_json"])["repository_generation"],1)
    def test_generation_advance_governance_block_is_replayable_and_duplicates_deny(self):
        self.claim(); original=self.s.bundle(); changed=Bundle(original.commit,"e"*64,original.project,original.stops,original.policy,original.tasks)
        with patch.object(self.s,"bundle",return_value=changed):
            with self.assertRaisesRegex(RuntimeUnavailable,"duplicate affected"):
                self.s.import_repository(["T","T"])
            self.s.import_repository(["T"])
        row=self.row()
        self.assertEqual((row["workflow"],row["execution"],row["repository_generation"]),("GOVERNANCE_BLOCKED","EXECUTION_BLOCKED",1))
        self.s.startup()
    def test_repository_import_supports_lagging_tasks_but_denies_stale_transition(self):
        self.s.create_task("U","receipt-u")
        original=self.s.bundle(); first=Bundle(original.commit,"1"*64,original.project,original.stops,original.policy,original.tasks); second=Bundle(original.commit,"2"*64,original.project,original.stops,original.policy,original.tasks)
        with patch.object(self.s,"bundle",return_value=first): self.s.import_repository(["T"])
        c=self.s.connect(); u=c.execute("select * from tasks where task_id='U'").fetchone(); c.close()
        stale={"expected":self.s.tuple(u),"repository_generation":1,"receipt_digest":u["receipt_digest"],"actor":"worker"}
        with patch.object(self.s,"bundle",return_value=first):
            with self.assertRaisesRegex(RuntimeUnavailable,"stale repository"): self.s.transition("CLAIM","U",stale,operation_key="stale-u")
        with patch.object(self.s,"bundle",return_value=second): self.s.import_repository(["U"])
        self.s.startup()
        c=self.s.connect(); event=c.execute("select payload from task_events where task_id='U' order by task_seq desc limit 1").fetchone(); c.close()
        payload=json.loads(event["payload"]); self.assertEqual((payload["old"],payload["task_old"],payload["new"]),(1,0,2))
    def test_cooperative_lock_contention_denies_without_mutation(self):
        with self.s.locked("holder"):
            with self.assertRaisesRegex(RuntimeUnavailable,"lock held"):
                with self.s.locked("second"): pass
        self.s.startup()

    def test_complete_requires_started_work_and_governance_scope_is_bounded(self):
        for actor in ("", None):
            with self.subTest(actor=actor):
                with self.assertRaisesRegex(RuntimeUnavailable,"claim actor"):
                    self.s.transition("CLAIM","T",{**self.req(),"actor":actor},operation_key=f"bad-actor-{actor!r}")
        claim=self.claim()["tuple"]
        request={**self.req(),"claim_id":claim["active_claim_id"],"fence":claim["task_fence"],"close":True}
        with self.assertRaises(RuntimeUnavailable):
            self.s.transition("COMPLETE","T",request,operation_key="premature-complete")
        self.s.transition("START","T",{**self.req(),"claim_id":claim["active_claim_id"],"fence":claim["task_fence"]},operation_key="start")
        current=self.req()
        self.s.transition("COMPLETE","T",{**current,"claim_id":current["expected"]["active_claim_id"],"fence":current["expected"]["task_fence"],"close":True},operation_key="complete")
        with self.assertRaises(RuntimeUnavailable):
            self.s.transition("GOVERNANCE_BLOCK","T",self.req(),operation_key="block-terminal")
        original=self.s.bundle(); changed=Bundle(original.commit,"f"*64,original.project,original.stops,original.policy,original.tasks)
        with patch.object(self.s,"bundle",return_value=changed):
            with self.assertRaisesRegex(RuntimeUnavailable,"transition scope"):
                self.s.import_repository(["T"])
        self.s.startup()

    def test_review_assignment_requires_nonempty_independent_identity(self):
        claim=self.claim()["tuple"]
        self.s.transition("START","T",{**self.req(),"claim_id":claim["active_claim_id"],"fence":claim["task_fence"]},operation_key="start")
        current=self.req()
        self.s.transition("COMPLETE","T",{**current,"claim_id":current["expected"]["active_claim_id"],"fence":current["expected"]["task_fence"]},operation_key="complete")
        for actor,role in (("","skeptic"),("reviewer",""),(None,"skeptic"),("reviewer",None)):
            with self.subTest(actor=actor,role=role):
                with self.assertRaisesRegex(RuntimeUnavailable,"review independence"):
                    self.s.transition("ASSIGN_REVIEW","T",{**self.req(),"actor":actor,"role":role},operation_key=f"bad-review-{actor!r}-{role!r}")
        self.s.startup()

    def test_replay_rejects_rehashed_semantically_impossible_event_delta_and_binding(self):
        self.claim()
        c=self.s.connect(); row=c.execute("select * from task_events where task_id='T' order by task_seq desc limit 1").fetchone()
        after=json.loads(row["after_json"]); after["execution"]="IN_PROGRESS"
        body={"id":row["event_id"],"n":row["global_seq"],"seq":row["task_seq"],"type":row["event_type"],"before":json.loads(row["before_json"]),"after":after,"payload":json.loads(row["payload"]),"prev":row["prev_task_digest"]}; event_digest=digest(body)
        c.execute("update task_events set after_json=?,event_digest=? where event_id=?",(json.dumps(after),event_digest,row["event_id"])); c.execute("update tasks set execution='IN_PROGRESS' where task_id='T'"); c.execute("update meta set v=? where k='global_head_digest'",(json.dumps(event_digest),)); c.commit(); c.close()
        with self.assertRaisesRegex(RuntimeUnavailable,"claim transition|event delta"):
            self.s.startup()

        self.tmp.cleanup(); self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.s=Scheduler(ROOT,Path(self.tmp.name)/"runtime"); self.s.initialize(); self.s.create_task("T","receipt"); self.claim()
        c=self.s.connect(); row=c.execute("select * from task_events where task_id='T' order by task_seq desc limit 1").fetchone()
        payload=json.loads(row["payload"]); payload["request"]["task_id"]="OTHER"
        body={"id":row["event_id"],"n":row["global_seq"],"seq":row["task_seq"],"type":row["event_type"],"before":json.loads(row["before_json"]),"after":json.loads(row["after_json"]),"payload":payload,"prev":row["prev_task_digest"]}; event_digest=digest(body)
        c.execute("update task_events set payload=?,event_digest=? where event_id=?",(json.dumps(payload),event_digest,row["event_id"])); c.execute("update meta set v=? where k='global_head_digest'",(json.dumps(event_digest),)); c.commit(); c.close()
        with self.assertRaisesRegex(RuntimeUnavailable,"request mismatch"):
            self.s.startup()

    def test_replay_reconstructs_attempt_claim_review_and_task_metadata(self):
        self.claim()
        mutations=(("tasks","owner='other'","task metadata"),("tasks","reviewer='forged'","task metadata"),("attempts","predecessor_attempt=99","attempt replay"),("claims","actor='other'","claim replay"),("claims","status='CLOSED'","claim replay"))
        for table,change,message in mutations:
            with self.subTest(table=table,change=change):
                c=self.s.connect(); c.execute(f"update {table} set {change}"); c.commit(); c.close()
                with self.assertRaisesRegex(RuntimeUnavailable,message): self.s.startup()
                self.tmp.cleanup(); self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
                self.s=Scheduler(ROOT,Path(self.tmp.name)/"runtime"); self.s.initialize(); self.s.create_task("T","receipt"); self.claim()

        self.s.transition("START","T",{**self.req(),"claim_id":self.req()["expected"]["active_claim_id"],"fence":self.req()["expected"]["task_fence"]},operation_key="start")
        current=self.req(); self.s.transition("COMPLETE","T",{**current,"claim_id":current["expected"]["active_claim_id"],"fence":current["expected"]["task_fence"]},operation_key="complete")
        self.s.transition("ASSIGN_REVIEW","T",{**self.req(),"actor":"reviewer","role":"skeptic"},operation_key="review")
        c=self.s.connect(); c.execute("update reviews set role='owner'"); c.commit(); c.close()
        with self.assertRaisesRegex(RuntimeUnavailable,"review replay"): self.s.startup()

    def test_replay_rejects_deleted_historical_claim(self):
        claim=self.claim()["tuple"]
        self.s.transition("YIELD","T",{**self.req(),"claim_id":claim["active_claim_id"],"fence":claim["task_fence"]},operation_key="yield")
        c=self.s.connect(); c.execute("delete from claims where task_id='T'"); c.commit(); c.close()
        with self.assertRaisesRegex(RuntimeUnavailable,"claim replay"): self.s.startup()

    def test_remediation_replay_binds_reciprocal_child_metadata_and_one_successor(self):
        claim=self.claim()["tuple"]
        self.s.transition("START","T",{**self.req(),"claim_id":claim["active_claim_id"],"fence":claim["task_fence"]},operation_key="start")
        current=self.req(); self.s.transition("COMPLETE","T",{**current,"claim_id":current["expected"]["active_claim_id"],"fence":current["expected"]["task_fence"]},operation_key="complete")
        assigned=self.s.transition("ASSIGN_REVIEW","T",{**self.req(),"actor":"reviewer","role":"skeptic"},operation_key="review")["tuple"]
        with self.assertRaisesRegex(RuntimeUnavailable,"decision digest"):
            self.s.transition("REMEDIATE","T",{**self.req(),"reviewer_id":assigned["reviewer_assignment_id"]},operation_key="missing-decision")
        self.s.transition("REMEDIATE","T",{**self.req(),"reviewer_id":assigned["reviewer_assignment_id"],"decision_digest":"d"*64},operation_key="remediate")
        request={"expected":self.req()["expected"],"repository_generation":self.req()["repository_generation"],"decision_digest":"d"*64,"receipt_digest":"child-receipt","owner":"child-owner"}
        with self.assertRaisesRegex(RuntimeUnavailable,"task identity"):
            self.s.create_remediation("T","",request,operation_key="empty-child")
        with self.assertRaisesRegex(RuntimeUnavailable,"remediation binding"):
            self.s.create_remediation("T","C",{**request,"decision_digest":"not-a-digest"},operation_key="bad-decision")
        with self.assertRaisesRegex(RuntimeUnavailable,"decision mismatch"):
            self.s.create_remediation("T","C",{**request,"decision_digest":"e"*64},operation_key="wrong-decision")
        self.s.startup()
        result=self.s.create_remediation("T","C",request,operation_key="link")
        self.s.startup()
        c=self.s.connect(); child_payload=json.loads(c.execute("select payload from task_events where task_id='C'").fetchone()[0]); c.close()
        self.assertEqual((child_payload["owner"],child_payload["receipt_digest"]),("child-owner","child-receipt"))
        request={**request,"expected":self.req()["expected"]}
        with self.assertRaisesRegex(RuntimeUnavailable,"lineage"):
            self.s.create_remediation("T","D",request,operation_key="second-link")

        c=self.s.connect(); link=dict(c.execute("select * from remediation_links").fetchone()); c.execute("delete from remediation_links"); c.commit(); c.close()
        with self.assertRaisesRegex(RuntimeUnavailable,"remediation link"): self.s.startup()
        c=self.s.connect(); c.execute("insert into remediation_links values (?,?,?,?,?,?,?)",tuple(link[key] for key in ("link_id","source_task","child_task","source_event","child_event","decision_digest","link_digest")))
        row=c.execute("select * from task_events where task_id='C'").fetchone(); payload=json.loads(row["payload"]); payload["owner"]="other"
        body={"id":row["event_id"],"n":row["global_seq"],"seq":row["task_seq"],"type":row["event_type"],"before":json.loads(row["before_json"]),"after":json.loads(row["after_json"]),"payload":payload,"prev":row["prev_task_digest"]}; event_digest=digest(body)
        c.execute("update task_events set payload=?,event_digest=? where event_id=?",(json.dumps(payload),event_digest,row["event_id"])); c.execute("update tasks set owner='other' where task_id='C'"); c.execute("update meta set v=? where k='global_head_digest'",(json.dumps(event_digest),)); c.commit(); c.close()
        with self.assertRaisesRegex(RuntimeUnavailable,"child metadata"): self.s.startup()

        self.assertEqual(len(result["relationship_id"]),36)

    def test_replay_binds_remediation_to_exact_review_decision(self):
        claim=self.claim()["tuple"]
        self.s.transition("START","T",{**self.req(),"claim_id":claim["active_claim_id"],"fence":claim["task_fence"]},operation_key="start")
        current=self.req(); self.s.transition("COMPLETE","T",{**current,"claim_id":current["expected"]["active_claim_id"],"fence":current["expected"]["task_fence"]},operation_key="complete")
        assigned=self.s.transition("ASSIGN_REVIEW","T",{**self.req(),"actor":"reviewer","role":"skeptic"},operation_key="review")["tuple"]
        self.s.transition("REMEDIATE","T",{**self.req(),"reviewer_id":assigned["reviewer_assignment_id"],"decision_digest":"d"*64},operation_key="remediate")
        request={"expected":self.req()["expected"],"repository_generation":self.req()["repository_generation"],"decision_digest":"d"*64,"receipt_digest":"child-receipt","owner":"child-owner"}
        self.s.create_remediation("T","C",request,operation_key="link")

        c=self.s.connect(); source=c.execute("select * from task_events where event_type='REMEDIATION_CREATED'").fetchone(); child=c.execute("select * from task_events where event_type='TASK_CREATED_FROM_REMEDIATION'").fetchone(); replacement="e"*64
        source_payload=json.loads(source["payload"]); source_payload["decision"]=replacement
        source_digest=digest({"id":source["event_id"],"n":source["global_seq"],"seq":source["task_seq"],"type":source["event_type"],"before":json.loads(source["before_json"]),"after":json.loads(source["after_json"]),"payload":source_payload,"prev":source["prev_task_digest"]})
        child_payload=json.loads(child["payload"]); child_payload["decision"]=replacement
        child_digest=digest({"id":child["event_id"],"n":child["global_seq"],"seq":child["task_seq"],"type":child["event_type"],"before":json.loads(child["before_json"]),"after":json.loads(child["after_json"]),"payload":child_payload,"prev":child["prev_task_digest"]})
        c.execute("update task_events set payload=?,event_digest=? where event_id=?",(json.dumps(source_payload),source_digest,source["event_id"])); c.execute("update task_events set payload=?,event_digest=?,prev_global_digest=? where event_id=?",(json.dumps(child_payload),child_digest,source_digest,child["event_id"]))
        link=dict(c.execute("select * from remediation_links").fetchone()); material={key:link[key] for key in ("link_id","source_task","child_task","source_event","child_event")}; material["decision_digest"]=replacement
        c.execute("update remediation_links set decision_digest=?,link_digest=? where link_id=?",(replacement,digest(material),link["link_id"])); c.execute("update meta set v=? where k='global_head_digest'",(json.dumps(child_digest),)); c.commit(); c.close()
        with self.assertRaisesRegex(RuntimeUnavailable,"remediation decision mismatch"): self.s.startup()


class LockedAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.s=Scheduler(ROOT,Path(self.tmp.name)/"runtime"); self.s.initialize(); self.s.create_task("T","receipt")
        self.schema=json.loads((ROOT/"schemas/m0-3a-locked-authority-read.v1.schema.json").read_text())
        self.v3=json.loads((ROOT/"schemas/m0-2-decision-evidence-verification-result.v3.schema.json").read_text())

    def row(self):
        c=self.s.connect(read_only=True); row=c.execute("select * from tasks where task_id='T'").fetchone(); c.close(); return row

    def req(self):
        row=self.row(); return {"expected":self.s.tuple(row),"repository_generation":row["repository_generation"],"receipt_digest":row["receipt_digest"]}

    def assert_closed(self,result):
        Draft202012Validator(self.schema).validate(result)
        Draft202012Validator(self.v3).validate(result["verification"])
        self.assertEqual(result["verification"]["authorizing_use"],"DENY")
        self.assertNotEqual(result["verification"]["currentness_status"],"CURRENT")

    def logical_state(self):
        c=self.s.connect(read_only=True)
        try:
            dump="\n".join(c.iterdump())
            heads={key:self.s._meta(c,key) for key in ("repository_generation","bundle_digest","global_head_id","global_head_digest")}
            counts={table:c.execute(f"select count(*) from {table}").fetchone()[0] for table in ("tasks","claims","runtime_events","task_events","idempotency")}
        finally:c.close()
        files={path.name:(digest(path.read_bytes()),path.stat().st_mode & 0o777) for path in (self.s.db,self.s.attachment,self.s.lock_path)}
        files[self.s.dir.name]=(None,self.s.dir.stat().st_mode & 0o777)
        return dump,heads,counts,files

    def test_coherent_actual_authority_is_schema_valid_and_deny_only(self):
        before_names={path.name for path in self.s.dir.iterdir()}
        before=self.logical_state(); result=read_locked_authority(self.s,"T"); after=self.logical_state()
        self.assert_closed(result)
        self.assertEqual(result["observation_status"],"COHERENT_DENY_ONLY")
        self.assertIsNone(result["failure_reason"])
        self.assertEqual(result["authority"]["task"]["tuple"]["decision_receipt_digest"],"receipt")
        self.assertEqual(result["authority_sha256"],digest(result["authority"]))
        self.assertEqual(before,after)
        self.assertEqual(before_names,{path.name for path in self.s.dir.iterdir()})

    def test_api_cannot_accept_caller_snapshots_bindings_or_receipts(self):
        signature=inspect.signature(read_locked_authority)
        self.assertEqual(tuple(signature.parameters),("scheduler","task_id"))
        with self.assertRaises(TypeError):
            read_locked_authority(self.s,"T",snapshot={})
        empty=read_locked_authority(self.s,"")
        self.assert_closed(empty); self.assertEqual(empty["failure_reason"],"TASK_UNKNOWN")

    def test_returned_denial_cannot_mutate_future_results(self):
        first=read_locked_authority(self.s,"T")
        first["verification"].update({"historical_status":"VALID","currentness_status":"CURRENT","runtime_compatible":True,"verifier_status":"PASS","generation_match":True,"authorizing_use":"ALLOW","reason_code":"NONE"})
        second=read_locked_authority(self.s,"T")
        self.assert_closed(second)

    def test_lock_contention_denies_without_logical_mutation(self):
        before=self.logical_state()
        with self.s.locked("holder"):
            result=read_locked_authority(self.s,"T")
        self.assert_closed(result)
        self.assertEqual((result["observation_status"],result["failure_reason"]),("UNAVAILABLE","LOCK_UNAVAILABLE"))
        self.assertEqual(before,self.logical_state())

    def test_repository_change_between_reads_denies(self):
        original=self.s.bundle(); changed=Bundle(original.commit,"f"*64,original.project,original.stops,original.policy,original.tasks)
        with patch.object(self.s,"bundle",side_effect=[original,changed]):
            result=read_locked_authority(self.s,"T")
        self.assert_closed(result)
        self.assertEqual(result["failure_reason"],"RACE_DETECTED")

    def test_stale_repository_bundle_denies(self):
        original=self.s.bundle(); changed=Bundle(original.commit,"e"*64,original.project,original.stops,original.policy,original.tasks)
        with patch.object(self.s,"bundle",return_value=changed):
            result=read_locked_authority(self.s,"T")
        self.assert_closed(result)
        self.assertEqual(result["failure_reason"],"BUNDLE_STALE")

    def test_unknown_task_and_incomplete_runtime_deny(self):
        unknown=read_locked_authority(self.s,"missing")
        self.assert_closed(unknown); self.assertEqual(unknown["failure_reason"],"TASK_UNKNOWN")
        missing=Scheduler(ROOT,Path(self.tmp.name)/"absent")
        unavailable=read_locked_authority(missing,"T")
        self.assert_closed(unavailable); self.assertEqual(unavailable["failure_reason"],"RUNTIME_UNAVAILABLE")
        self.assertFalse(missing.dir.exists())

    def test_missing_lock_or_unsafe_permissions_deny_without_repair(self):
        self.s.lock_path.unlink()
        missing=read_locked_authority(self.s,"T")
        self.assert_closed(missing); self.assertEqual(missing["failure_reason"],"RUNTIME_UNAVAILABLE")
        self.assertFalse(self.s.lock_path.exists())

        self.s.lock_path.touch(mode=0o600)
        self.s.attachment.chmod(0o644)
        unsafe=read_locked_authority(self.s,"T")
        self.assert_closed(unsafe); self.assertEqual(unsafe["failure_reason"],"RUNTIME_UNAVAILABLE")
        self.assertEqual(self.s.attachment.stat().st_mode & 0o777,0o644)

    def test_preexisting_sqlite_sidecar_denies_without_touching_it(self):
        sidecar=self.s.db.with_name(self.s.db.name+"-wal"); sidecar.write_bytes(b"pending")
        result=read_locked_authority(self.s,"T")
        self.assert_closed(result); self.assertEqual(result["failure_reason"],"RUNTIME_UNAVAILABLE")
        self.assertEqual(sidecar.read_bytes(),b"pending")

    def test_attachment_and_replay_corruption_deny(self):
        attachment=json.loads(self.s.attachment.read_text()); attachment["canonical_project_id"]="other"
        self.s.attachment.write_text(json.dumps(attachment))
        invalid=read_locked_authority(self.s,"T")
        self.assert_closed(invalid); self.assertEqual(invalid["failure_reason"],"AUTHORITY_INVALID")

        self.tmp.cleanup(); self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.s=Scheduler(ROOT,Path(self.tmp.name)/"runtime"); self.s.initialize(); self.s.create_task("T","receipt")
        c=self.s.connect(); c.execute("update task_events set payload='{}' where task_id='T'"); c.commit(); c.close()
        corrupt=read_locked_authority(self.s,"T")
        self.assert_closed(corrupt); self.assertEqual(corrupt["failure_reason"],"AUTHORITY_INVALID")

    def test_attachment_read_race_and_invalid_meta_deny(self):
        valid=self.s.attachment.read_text()
        attachment=json.loads(valid); attachment["canonical_project_id"]="tampered"
        reads=iter((valid,json.dumps(attachment))); original=Path.read_text
        def raced_read(path,*args,**kwargs):
            return next(reads) if path == self.s.attachment else original(path,*args,**kwargs)
        with patch.object(Path,"read_text",autospec=True,side_effect=raced_read):
            raced=read_locked_authority(self.s,"T")
        self.assert_closed(raced); self.assertEqual(raced["failure_reason"],"AUTHORITY_INVALID")

        c=self.s.connect(); c.execute("update meta set v='false' where k='available'"); c.commit(); c.close()
        invalid=read_locked_authority(self.s,"T")
        self.assert_closed(invalid); self.assertEqual(invalid["failure_reason"],"AUTHORITY_INVALID")

    def test_schema_invalid_authority_and_malformed_meta_deny(self):
        self.tmp.cleanup(); self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.s=Scheduler(ROOT,Path(self.tmp.name)/"runtime"); self.s.initialize(project_id=""); self.s.create_task("T","receipt")
        project=read_locked_authority(self.s,"T")
        self.assert_closed(project); self.assertEqual(project["failure_reason"],"AUTHORITY_INVALID")

        self.tmp.cleanup(); self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.s=Scheduler(ROOT,Path(self.tmp.name)/"runtime"); self.s.initialize(); self.s.create_task("T","receipt")
        self.s.transition("CLAIM","T",{**self.req(),"actor":"worker"},operation_key="claim")
        c=self.s.connect(); c.execute("update claims set actor='' where task_id='T'"); c.commit(); c.close()
        actor=read_locked_authority(self.s,"T")
        self.assert_closed(actor); self.assertEqual(actor["failure_reason"],"AUTHORITY_INVALID")

        for value in (None,"not-json"):
            self.tmp.cleanup(); self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
            self.s=Scheduler(ROOT,Path(self.tmp.name)/"runtime"); self.s.initialize(); self.s.create_task("T","receipt")
            c=self.s.connect()
            if value is None: c.execute("delete from meta where k='available'")
            else: c.execute("update meta set v=? where k='available'",(value,))
            c.commit(); c.close()
            meta=read_locked_authority(self.s,"T")
            self.assert_closed(meta); self.assertEqual(meta["failure_reason"],"AUTHORITY_INVALID")

    def test_claim_fence_inconsistency_denies(self):
        self.s.transition("CLAIM","T",{**self.req(),"actor":"worker"},operation_key="claim")
        c=self.s.connect(); c.execute("update claims set fence=fence+1 where task_id='T'"); c.commit(); c.close()
        result=read_locked_authority(self.s,"T")
        self.assert_closed(result); self.assertEqual(result["failure_reason"],"AUTHORITY_INVALID")

    def test_claim_actor_attempt_and_review_inconsistency_deny(self):
        self.s.transition("CLAIM","T",{**self.req(),"actor":"worker"},operation_key="claim")
        c=self.s.connect(); c.execute("update claims set actor='other' where task_id='T'"); c.commit(); c.close()
        actor=read_locked_authority(self.s,"T")
        self.assert_closed(actor); self.assertEqual(actor["failure_reason"],"AUTHORITY_INVALID")

        self.tmp.cleanup(); self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.s=Scheduler(ROOT,Path(self.tmp.name)/"runtime"); self.s.initialize(); self.s.create_task("T","receipt")
        c=self.s.connect(); c.execute("delete from attempts where task_id='T'"); c.commit(); c.close()
        attempt=read_locked_authority(self.s,"T")
        self.assert_closed(attempt); self.assertEqual(attempt["failure_reason"],"AUTHORITY_INVALID")

        self.tmp.cleanup(); self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.s=Scheduler(ROOT,Path(self.tmp.name)/"runtime"); self.s.initialize(); self.s.create_task("T","receipt")
        claimed=self.s.transition("CLAIM","T",{**self.req(),"actor":"worker"},operation_key="claim")["tuple"]
        self.s.transition("START","T",{**self.req(),"claim_id":claimed["active_claim_id"],"fence":claimed["task_fence"]},operation_key="start")
        current=self.req(); self.s.transition("COMPLETE","T",{**current,"claim_id":current["expected"]["active_claim_id"],"fence":current["expected"]["task_fence"]},operation_key="complete")
        self.s.transition("ASSIGN_REVIEW","T",{**self.req(),"actor":"reviewer","role":"skeptic"},operation_key="review")
        c=self.s.connect(); c.execute("delete from reviews where task_id='T'"); c.commit(); c.close()
        review=read_locked_authority(self.s,"T")
        self.assert_closed(review); self.assertEqual(review["failure_reason"],"AUTHORITY_INVALID")

    def test_governance_block_fences_auxiliary_rows_and_remains_readable(self):
        self.s.transition("CLAIM","T",{**self.req(),"actor":"worker"},operation_key="claim")
        self.s.transition("GOVERNANCE_BLOCK","T",self.req(),operation_key="block")
        blocked=read_locked_authority(self.s,"T")
        self.assert_closed(blocked); self.assertEqual(blocked["observation_status"],"COHERENT_DENY_ONLY")
        c=self.s.connect(read_only=True); self.assertEqual(c.execute("select status from claims where task_id='T'").fetchone()[0],"GOVERNANCE_BLOCKED"); c.close()

        self.tmp.cleanup(); self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.s=Scheduler(ROOT,Path(self.tmp.name)/"runtime"); self.s.initialize(); self.s.create_task("T","receipt")
        claimed=self.s.transition("CLAIM","T",{**self.req(),"actor":"worker"},operation_key="claim")["tuple"]
        self.s.transition("START","T",{**self.req(),"claim_id":claimed["active_claim_id"],"fence":claimed["task_fence"]},operation_key="start")
        current=self.req(); self.s.transition("COMPLETE","T",{**current,"claim_id":current["expected"]["active_claim_id"],"fence":current["expected"]["task_fence"]},operation_key="complete")
        self.s.transition("ASSIGN_REVIEW","T",{**self.req(),"actor":"reviewer","role":"skeptic"},operation_key="review")
        self.s.transition("GOVERNANCE_BLOCK","T",self.req(),operation_key="block")
        review_blocked=read_locked_authority(self.s,"T")
        self.assert_closed(review_blocked); self.assertEqual(review_blocked["observation_status"],"COHERENT_DENY_ONLY")
        c=self.s.connect(read_only=True); self.assertEqual(c.execute("select status from reviews where task_id='T'").fetchone()[0],"GOVERNANCE_BLOCKED"); c.close()

    def test_repository_import_fences_active_claim_and_remains_readable(self):
        self.s.transition("CLAIM","T",{**self.req(),"actor":"worker"},operation_key="claim")
        original=self.s.bundle(); changed=Bundle(original.commit,"d"*64,original.project,original.stops,original.policy,original.tasks)
        with patch.object(self.s,"bundle",return_value=changed):
            self.s.import_repository(["T"])
            result=read_locked_authority(self.s,"T")
        self.assert_closed(result); self.assertEqual(result["observation_status"],"COHERENT_DENY_ONLY")
        c=self.s.connect(read_only=True); self.assertEqual(c.execute("select status from claims where task_id='T'").fetchone()[0],"GOVERNANCE_BLOCKED"); c.close()


class AuthorityBindingTests(unittest.TestCase):
    capture_id="AUTH-AUTHENTIC-STAGE1-DISPATCH"
    task_id="T-SYNTHETIC-001"

    @classmethod
    def setUpClass(cls):
        cls.historical=authority_binding.verify_authentic_history(ROOT/"tests/fixtures/authentic-stage1/dispatch")
        if cls.historical["status"]!="HISTORICALLY_VALID": raise RuntimeError("historical test fixture unavailable")

    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.s=Scheduler(ROOT,Path(self.tmp.name)/"runtime"); self.s.initialize(); self.s.create_task(self.task_id,"untrusted-receipt")
        self.seal_schema=json.loads((ROOT/"schemas/m0-3a-historical-decision-seal.v1.schema.json").read_text())
        self.candidate_schema=json.loads((ROOT/"schemas/m0-3a-authority-binding-candidate.v1.schema.json").read_text())
        self.v3=json.loads((ROOT/"schemas/m0-2-decision-evidence-verification-result.v3.schema.json").read_text())

    def assert_candidate(self,result):
        resolver=RefResolver(
            (ROOT/"schemas").as_uri()+"/",
            self.candidate_schema,
            store={self.seal_schema["$id"]:self.seal_schema},
        )
        Draft202012Validator(self.candidate_schema,resolver=resolver).validate(result)
        Draft202012Validator(self.v3).validate(result["verification"])
        self.assertTrue(verify_binding_integrity(result))
        self.assertEqual(result["verification"]["authorizing_use"],"DENY")
        self.assertNotEqual(result["verification"]["currentness_status"],"CURRENT")
        self.assertEqual(result["candidate_sha256"],digest({key:value for key,value in result.items() if key!="candidate_sha256"}))
        if result["historical_seal"] is not None:
            seal=result["historical_seal"]
            Draft202012Validator(self.seal_schema).validate(seal)
            self.assertEqual(seal["seal_sha256"],digest({key:value for key,value in seal.items() if key!="seal_sha256"}))

    def runtime_state(self):
        c=self.s.connect(read_only=True)
        try: dump="\n".join(c.iterdump())
        finally: c.close()
        files={path.name:digest(path.read_bytes()) for path in self.s.dir.iterdir() if path.is_file()}
        return dump,files

    def test_real_historical_dispatch_binds_but_remains_deny_only_and_read_only(self):
        before=self.runtime_state(); result=compose_authority_binding(self.s,self.task_id,self.capture_id); after=self.runtime_state()
        self.assert_candidate(result)
        self.assertEqual(result["status"],"BOUND_DENY_ONLY")
        self.assertEqual(result["evidence_class"],"R_GATE_CANDIDATE_EVIDENCE")
        self.assertEqual(result["attempt"],1)
        self.assertEqual(result["historical_seal"]["subject"],{"attempt":1,"task_id":self.task_id})
        self.assertEqual(result["historical_seal"]["decision"]["operation"],"SYNTHETIC_ASSERT")
        self.assertEqual(before,after)

    def test_historical_deny_is_non_authorizing_evidence(self):
        deny=authority_binding.verify_authentic_history(ROOT/"tests/fixtures/authentic-stage1/deny")
        with patch.object(authority_binding,"verify_authentic_history",return_value=deny):
            result=compose_authority_binding(self.s,self.task_id,"AUTH-AUTHENTIC-STAGE1-DENY")
        self.assert_candidate(result)
        self.assertEqual((result["status"],result["evidence_class"]),("BOUND_DENY_ONLY","NON_AUTHORIZING_EVIDENCE"))
        self.assertIsNone(result["historical_seal"]["decision"].get("operation"))

    def test_api_has_no_caller_source_receipt_or_snapshot_inputs(self):
        self.assertEqual(tuple(inspect.signature(compose_authority_binding).parameters),("scheduler","task_id","capture_id"))
        with self.assertRaises(TypeError): compose_authority_binding(self.s,self.task_id,self.capture_id,snapshot={})
        for task,capture,reason in (("",self.capture_id,"INPUT_INVALID"),(self.task_id,"","INPUT_INVALID"),(self.task_id,"UNKNOWN","CAPTURE_UNKNOWN")):
            with self.subTest(task=task,capture=capture):
                result=compose_authority_binding(self.s,task,capture); self.assert_candidate(result); self.assertEqual(result["failure_reason"],reason)

    def test_subject_attempt_and_runtime_mismatch_fail_closed(self):
        with patch.object(authority_binding,"verify_authentic_history",return_value=self.historical):
            unknown=compose_authority_binding(self.s,"OTHER",self.capture_id)
        self.assert_candidate(unknown); self.assertEqual(unknown["failure_reason"],"RUNTIME_UNAVAILABLE")

        claimed=self.s.transition("CLAIM",self.task_id,{"expected":self.s.tuple(self._row()),"repository_generation":0,"receipt_digest":"untrusted-receipt","actor":"worker"},operation_key="claim")["tuple"]
        self.s.transition("FAIL",self.task_id,{"expected":self.s.tuple(self._row()),"repository_generation":0,"receipt_digest":"untrusted-receipt","claim_id":claimed["active_claim_id"],"fence":claimed["task_fence"]},operation_key="fail")
        self.s.transition("RETRY",self.task_id,{"expected":self.s.tuple(self._row()),"repository_generation":0,"receipt_digest":"untrusted-receipt","retryable":True},operation_key="retry")
        with patch.object(authority_binding,"verify_authentic_history",return_value=self.historical):
            attempt=compose_authority_binding(self.s,self.task_id,self.capture_id)
        self.assert_candidate(attempt); self.assertEqual(attempt["failure_reason"],"SUBJECT_MISMATCH")

    def _row(self):
        c=self.s.connect(read_only=True); row=c.execute("select * from tasks where task_id=?",(self.task_id,)).fetchone(); c.close(); return row

    def test_source_and_runtime_races_fail_closed(self):
        original_sources=authority_binding._source_bytes; calls=0
        def raced_sources(root,fixture=None):
            nonlocal calls
            calls+=1; value=original_sources(root,fixture)
            if calls==3: value={**value,"sidecar":value["sidecar"]+b"race"}
            return value
        with patch.object(authority_binding,"verify_authentic_history",return_value=self.historical), patch.object(authority_binding,"_source_bytes",side_effect=raced_sources):
            source=compose_authority_binding(self.s,self.task_id,self.capture_id)
        self.assert_candidate(source); self.assertEqual(source["failure_reason"],"RACE_DETECTED")

        actual=read_locked_authority(self.s,self.task_id); calls=0
        def raced_authority(*args):
            nonlocal calls
            calls+=1; value=json.loads(json.dumps(actual))
            if calls==2: value["authority_sha256"]="f"*64
            return value
        with patch.object(authority_binding,"verify_authentic_history",return_value=self.historical), patch.object(authority_binding,"read_locked_authority",side_effect=raced_authority):
            runtime=compose_authority_binding(self.s,self.task_id,self.capture_id)
        self.assert_candidate(runtime); self.assertEqual(runtime["failure_reason"],"RACE_DETECTED")

    def test_invalid_history_and_positive_tampering_fail_closed(self):
        invalid={**self.historical,"status":"INVALID","authorization_result":{**self.historical["authorization_result"],"historical_status":"INVALID","runtime_compatible":False,"reason_code":"HISTORICAL_INVALID"}}
        with patch.object(authority_binding,"verify_authentic_history",return_value=invalid):
            result=compose_authority_binding(self.s,self.task_id,self.capture_id)
        self.assert_candidate(result); self.assertEqual(result["failure_reason"],"HISTORICAL_INVALID")

        with patch.object(authority_binding,"verify_authentic_history",return_value=self.historical):
            bound=compose_authority_binding(self.s,self.task_id,self.capture_id)
        bound["verification"].update({"currentness_status":"CURRENT","verifier_status":"PASS","generation_match":True,"authorizing_use":"ALLOW","reason_code":"NONE"})
        resolver=RefResolver((ROOT/"schemas").as_uri()+"/",self.candidate_schema,store={self.seal_schema["$id"]:self.seal_schema})
        with self.assertRaises(Exception): Draft202012Validator(self.candidate_schema,resolver=resolver).validate(bound)

        with patch.object(authority_binding,"verify_authentic_history",return_value=self.historical):
            bound=compose_authority_binding(self.s,self.task_id,self.capture_id)
        bound["evidence_class"]="NON_AUTHORIZING_EVIDENCE"
        with self.assertRaises(Exception): Draft202012Validator(self.candidate_schema,resolver=resolver).validate(bound)

        unavailable=compose_authority_binding(self.s,"UNKNOWN",self.capture_id)
        unavailable["attempt"]=1
        with self.assertRaises(Exception): Draft202012Validator(self.candidate_schema,resolver=resolver).validate(unavailable)

    def test_source_pins_canonical_root_and_semantic_verifier_deny_substitution(self):
        original=authority_binding._source_bytes
        def substituted(root,fixture=None):
            value=original(root,fixture)
            return {**value,"mapping":b"not the mapping contract\n"}
        with patch.object(authority_binding,"_source_bytes",side_effect=substituted):
            result=compose_authority_binding(self.s,self.task_id,self.capture_id)
        self.assert_candidate(result); self.assertEqual(result["failure_reason"],"SOURCE_INVALID")

        original_load=authority_binding.load_trust
        def substituted_capture_root(*args,**kwargs):
            trust,capture_root=original_load(*args,**kwargs)
            capture_root=json.loads(json.dumps(capture_root)); capture_root["root_sha256"]="f"*64
            return trust,capture_root
        with patch.object(authority_binding,"load_trust",side_effect=substituted_capture_root):
            result=compose_authority_binding(self.s,self.task_id,self.capture_id)
        self.assert_candidate(result); self.assertEqual(result["failure_reason"],"SOURCE_INVALID")

        alternate=Scheduler(Path(self.tmp.name)/"alternate-root",Path(self.tmp.name)/"alternate-runtime")
        result=compose_authority_binding(alternate,self.task_id,self.capture_id)
        self.assert_candidate(result); self.assertEqual(result["failure_reason"],"SOURCE_INVALID")

        with patch.object(authority_binding,"verify_authentic_history",return_value=self.historical):
            bound=compose_authority_binding(self.s,self.task_id,self.capture_id)
        attacks=(
            lambda r: r.update(task_id="OTHER"),
            lambda r: r["historical_seal"]["subject"].update(attempt=2),
            lambda r: r["historical_seal"]["historical_verification"].update(decision_id="D-"+"f"*32),
            lambda r: r["historical_seal"].update(raw_result_sha256="f"*64),
            lambda r: r.update(candidate_sha256="f"*64),
        )
        for attack in attacks:
            forged=json.loads(json.dumps(bound)); attack(forged)
            with self.subTest(attack=attack): self.assertFalse(verify_binding_integrity(forged))

if __name__ == "__main__": unittest.main()
