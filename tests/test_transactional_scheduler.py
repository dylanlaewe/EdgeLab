"""M0.3A synthetic runtime acceptance: no workers, network, executor, or capital."""
from __future__ import annotations
import inspect
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator

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
    def test_cooperative_lock_contention_denies_without_mutation(self):
        with self.s.locked("holder"):
            with self.assertRaisesRegex(RuntimeUnavailable,"lock held"):
                with self.s.locked("second"): pass
        self.s.startup()


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
        self.s.transition("CLAIM","T",{**self.req(),"actor":""},operation_key="claim")
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
        self.assert_closed(result); self.assertEqual(result["failure_reason"],"CLAIM_INCONSISTENT")

    def test_claim_actor_attempt_and_review_inconsistency_deny(self):
        self.s.transition("CLAIM","T",{**self.req(),"actor":"worker"},operation_key="claim")
        c=self.s.connect(); c.execute("update claims set actor='other' where task_id='T'"); c.commit(); c.close()
        actor=read_locked_authority(self.s,"T")
        self.assert_closed(actor); self.assertEqual(actor["failure_reason"],"CLAIM_INCONSISTENT")

        self.tmp.cleanup(); self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.s=Scheduler(ROOT,Path(self.tmp.name)/"runtime"); self.s.initialize(); self.s.create_task("T","receipt")
        c=self.s.connect(); c.execute("delete from attempts where task_id='T'"); c.commit(); c.close()
        attempt=read_locked_authority(self.s,"T")
        self.assert_closed(attempt); self.assertEqual(attempt["failure_reason"],"ATTEMPT_INCONSISTENT")

        self.tmp.cleanup(); self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.s=Scheduler(ROOT,Path(self.tmp.name)/"runtime"); self.s.initialize(); self.s.create_task("T","receipt")
        claimed=self.s.transition("CLAIM","T",{**self.req(),"actor":"worker"},operation_key="claim")["tuple"]
        self.s.transition("START","T",{**self.req(),"claim_id":claimed["active_claim_id"],"fence":claimed["task_fence"]},operation_key="start")
        current=self.req(); self.s.transition("COMPLETE","T",{**current,"claim_id":current["expected"]["active_claim_id"],"fence":current["expected"]["task_fence"]},operation_key="complete")
        self.s.transition("ASSIGN_REVIEW","T",{**self.req(),"actor":"reviewer","role":"skeptic"},operation_key="review")
        c=self.s.connect(); c.execute("delete from reviews where task_id='T'"); c.commit(); c.close()
        review=read_locked_authority(self.s,"T")
        self.assert_closed(review); self.assertEqual(review["failure_reason"],"REVIEW_INCONSISTENT")

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

if __name__ == "__main__": unittest.main()
