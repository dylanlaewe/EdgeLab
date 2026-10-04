"""M0.3A local-only, synthetic SQLite scheduler.  It is never an executor."""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import sqlite3
import subprocess
import tempfile
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from .orchestration import EXPECTED_REMOTE

SCHEMA_VERSION = 1
FREEZE = "bc3a40924ca580ca6eddc4c24e32ff99ddd95330"
VALID = {("ACTIVE","CLAIMABLE","NOT_REQUIRED"), ("ACTIVE","CLAIMED","NOT_REQUIRED"),
         ("ACTIVE","IN_PROGRESS","NOT_REQUIRED"), ("ACTIVE","FAILED","NOT_REQUIRED"),
         ("ACTIVE","EXECUTION_COMPLETED","REVIEW_PENDING"), ("ACTIVE","EXECUTION_COMPLETED","REVIEWING"),
         ("ACTIVE","EXECUTION_COMPLETED","REJECTED"), ("ACTIVE","EXECUTION_COMPLETED","REMEDIATION_REQUIRED"),
         ("ACTIVE","EXECUTION_COMPLETED","APPROVED"), ("DIRECTOR_GATE_READY","EXECUTION_COMPLETED","APPROVED"),
         ("GOVERNANCE_BLOCKED","EXECUTION_BLOCKED","NOT_REQUIRED"), ("GOVERNANCE_BLOCKED","EXECUTION_BLOCKED","REVIEW_PENDING"),
         ("CLOSED","EXECUTION_COMPLETED","NOT_REQUIRED"), ("CANCELLED","EXECUTION_BLOCKED","NOT_REQUIRED"),
         ("CANCELLED","EXECUTION_BLOCKED","REVIEW_PENDING"), ("SUPERSEDED","EXECUTION_BLOCKED","NOT_REQUIRED"), ("SUPERSEDED","EXECUTION_BLOCKED","REVIEW_PENDING")}

def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()
def digest(value: Any) -> str: return hashlib.sha256(canonical(value) if not isinstance(value, bytes) else value).hexdigest()
def utc() -> str: return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
def _mode(path: Path, wanted: int) -> None:
    try: os.chmod(path, wanted)
    except OSError as error: raise RuntimeError("runtime permissions unavailable") from error
    if os.stat(path).st_mode & 0o777 != wanted: raise RuntimeError("unsafe runtime permissions")

@dataclass(frozen=True)
class Bundle:
    commit: str; digest: str; project: str; stops: str; policy: str; tasks: str

class RuntimeUnavailable(RuntimeError): pass

class Scheduler:
    """All mutating calls lock, use BEGIN IMMEDIATE, and preserve event/state atomicity."""
    def __init__(self, root: Path, runtime_dir: Path):
        self.root, self.dir = root.resolve(), runtime_dir.resolve()
        self.db, self.attachment, self.lock_path = self.dir / "runtime.sqlite", self.dir / "attachment.json", self.dir / "scheduler.lock"

    def _git(self, *args: str) -> str:
        p = subprocess.run(["git", "-C", str(self.root), *args], text=True, capture_output=True, check=False)
        if p.returncode: raise RuntimeUnavailable("Git binding unavailable")
        return p.stdout.strip()
    def bundle(self) -> Bundle:
        if self._git("remote", "get-url", "origin") != EXPECTED_REMOTE: raise RuntimeUnavailable("wrong repository")
        commit = self._git("rev-parse", "HEAD")
        selected = ["docs/project-state.json", *sorted(str(x.relative_to(self.root)) for x in (self.root/"reports/stops").glob("*.json")), *sorted(str(x.relative_to(self.root)) for x in (self.root/"orchestration").rglob("*.json")), *sorted(str(x.relative_to(self.root)) for x in (self.root/"portfolio").glob("*.json"))]
        pairs = [(p, hashlib.sha256((self.root/p).read_bytes()).hexdigest()) for p in selected]
        groups = lambda prefix: digest([x for x in pairs if x[0].startswith(prefix)])
        # A source commit is recorded with every binding, but only authoritative
        # path content advances generation; a no-op commit must not fence work.
        return Bundle(commit, digest({"files":pairs}), groups("docs/project-state"), groups("reports/stops"), digest([x for x in pairs if x[0].startswith("portfolio/") or x[0].startswith("orchestration/capabilities")]), groups("orchestration/"))
    @contextmanager
    def locked(self, purpose: str) -> Iterator[None]:
        self.dir.mkdir(mode=0o700, parents=True, exist_ok=True); _mode(self.dir, 0o700)
        f = open(self.lock_path, "a+", encoding="utf-8"); _mode(self.lock_path, 0o600)
        try:
            try: fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as e: raise RuntimeUnavailable("cooperative lock held") from e
            yield
        finally:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN); f.close()
    def connect(self) -> sqlite3.Connection:
        c = sqlite3.connect(self.db, isolation_level=None); c.row_factory = sqlite3.Row
        try:
            if c.execute("PRAGMA journal_mode=WAL").fetchone()[0].lower() != "wal": raise RuntimeUnavailable("WAL unavailable")
            c.execute("PRAGMA synchronous=FULL")
            c.execute("PRAGMA foreign_keys=ON"); c.execute("PRAGMA busy_timeout=5000")
            if c.execute("PRAGMA foreign_keys").fetchone()[0] != 1 or c.execute("PRAGMA synchronous").fetchone()[0] != 2 or c.execute("PRAGMA busy_timeout").fetchone()[0] != 5000: raise RuntimeUnavailable("SQLite profile unavailable")
            return c
        except Exception: c.close(); raise
    def initialize(self, project_id: str = "EdgeLab") -> None:
        with self.locked("initialize"):
            if self.db.exists() or self.attachment.exists(): raise RuntimeUnavailable("runtime already initialized or incomplete")
            b = self.bundle(); nonce = uuid.uuid4().hex
            att = {"attachment_schema_version":1,"attachment_id":str(uuid.uuid4()),"canonical_project_id":project_id,"repository_identity":self._git("rev-parse","--show-toplevel"),"expected_remote":EXPECTED_REMOTE,"repository_marker_digest":digest({"remote":EXPECTED_REMOTE,"common":self._git("rev-parse","--git-common-dir")}),"m0_2_freeze_commit":FREEZE,"checkout_realpath":str(self.root),"git_common_dir_identity":self._git("rev-parse","--git-common-dir"),"checkout_local_nonce":nonce,"created_at":utc()}
            self.attachment.write_bytes(canonical(att)); _mode(self.attachment,0o600); ad=digest(att)
            c=self.connect()
            try:
                c.execute("BEGIN EXCLUSIVE"); self._schema(c)
                runtime_id=str(uuid.uuid4()); genesis={"runtime_schema_version":SCHEMA_VERSION,"runtime_id":runtime_id,"attachment_id":att["attachment_id"],"attachment_digest":ad,"source_git_commit":b.commit,"m0_2_freeze_commit":FREEZE,"project_state_digest":b.project,"complete_stop_set_digest":b.stops,"policy_capability_bundle_digest":b.policy,"task_dependency_assignment_handoff_digest":b.tasks,"initial_repository_generation":0,"initial_scheduler_generation":0,"global_sequence":0,"predecessor_id":"GENESIS","predecessor_digest":hashlib.sha256(b"GENESIS").hexdigest(),"created_at":utc()}; gd=digest(genesis)
                for k,v in {"schema_version":1,"runtime_id":runtime_id,"genesis":genesis,"genesis_digest":gd,"attachment_digest":ad,"repository_generation":0,"bundle_digest":b.digest,"global_head_id":"GENESIS","global_head_digest":genesis["predecessor_digest"],"available":True}.items(): c.execute("INSERT INTO meta VALUES (?,?)",(k,json.dumps(v)))
                seal={"runtime_id":runtime_id,"attachment_id":att["attachment_id"],"attachment_digest":ad,"genesis_digest":gd,"created_at":utc()}; seal["seal_digest"]=digest(seal); c.execute("INSERT INTO seals VALUES (?,?,?,?,?,?)",tuple(seal[k] for k in ("runtime_id","attachment_id","attachment_digest","genesis_digest","created_at","seal_digest")))
                self._runtime_event(c,"GENESIS",{},b); c.commit()
            except Exception: c.rollback(); raise
            finally: c.close()
    def _schema(self,c:sqlite3.Connection)->None:
        c.executescript("""CREATE TABLE meta(k TEXT PRIMARY KEY,v TEXT NOT NULL); CREATE TABLE seals(runtime_id TEXT PRIMARY KEY,attachment_id TEXT,attachment_digest TEXT,genesis_digest TEXT,created_at TEXT,seal_digest TEXT); CREATE TABLE tasks(task_id TEXT PRIMARY KEY,attempt INTEGER,workflow TEXT,execution TEXT,review TEXT,scheduler_generation INTEGER,dispatch_generation INTEGER,task_fence INTEGER,claim_id TEXT,reviewer_id TEXT,continuations INTEGER,repository_generation INTEGER,receipt_digest TEXT,owner TEXT,reviewer TEXT,predecessor_task TEXT,successor_task TEXT); CREATE TABLE attempts(task_id TEXT,attempt INTEGER,predecessor_attempt INTEGER,PRIMARY KEY(task_id,attempt)); CREATE TABLE claims(claim_id TEXT PRIMARY KEY,task_id TEXT,attempt INTEGER,fence INTEGER,status TEXT,actor TEXT); CREATE TABLE reviews(assignment_id TEXT PRIMARY KEY,task_id TEXT,actor TEXT,role TEXT,status TEXT); CREATE TABLE idempotency(operation_key TEXT PRIMARY KEY,request_digest TEXT NOT NULL,response TEXT NOT NULL); CREATE TABLE runtime_events(event_id TEXT PRIMARY KEY,global_seq INTEGER UNIQUE,event_type TEXT,payload TEXT,event_digest TEXT,prev_id TEXT,prev_digest TEXT); CREATE TABLE task_events(event_id TEXT PRIMARY KEY,task_id TEXT,attempt INTEGER,task_seq INTEGER,global_seq INTEGER UNIQUE,event_type TEXT,before_json TEXT,after_json TEXT,payload TEXT,event_digest TEXT,prev_task_digest TEXT,prev_global_digest TEXT); CREATE TABLE remediation_links(link_id TEXT PRIMARY KEY,source_task TEXT,child_task TEXT,source_event TEXT,child_event TEXT,decision_digest TEXT,link_digest TEXT); CREATE TABLE migration_ledger(migration_id TEXT PRIMARY KEY,from_version INTEGER,to_version INTEGER,artifact_digest TEXT,backup_ref TEXT,backup_digest TEXT,result TEXT,created_at TEXT); CREATE TABLE snapshots(snapshot_id TEXT PRIMARY KEY,digest TEXT,generation INTEGER,global_head TEXT,created_at TEXT);""")
    def _meta(self,c,k): return json.loads(c.execute("SELECT v FROM meta WHERE k=?",(k,)).fetchone()[0])
    def _set(self,c,k,v): c.execute("UPDATE meta SET v=? WHERE k=?",(json.dumps(v),k))
    def _verify(self,c):
        if not self.attachment.exists(): raise RuntimeUnavailable("attachment missing")
        _mode(self.dir,0o700); _mode(self.attachment,0o600); _mode(self.db,0o600)
        if c.execute("PRAGMA integrity_check").fetchone()[0] != "ok" or c.execute("PRAGMA foreign_key_check").fetchall(): raise RuntimeUnavailable("SQLite corruption")
        a=json.loads(self.attachment.read_text()); g=self._meta(c,"genesis"); seal=c.execute("SELECT * FROM seals").fetchone()
        if digest(a)!=self._meta(c,"attachment_digest") or digest(g)!=self._meta(c,"genesis_digest") or not seal or seal[2]!=digest(a) or seal[3]!=digest(g) or a["checkout_realpath"]!=str(self.root) or a["expected_remote"]!=EXPECTED_REMOTE: raise RuntimeUnavailable("attachment/genesis seal mismatch")
        self.replay(c)
    def startup(self):
        with self.locked("startup"):
            if not self.db.exists(): raise RuntimeUnavailable("database missing")
            c=self.connect()
            try: self._verify(c)
            finally: c.close()
    def _runtime_event(self,c,typ,payload,b):
        n=c.execute("SELECT COALESCE(MAX(global_seq),-1)+1 FROM (SELECT global_seq FROM runtime_events UNION ALL SELECT global_seq FROM task_events)").fetchone()[0]; prev=self._meta(c,"global_head_digest"); eid=str(uuid.uuid4()); body={"id":eid,"seq":n,"type":typ,"payload":payload,"prev":prev}; ed=digest(body); c.execute("INSERT INTO runtime_events VALUES (?,?,?,?,?,?,?)",(eid,n,typ,json.dumps(payload),ed,self._meta(c,"global_head_id"),prev)); self._set(c,"global_head_id",eid); self._set(c,"global_head_digest",ed)
    def _task_event(self,c,row,before,after,typ,payload):
        n=c.execute("SELECT COALESCE(MAX(global_seq),-1)+1 FROM (SELECT global_seq FROM runtime_events UNION ALL SELECT global_seq FROM task_events)").fetchone()[0]; seq=c.execute("SELECT COALESCE(MAX(task_seq),0)+1 FROM task_events WHERE task_id=?",(row["task_id"],)).fetchone()[0]; prev=c.execute("SELECT event_digest FROM task_events WHERE task_id=? ORDER BY task_seq DESC LIMIT 1",(row["task_id"],)).fetchone(); pd=prev[0] if prev else digest("TASK_GENESIS:"+row["task_id"]); eid=str(uuid.uuid4()); body={"id":eid,"n":n,"seq":seq,"type":typ,"before":before,"after":after,"payload":payload,"prev":pd}; ed=digest(body); c.execute("INSERT INTO task_events VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",(eid,row["task_id"],row["attempt"],seq,n,typ,json.dumps(before),json.dumps(after),json.dumps(payload),ed,pd,self._meta(c,"global_head_digest"))); self._set(c,"global_head_id",eid); self._set(c,"global_head_digest",ed); return eid

    @staticmethod
    def tuple(row: sqlite3.Row) -> dict[str, Any]:
        return {"workflow":row["workflow"],"execution":row["execution"],"review":row["review"],"attempt_no":row["attempt"],"scheduler_generation":row["scheduler_generation"],"dispatch_generation":row["dispatch_generation"],"task_fence":row["task_fence"],"active_claim_id":row["claim_id"],"reviewer_assignment_id":row["reviewer_id"],"continuation_count":row["continuations"],"repository_generation":row["repository_generation"],"decision_receipt_digest":row["receipt_digest"]}

    def create_task(self, task_id: str, receipt_digest: str, owner: str="synthetic-owner") -> dict[str, Any]:
        return self.transition("INITIALIZE", task_id, {"receipt_digest":receipt_digest,"owner":owner}, operation_key="init-"+task_id)

    def transition(self, op: str, task_id: str, request: dict[str, Any], *, operation_key: str, inject: str|None=None) -> dict[str, Any]:
        body={"operation":op,"task_id":task_id,"request":request}; rd=digest(body)
        with self.locked(op):
            b=self.bundle(); c=self.connect()
            try:
                c.execute("BEGIN IMMEDIATE"); self._verify(c)
                hit=c.execute("SELECT request_digest,response FROM idempotency WHERE operation_key=?",(operation_key,)).fetchone()
                if hit:
                    if hit["request_digest"] != rd: raise RuntimeUnavailable("idempotency key reused with different request")
                    c.rollback(); return json.loads(hit["response"])
                if inject=="before_event": raise RuntimeError("injected before event")
                if op=="INITIALIZE":
                    if c.execute("SELECT 1 FROM tasks WHERE task_id=?",(task_id,)).fetchone(): raise RuntimeUnavailable("task exists")
                    c.execute("INSERT INTO tasks VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(task_id,1,"ACTIVE","CLAIMABLE","NOT_REQUIRED",0,0,0,None,None,0,self._meta(c,"repository_generation"),request["receipt_digest"],request["owner"],None,None,None)); c.execute("INSERT INTO attempts VALUES (?,?,?)",(task_id,1,None)); event="TASK_INITIALIZED"; before=None
                else:
                    row=c.execute("SELECT * FROM tasks WHERE task_id=?",(task_id,)).fetchone()
                    if not row: raise RuntimeUnavailable("unknown task")
                    if request.get("expected") != self.tuple(row): raise RuntimeUnavailable("stale tuple")
                    if request.get("repository_generation") != self._meta(c,"repository_generation") or request.get("receipt_digest") != row["receipt_digest"]: raise RuntimeUnavailable("stale repository or M0.2 receipt")
                    before=self.tuple(row); event=self._apply(c,row,op,request)
                row=c.execute("SELECT * FROM tasks WHERE task_id=?",(task_id,)).fetchone(); after=self.tuple(row); self._task_event(c,row,before,after,event,{"request":body,"bundle":b.digest})
                if inject in {"after_event","after_state"}: raise RuntimeError("injected before idempotency")
                response={"task_id":task_id,"operation":op,"tuple":after,"event":event,"global_head":self._meta(c,"global_head_id")}; c.execute("INSERT INTO idempotency VALUES (?,?,?)",(operation_key,rd,json.dumps(response)))
                if inject=="after_idempotency": raise RuntimeError("injected before commit")
                if self.bundle() != b: raise RuntimeUnavailable("authoritative Git bundle changed before commit")
                c.commit()
                if inject=="after_commit": raise ConnectionError("lost response after commit")
                return response
            except Exception:
                if c.in_transaction: c.rollback()
                raise
            finally: c.close()

    def _apply(self,c,row,op,r):
        w,e,v=row["workflow"],row["execution"],row["review"]; S=row["scheduler_generation"]+1; D=row["dispatch_generation"]; F=row["task_fence"]
        def setstate(**k):
            now={x:row[x] for x in row.keys()}; now.update(k); c.execute("UPDATE tasks SET workflow=?,execution=?,review=?,scheduler_generation=?,dispatch_generation=?,task_fence=?,claim_id=?,reviewer_id=?,continuations=?,repository_generation=?,successor_task=? WHERE task_id=?",(now["workflow"],now["execution"],now["review"],now["scheduler_generation"],now["dispatch_generation"],now["task_fence"],now["claim_id"],now["reviewer_id"],now["continuations"],now["repository_generation"],now["successor_task"],row["task_id"]))
        if op=="CLAIM" and (w,e,v)==("ACTIVE","CLAIMABLE","NOT_REQUIRED"):
            cid=str(uuid.uuid4()); setstate(execution="CLAIMED",scheduler_generation=S,dispatch_generation=D+1,task_fence=F+1,claim_id=cid); c.execute("INSERT INTO claims VALUES (?,?,?,?,?,?)",(cid,row["task_id"],row["attempt"],F+1,"ACTIVE",r["actor"])); return "CLAIM_ISSUED"
        if op in {"START","CONTINUE","YIELD","FAIL","COMPLETE"}:
            if r.get("claim_id")!=row["claim_id"] or r.get("fence")!=F: raise RuntimeUnavailable("stale worker fence")
            if op=="START" and e=="CLAIMED": setstate(execution="IN_PROGRESS",scheduler_generation=S); return "TASK_STARTED"
            if op=="CONTINUE" and e=="IN_PROGRESS": setstate(scheduler_generation=S,continuations=row["continuations"]+1); return "TASK_CONTINUED"
            if op in {"YIELD","FAIL","COMPLETE"} and e in {"CLAIMED","IN_PROGRESS"}:
                execution="CLAIMABLE" if op=="YIELD" else "FAILED" if op=="FAIL" else "EXECUTION_COMPLETED"; review="REVIEW_PENDING" if op=="COMPLETE" and not r.get("close") else "NOT_REQUIRED"; workflow="CLOSED" if op=="COMPLETE" and r.get("close") else "ACTIVE"; setstate(workflow=workflow,execution=execution,review=review,scheduler_generation=S,dispatch_generation=D+1,task_fence=F+1,claim_id=None); c.execute("UPDATE claims SET status='CLOSED' WHERE claim_id=?",(row["claim_id"],)); return "TASK_"+op+"D"
        if op=="RECOVER" and (w,e,v)==("ACTIVE","CLAIMED","NOT_REQUIRED") and r.get("liveness_evidence"):
            setstate(execution="CLAIMABLE",scheduler_generation=S,dispatch_generation=D+1,task_fence=F+1,claim_id=None); c.execute("UPDATE claims SET status='RECOVERED' WHERE claim_id=?",(row["claim_id"],)); return "CLAIM_RECOVERED"
        if op=="RETRY" and (w,e,v)==("ACTIVE","FAILED","NOT_REQUIRED") and r.get("retryable"):
            c.execute("INSERT INTO attempts VALUES (?,?,?)",(row["task_id"],row["attempt"]+1,row["attempt"])); c.execute("UPDATE tasks SET attempt=?,execution='CLAIMABLE',scheduler_generation=?,dispatch_generation=?,task_fence=?,claim_id=NULL WHERE task_id=?",(row["attempt"]+1,S,D+1,F+1,row["task_id"])); return "TASK_RETRIED"
        if op=="GOVERNANCE_BLOCK" and (w,e,v) in VALID:
            rv="REVIEW_PENDING" if v in {"REVIEW_PENDING","REVIEWING"} else "NOT_REQUIRED"; setstate(workflow="GOVERNANCE_BLOCKED",execution="EXECUTION_BLOCKED",review=rv,scheduler_generation=S,dispatch_generation=D+1,task_fence=F+1,claim_id=None,reviewer_id=None); return "GOVERNANCE_BLOCKED"
        if op=="REVALIDATE" and (w,e,v) in {("GOVERNANCE_BLOCKED","EXECUTION_BLOCKED","NOT_REQUIRED"),("GOVERNANCE_BLOCKED","EXECUTION_BLOCKED","REVIEW_PENDING")}:
            setstate(workflow="ACTIVE",execution="CLAIMABLE" if v=="NOT_REQUIRED" else "EXECUTION_COMPLETED",review=v,scheduler_generation=S); return "GOVERNANCE_REVALIDATED"
        if op=="ASSIGN_REVIEW" and (w,e,v)==("ACTIVE","EXECUTION_COMPLETED","REVIEW_PENDING"):
            if r["actor"]==row["owner"] or r["role"]=="owner": raise RuntimeUnavailable("review independence denied")
            aid=str(uuid.uuid4()); setstate(review="REVIEWING",scheduler_generation=S,reviewer_id=aid); c.execute("INSERT INTO reviews VALUES (?,?,?,?,?)",(aid,row["task_id"],r["actor"],r["role"],"ACTIVE")); return "REVIEW_ASSIGNED"
        if op in {"APPROVE","REJECT","REMEDIATE"} and (w,e,v)==("ACTIVE","EXECUTION_COMPLETED","REVIEWING"):
            if r.get("reviewer_id")!=row["reviewer_id"]: raise RuntimeUnavailable("stale reviewer")
            review={"APPROVE":"APPROVED","REJECT":"REJECTED","REMEDIATE":"REMEDIATION_REQUIRED"}[op]; setstate(review=review,scheduler_generation=S,reviewer_id=None); c.execute("UPDATE reviews SET status=? WHERE assignment_id=?",(review,row["reviewer_id"])); return "REVIEW_"+op+"D"
        if op=="ROUTE" and (w,e,v)==("ACTIVE","EXECUTION_COMPLETED","APPROVED") and r.get("routing_evidence"):
            setstate(workflow="DIRECTOR_GATE_READY",scheduler_generation=S); return "DIRECTOR_ROUTED"
        raise RuntimeUnavailable("invalid or terminal transition")

    def create_remediation(self, source_task: str, child_task: str, request: dict[str, Any], *, operation_key: str, inject: str|None=None) -> dict[str, Any]:
        """Commit both reciprocal remediation events, child state, link and result or none."""
        body={"operation":"CREATE_REMEDIATION_TASK","source":source_task,"child":child_task,"request":request}; rd=digest(body)
        with self.locked("remediation"):
            b=self.bundle(); c=self.connect()
            try:
                c.execute("BEGIN IMMEDIATE"); self._verify(c)
                hit=c.execute("SELECT request_digest,response FROM idempotency WHERE operation_key=?",(operation_key,)).fetchone()
                if hit:
                    if hit["request_digest"]!=rd: raise RuntimeUnavailable("idempotency key reused with different request")
                    c.rollback(); return json.loads(hit["response"])
                source=c.execute("SELECT * FROM tasks WHERE task_id=?",(source_task,)).fetchone()
                if not source or self.tuple(source)!=request.get("expected") or source["review"] not in {"REJECTED","REMEDIATION_REQUIRED"}: raise RuntimeUnavailable("stale or non-remediable source")
                if request.get("repository_generation")!=self._meta(c,"repository_generation") or c.execute("SELECT 1 FROM tasks WHERE task_id=?",(child_task,)).fetchone(): raise RuntimeUnavailable("stale binding or child exists")
                link=str(uuid.uuid4()); before=self.tuple(source); c.execute("UPDATE tasks SET scheduler_generation=scheduler_generation+1,successor_task=? WHERE task_id=?",(child_task,source_task)); source2=c.execute("SELECT * FROM tasks WHERE task_id=?",(source_task,)).fetchone()
                first=self._task_event(c,source2,before,self.tuple(source2),"REMEDIATION_CREATED",{"relationship_id":link,"child":child_task,"decision":request["decision_digest"]})
                if inject in {"before_event","after_event"}: raise RuntimeError("injected remediation failure")
                c.execute("INSERT INTO tasks VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(child_task,1,"ACTIVE","CLAIMABLE","NOT_REQUIRED",0,0,0,None,None,0,self._meta(c,"repository_generation"),request["receipt_digest"],request["owner"],None,source_task,None)); c.execute("INSERT INTO attempts VALUES (?,?,?)",(child_task,1,None)); child=c.execute("SELECT * FROM tasks WHERE task_id=?",(child_task,)).fetchone()
                second=self._task_event(c,child,None,self.tuple(child),"TASK_CREATED_FROM_REMEDIATION",{"relationship_id":link,"parent":source_task,"parent_attempt":source["attempt"],"decision":request["decision_digest"]})
                ld=digest({"link_id":link,"source_task":source_task,"child_task":child_task,"source_event":first,"child_event":second,"decision_digest":request["decision_digest"]}); c.execute("INSERT INTO remediation_links VALUES (?,?,?,?,?,?,?)",(link,source_task,child_task,first,second,request["decision_digest"],ld))
                if inject in {"after_state","after_idempotency"}: raise RuntimeError("injected remediation failure")
                response={"relationship_id":link,"source_event":first,"child_event":second,"child_tuple":self.tuple(child)}; c.execute("INSERT INTO idempotency VALUES (?,?,?)",(operation_key,rd,json.dumps(response)))
                if self.bundle()!=b: raise RuntimeUnavailable("authoritative Git bundle changed before commit")
                c.commit(); return response
            except Exception:
                if c.in_transaction:c.rollback()
                raise
            finally:c.close()

    def migrate(self, target_version: int, artifact_digest: str, backup_target: Path, *, inject: bool=False) -> None:
        """Only v1 exists: v1→v1 records infrastructure; downgrade/newer schemas deny."""
        if target_version != SCHEMA_VERSION: raise RuntimeUnavailable("unknown newer schema or downgrade denied")
        backup_digest=self.backup(backup_target)
        with self.locked("migration"):
            c=self.connect()
            try:
                c.execute("BEGIN EXCLUSIVE"); self._verify(c)
                current=self._meta(c,"schema_version")
                if current != SCHEMA_VERSION: raise RuntimeUnavailable("schema mismatch")
                if inject: raise RuntimeError("injected migration failure")
                mid=str(uuid.uuid4()); c.execute("INSERT INTO migration_ledger VALUES (?,?,?,?,?,?,?,?)",(mid,current,target_version,artifact_digest,str(backup_target),backup_digest,"SUCCESS",utc())); self._runtime_event(c,"SCHEMA_MIGRATED",{"migration_id":mid,"from":current,"to":target_version,"backup_digest":backup_digest},self.bundle()); c.commit()
            except Exception:
                if c.in_transaction:c.rollback()
                raise
            finally:c.close()

    def replay(self, c: sqlite3.Connection) -> None:
        """Verify contiguous global/task chains and materialized tuple validity; deny on any anomaly."""
        events=[]
        for table in ("runtime_events","task_events"):
            events += [(r["global_seq"],table,r) for r in c.execute(f"SELECT * FROM {table}")]
        events.sort(); prev_id="GENESIS"; prev=hashlib.sha256(b"GENESIS").hexdigest()
        for expected,(_,table,row) in enumerate(events):
            if row["global_seq"] != expected: raise RuntimeUnavailable("global event sequence gap")
            parent_id = row["prev_id"] if table == "runtime_events" else None
            parent_digest = row["prev_digest"] if table == "runtime_events" else row["prev_global_digest"]
            if (parent_id is not None and parent_id != prev_id) or parent_digest != prev: raise RuntimeUnavailable("global event chain mismatch")
            prev_id,prev=row["event_id"],row["event_digest"]
        if self._meta(c,"global_head_id") != prev_id or self._meta(c,"global_head_digest") != prev: raise RuntimeUnavailable("materialized global head mismatch")
        for task in c.execute("SELECT * FROM tasks"):
            if (task["workflow"],task["execution"],task["review"]) not in VALID: raise RuntimeUnavailable("invalid materialized tuple")
            rows=list(c.execute("SELECT * FROM task_events WHERE task_id=? ORDER BY task_seq",(task["task_id"],))); pd=digest("TASK_GENESIS:"+task["task_id"])
            for seq,row in enumerate(rows,1):
                if row["task_seq"] != seq or row["prev_task_digest"] != pd: raise RuntimeUnavailable("task event chain mismatch")
                pd=row["event_digest"]
        for link in c.execute("SELECT * FROM remediation_links"):
            s=c.execute("SELECT 1 FROM task_events WHERE event_id=? AND task_id=?",(link["source_event"],link["source_task"])).fetchone(); child=c.execute("SELECT 1 FROM task_events WHERE event_id=? AND task_id=?",(link["child_event"],link["child_task"])).fetchone()
            if not s or not child or link["link_digest"] != digest({k:link[k] for k in ("link_id","source_task","child_task","source_event","child_event","decision_digest")}): raise RuntimeUnavailable("remediation link mismatch")

    def import_repository(self, affected: list[str], reason: str="IMPORT") -> None:
        with self.locked("import"):
            b=self.bundle(); c=self.connect()
            try:
                c.execute("BEGIN IMMEDIATE"); self._verify(c); old=self._meta(c,"repository_generation"); prior=self._meta(c,"bundle_digest")
                if b.digest==prior: c.rollback(); return
                new=old+1; self._set(c,"repository_generation",new)
                self._set(c,"bundle_digest",b.digest)
                for tid in affected:
                    row=c.execute("SELECT * FROM tasks WHERE task_id=?",(tid,)).fetchone()
                    if not row: raise RuntimeUnavailable("unknown affected task")
                    if (row["workflow"],row["execution"],row["review"]) in {( "ACTIVE","CLAIMABLE","NOT_REQUIRED")}:
                        c.execute("UPDATE tasks SET scheduler_generation=scheduler_generation+1,repository_generation=? WHERE task_id=?",(new,tid))
                    else:
                        c.execute("UPDATE tasks SET workflow='GOVERNANCE_BLOCKED',execution='EXECUTION_BLOCKED',review=?,claim_id=NULL,reviewer_id=NULL,scheduler_generation=scheduler_generation+1,dispatch_generation=dispatch_generation+1,task_fence=task_fence+1,repository_generation=? WHERE task_id=?",("REVIEW_PENDING" if row["review"] in {"REVIEW_PENDING","REVIEWING"} else "NOT_REQUIRED",new,tid))
                self._runtime_event(c,"REPOSITORY_GENERATION_ADVANCED",{"old":old,"new":new,"bundle":b.digest,"source_commit":b.commit,"project":b.project,"stops":b.stops,"policy":b.policy,"reason":reason,"affected":affected},b); c.commit()
            except Exception:
                if c.in_transaction:c.rollback()
                raise
            finally:c.close()

    def backup(self, target: Path) -> str:
        with self.locked("backup"):
            target.parent.mkdir(parents=True,exist_ok=True); _mode(target.parent,0o700)
            tmp=target.with_suffix(".tmp"); src=self.connect(); self._verify(src); dst=sqlite3.connect(tmp)
            try:
                src.backup(dst); dst.close(); _mode(tmp,0o600)
                chk=sqlite3.connect(tmp); ok=chk.execute("PRAGMA integrity_check").fetchone()[0]=="ok" and not chk.execute("PRAGMA foreign_key_check").fetchall(); chk.close()
                if not ok: raise RuntimeUnavailable("backup verification failed")
                os.replace(tmp,target); _mode(target,0o600); return hashlib.sha256(target.read_bytes()).hexdigest()
            finally:
                src.close();
                if tmp.exists(): tmp.unlink()

    def export(self, target: Path) -> dict[str,Any]:
        with self.locked("export"):
            c=self.connect()
            try:
                self._verify(c); b=self.bundle(); c.execute("BEGIN")
                payload={"schema_version":1,"runtime_id":self._meta(c,"runtime_id"),"repository_generation":self._meta(c,"repository_generation"),"bundle_digest":b.digest,"global_head_id":self._meta(c,"global_head_id"),"global_head_digest":self._meta(c,"global_head_digest"),"tasks":[dict(x) for x in c.execute("SELECT * FROM tasks ORDER BY task_id")],"runtime_events":[dict(x) for x in c.execute("SELECT * FROM runtime_events ORDER BY global_seq")],"task_events":[dict(x) for x in c.execute("SELECT * FROM task_events ORDER BY global_seq")]}; payload["snapshot_digest"]=digest(payload); c.rollback(); target.parent.mkdir(parents=True,exist_ok=True); _mode(target.parent,0o700); target.write_bytes(canonical(payload)); _mode(target,0o600); return payload
            finally:c.close()
