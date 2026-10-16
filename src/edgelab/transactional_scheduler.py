"""M0.3A local-only, synthetic SQLite scheduler.  It is never an executor."""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import sqlite3
import stat
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
def is_sha256(value: Any) -> bool: return isinstance(value,str) and len(value)==64 and all(character in "0123456789abcdef" for character in value)
def strict_equal(left: Any, right: Any) -> bool:
    if type(left) is not type(right): return False
    if isinstance(left,dict): return left.keys()==right.keys() and all(strict_equal(left[key],right[key]) for key in left)
    if isinstance(left,list): return len(left)==len(right) and all(strict_equal(a,b) for a,b in zip(left,right))
    return left==right
def utc() -> str: return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
def _mode(path: Path, wanted: int, *, repair: bool = True) -> None:
    try:
        if repair:
            os.chmod(path, wanted)
        actual = stat.S_IMODE(os.stat(path).st_mode)
    except OSError as error: raise RuntimeError("runtime permissions unavailable") from error
    if actual != wanted: raise RuntimeError("unsafe runtime permissions")

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
    def locked(self, purpose: str, *, repair_permissions: bool = True) -> Iterator[None]:
        if repair_permissions:
            self.dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        _mode(self.dir, 0o700, repair=repair_permissions)
        mode = "a+" if repair_permissions else "r+"
        f = open(self.lock_path, mode, encoding="utf-8"); _mode(self.lock_path, 0o600, repair=repair_permissions)
        try:
            try: fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as e: raise RuntimeUnavailable("cooperative lock held") from e
            yield
        finally:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN); f.close()
    def connect(self, *, read_only: bool = False) -> sqlite3.Connection:
        target = f"file:{self.db}?mode=ro&immutable=1" if read_only else self.db
        c = sqlite3.connect(target, isolation_level=None, uri=read_only); c.row_factory = sqlite3.Row
        try:
            if not read_only and c.execute("PRAGMA journal_mode=WAL").fetchone()[0].lower() != "wal": raise RuntimeUnavailable("WAL unavailable")
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
    def _verify(self,c, *, repair_permissions: bool = True):
        if not self.attachment.exists(): raise RuntimeUnavailable("attachment missing")
        _mode(self.dir,0o700,repair=repair_permissions); _mode(self.attachment,0o600,repair=repair_permissions); _mode(self.db,0o600,repair=repair_permissions)
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
        if not isinstance(task_id,str) or not task_id: raise RuntimeUnavailable("invalid task identity")
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
                    if set(request)!={"receipt_digest","owner"} or not isinstance(request.get("receipt_digest"),str) or not request["receipt_digest"] or not isinstance(request.get("owner"),str) or not request["owner"]: raise RuntimeUnavailable("invalid task origin binding")
                    c.execute("INSERT INTO tasks VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(task_id,1,"ACTIVE","CLAIMABLE","NOT_REQUIRED",0,0,0,None,None,0,self._meta(c,"repository_generation"),request["receipt_digest"],request["owner"],None,None,None)); c.execute("INSERT INTO attempts VALUES (?,?,?)",(task_id,1,None)); event="TASK_INITIALIZED"; before=None
                else:
                    row=c.execute("SELECT * FROM tasks WHERE task_id=?",(task_id,)).fetchone()
                    if not row: raise RuntimeUnavailable("unknown task")
                    if not strict_equal(request.get("expected"),self.tuple(row)): raise RuntimeUnavailable("stale tuple")
                    repository_generation=self._meta(c,"repository_generation")
                    if type(request.get("repository_generation")) is not int or request["repository_generation"] != repository_generation or row["repository_generation"] != repository_generation or not isinstance(request.get("receipt_digest"),str) or request["receipt_digest"] != row["receipt_digest"]: raise RuntimeUnavailable("stale repository or M0.2 receipt")
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
            if not isinstance(r.get("actor"),str) or not r["actor"]: raise RuntimeUnavailable("invalid claim actor")
            cid=str(uuid.uuid4()); setstate(execution="CLAIMED",scheduler_generation=S,dispatch_generation=D+1,task_fence=F+1,claim_id=cid); c.execute("INSERT INTO claims VALUES (?,?,?,?,?,?)",(cid,row["task_id"],row["attempt"],F+1,"ACTIVE",r["actor"])); return "CLAIM_ISSUED"
        if op in {"START","CONTINUE","YIELD","FAIL","COMPLETE"}:
            if not isinstance(r.get("claim_id"),str) or r["claim_id"]!=row["claim_id"] or type(r.get("fence")) is not int or r["fence"]!=F: raise RuntimeUnavailable("stale worker fence")
            if op=="START" and e=="CLAIMED": setstate(execution="IN_PROGRESS",scheduler_generation=S); return "TASK_STARTED"
            if op=="CONTINUE" and e=="IN_PROGRESS": setstate(scheduler_generation=S,continuations=row["continuations"]+1); return "TASK_CONTINUED"
            if ((op in {"YIELD","FAIL"} and e in {"CLAIMED","IN_PROGRESS"}) or
                    (op=="COMPLETE" and e=="IN_PROGRESS")):
                if op=="COMPLETE" and r.get("close") is not None and type(r["close"]) is not bool: raise RuntimeUnavailable("invalid completion mode")
                execution="CLAIMABLE" if op=="YIELD" else "FAILED" if op=="FAIL" else "EXECUTION_COMPLETED"; review="REVIEW_PENDING" if op=="COMPLETE" and not r.get("close") else "NOT_REQUIRED"; workflow="CLOSED" if op=="COMPLETE" and r.get("close") else "ACTIVE"; setstate(workflow=workflow,execution=execution,review=review,scheduler_generation=S,dispatch_generation=D+1,task_fence=F+1,claim_id=None); c.execute("UPDATE claims SET status='CLOSED' WHERE claim_id=?",(row["claim_id"],)); return "TASK_"+op+"D"
        if op=="RECOVER" and (w,e,v)==("ACTIVE","CLAIMED","NOT_REQUIRED") and isinstance(r.get("liveness_evidence"),str) and r["liveness_evidence"]:
            setstate(execution="CLAIMABLE",scheduler_generation=S,dispatch_generation=D+1,task_fence=F+1,claim_id=None); c.execute("UPDATE claims SET status='RECOVERED' WHERE claim_id=?",(row["claim_id"],)); return "CLAIM_RECOVERED"
        if op=="RETRY" and (w,e,v)==("ACTIVE","FAILED","NOT_REQUIRED") and r.get("retryable") is True:
            c.execute("INSERT INTO attempts VALUES (?,?,?)",(row["task_id"],row["attempt"]+1,row["attempt"])); c.execute("UPDATE tasks SET attempt=?,execution='CLAIMABLE',scheduler_generation=?,dispatch_generation=?,task_fence=?,claim_id=NULL WHERE task_id=?",(row["attempt"]+1,S,D+1,F+1,row["task_id"])); return "TASK_RETRIED"
        if op=="GOVERNANCE_BLOCK" and (w,e,v) in {
                ("ACTIVE","CLAIMABLE","NOT_REQUIRED"),
                ("ACTIVE","CLAIMED","NOT_REQUIRED"),
                ("ACTIVE","IN_PROGRESS","NOT_REQUIRED"),
                ("ACTIVE","EXECUTION_COMPLETED","REVIEW_PENDING"),
                ("ACTIVE","EXECUTION_COMPLETED","REVIEWING")}:
            if row["claim_id"] is not None: c.execute("UPDATE claims SET status='GOVERNANCE_BLOCKED' WHERE claim_id=?",(row["claim_id"],))
            if row["reviewer_id"] is not None: c.execute("UPDATE reviews SET status='GOVERNANCE_BLOCKED' WHERE assignment_id=?",(row["reviewer_id"],))
            rv="REVIEW_PENDING" if v in {"REVIEW_PENDING","REVIEWING"} else "NOT_REQUIRED"; setstate(workflow="GOVERNANCE_BLOCKED",execution="EXECUTION_BLOCKED",review=rv,scheduler_generation=S,dispatch_generation=D+1,task_fence=F+1,claim_id=None,reviewer_id=None); return "GOVERNANCE_BLOCKED"
        if op=="REVALIDATE" and (w,e,v) in {("GOVERNANCE_BLOCKED","EXECUTION_BLOCKED","NOT_REQUIRED"),("GOVERNANCE_BLOCKED","EXECUTION_BLOCKED","REVIEW_PENDING")}:
            setstate(workflow="ACTIVE",execution="CLAIMABLE" if v=="NOT_REQUIRED" else "EXECUTION_COMPLETED",review=v,scheduler_generation=S); return "GOVERNANCE_REVALIDATED"
        if op=="ASSIGN_REVIEW" and (w,e,v)==("ACTIVE","EXECUTION_COMPLETED","REVIEW_PENDING"):
            if any(not isinstance(r.get(field),str) or not r[field] for field in ("actor","role")) or r["actor"]==row["owner"] or r["role"]=="owner": raise RuntimeUnavailable("review independence denied")
            aid=str(uuid.uuid4()); setstate(review="REVIEWING",scheduler_generation=S,reviewer_id=aid); c.execute("INSERT INTO reviews VALUES (?,?,?,?,?)",(aid,row["task_id"],r["actor"],r["role"],"ACTIVE")); return "REVIEW_ASSIGNED"
        if op in {"APPROVE","REJECT","REMEDIATE"} and (w,e,v)==("ACTIVE","EXECUTION_COMPLETED","REVIEWING"):
            if r.get("reviewer_id")!=row["reviewer_id"]: raise RuntimeUnavailable("stale reviewer")
            if not is_sha256(r.get("decision_digest")): raise RuntimeUnavailable("invalid review decision digest")
            review={"APPROVE":"APPROVED","REJECT":"REJECTED","REMEDIATE":"REMEDIATION_REQUIRED"}[op]; setstate(review=review,scheduler_generation=S,reviewer_id=None); c.execute("UPDATE reviews SET status=? WHERE assignment_id=?",(review,row["reviewer_id"])); return "REVIEW_"+op+"D"
        if op=="ROUTE" and (w,e,v)==("ACTIVE","EXECUTION_COMPLETED","APPROVED") and isinstance(r.get("routing_evidence"),str) and r["routing_evidence"]:
            setstate(workflow="DIRECTOR_GATE_READY",scheduler_generation=S); return "DIRECTOR_ROUTED"
        raise RuntimeUnavailable("invalid or terminal transition")

    def create_remediation(self, source_task: str, child_task: str, request: dict[str, Any], *, operation_key: str, inject: str|None=None) -> dict[str, Any]:
        """Commit both reciprocal remediation events, child state, link and result or none."""
        if any(not isinstance(task_id,str) or not task_id for task_id in (source_task,child_task)): raise RuntimeUnavailable("invalid remediation task identity")
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
                if not source or not strict_equal(self.tuple(source),request.get("expected")) or source["review"] not in {"REJECTED","REMEDIATION_REQUIRED"}: raise RuntimeUnavailable("stale or non-remediable source")
                if source_task==child_task or source["successor_task"] is not None: raise RuntimeUnavailable("invalid remediation lineage")
                if not is_sha256(request.get("decision_digest")) or any(not isinstance(request.get(key),str) or not request[key] for key in ("receipt_digest","owner")): raise RuntimeUnavailable("invalid remediation binding")
                review_event=c.execute("SELECT payload FROM task_events WHERE task_id=? AND event_type IN ('REVIEW_REJECTD','REVIEW_REMEDIATED') ORDER BY task_seq DESC LIMIT 1",(source_task,)).fetchone()
                try: reviewed_digest=json.loads(review_event["payload"])["request"]["request"]["decision_digest"] if review_event else None
                except (TypeError,KeyError,json.JSONDecodeError): reviewed_digest=None
                if request["decision_digest"]!=reviewed_digest: raise RuntimeUnavailable("remediation decision mismatch")
                repository_generation=self._meta(c,"repository_generation")
                if type(request.get("repository_generation")) is not int or request["repository_generation"]!=repository_generation or source["repository_generation"]!=repository_generation or c.execute("SELECT 1 FROM tasks WHERE task_id=?",(child_task,)).fetchone(): raise RuntimeUnavailable("stale binding or child exists")
                link=str(uuid.uuid4()); before=self.tuple(source); c.execute("UPDATE tasks SET scheduler_generation=scheduler_generation+1,successor_task=? WHERE task_id=?",(child_task,source_task)); source2=c.execute("SELECT * FROM tasks WHERE task_id=?",(source_task,)).fetchone()
                first=self._task_event(c,source2,before,self.tuple(source2),"REMEDIATION_CREATED",{"relationship_id":link,"child":child_task,"decision":request["decision_digest"],"child_owner":request["owner"],"child_receipt_digest":request["receipt_digest"]})
                if inject in {"before_event","after_event"}: raise RuntimeError("injected remediation failure")
                c.execute("INSERT INTO tasks VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(child_task,1,"ACTIVE","CLAIMABLE","NOT_REQUIRED",0,0,0,None,None,0,self._meta(c,"repository_generation"),request["receipt_digest"],request["owner"],None,source_task,None)); c.execute("INSERT INTO attempts VALUES (?,?,?)",(child_task,1,None)); child=c.execute("SELECT * FROM tasks WHERE task_id=?",(child_task,)).fetchone()
                second=self._task_event(c,child,None,self.tuple(child),"TASK_CREATED_FROM_REMEDIATION",{"relationship_id":link,"parent":source_task,"parent_attempt":source["attempt"],"decision":request["decision_digest"],"owner":request["owner"],"receipt_digest":request["receipt_digest"]})
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
        """Rebuild task and auxiliary state from events; deny on any anomaly."""
        def load_json(value: str, label: str) -> Any:
            try: return json.loads(value)
            except (TypeError, json.JSONDecodeError) as error: raise RuntimeUnavailable(f"invalid {label}") from error
        def require(condition: bool, message: str) -> None:
            if not condition: raise RuntimeUnavailable(message)
        def advanced(before: dict[str,Any], **changes: Any) -> dict[str,Any]:
            result=dict(before); result.update(changes); return result
        def triple(value: dict[str,Any]) -> tuple[str,str,str]:
            return value["workflow"],value["execution"],value["review"]
        def normal_payload(row: sqlite3.Row, payload: Any, before: dict[str,Any], operation: str) -> dict[str,Any]:
            require(isinstance(payload,dict) and set(payload)=={"request","bundle"} and isinstance(payload["bundle"],str) and bool(payload["bundle"]),"invalid task event payload")
            outer=payload["request"]
            require(isinstance(outer,dict) and set(outer)=={"operation","task_id","request"},"invalid task event request")
            require(outer["operation"]==operation and outer["task_id"]==row["task_id"] and isinstance(outer["request"],dict),"task event request mismatch")
            request=outer["request"]
            require(strict_equal(request.get("expected"),before),"task event expected tuple mismatch")
            require(type(request.get("repository_generation")) is int and request["repository_generation"]==before["repository_generation"] and isinstance(request.get("receipt_digest"),str) and request["receipt_digest"]==before["decision_receipt_digest"],"task event binding mismatch")
            return request
        def close_claim(claims: dict[str,dict[str,Any]], before: dict[str,Any], status: str) -> None:
            claim_id=before["active_claim_id"]
            require(isinstance(claim_id,str) and claim_id in claims and claims[claim_id]["status"]=="ACTIVE","claim lifecycle mismatch")
            claims[claim_id]["status"]=status
        def close_review(reviews: dict[str,dict[str,Any]], before: dict[str,Any], status: str) -> None:
            assignment=before["reviewer_assignment_id"]
            require(isinstance(assignment,str) and assignment in reviews and reviews[assignment]["status"]=="ACTIVE","review lifecycle mismatch")
            reviews[assignment]["status"]=status

        events=[]
        for table in ("runtime_events","task_events"):
            events += [(r["global_seq"],table,r) for r in c.execute(f"SELECT * FROM {table}")]
        events.sort(); prev_id="GENESIS"; prev=hashlib.sha256(b"GENESIS").hexdigest()
        for expected,(_,table,row) in enumerate(events):
            if row["global_seq"] != expected: raise RuntimeUnavailable("global event sequence gap")
            parent_id = row["prev_id"] if table == "runtime_events" else None
            parent_digest = row["prev_digest"] if table == "runtime_events" else row["prev_global_digest"]
            if (parent_id is not None and parent_id != prev_id) or parent_digest != prev: raise RuntimeUnavailable("global event chain mismatch")
            if table == "runtime_events":
                rebuilt=digest({"id":row["event_id"],"seq":row["global_seq"],"type":row["event_type"],"payload":load_json(row["payload"],"runtime event payload"),"prev":row["prev_digest"]})
            else:
                rebuilt=digest({"id":row["event_id"],"n":row["global_seq"],"seq":row["task_seq"],"type":row["event_type"],"before":load_json(row["before_json"],"task event before"),"after":load_json(row["after_json"],"task event after"),"payload":load_json(row["payload"],"task event payload"),"prev":row["prev_task_digest"]})
            if rebuilt != row["event_digest"]: raise RuntimeUnavailable("event digest mutation")
            prev_id,prev=row["event_id"],row["event_digest"]
        if self._meta(c,"global_head_id") != prev_id or self._meta(c,"global_head_digest") != prev: raise RuntimeUnavailable("materialized global head mismatch")
        tasks={row["task_id"]:row for row in c.execute("SELECT * FROM tasks")}
        event_task_ids={row[0] for row in c.execute("SELECT DISTINCT task_id FROM task_events")}
        if set(tasks) != event_task_ids: raise RuntimeUnavailable("replay task inventory mismatch")
        expected_attempts: dict[tuple[str,int],dict[str,Any]]={}
        expected_claims: dict[str,dict[str,Any]]={}
        expected_reviews: dict[str,dict[str,Any]]={}
        expected_metadata: dict[str,dict[str,Any]]={}
        remediation_decisions: dict[str,str]={}
        remediation_sources: dict[str,dict[str,Any]]={}
        remediation_children: dict[str,dict[str,Any]]={}
        for task_id,task in tasks.items():
            if (task["workflow"],task["execution"],task["review"]) not in VALID: raise RuntimeUnavailable("invalid materialized tuple")
            rows=list(c.execute("SELECT * FROM task_events WHERE task_id=? ORDER BY task_seq",(task_id,))); pd=digest("TASK_GENESIS:"+task_id); previous=None
            tuple_fields=set(self.tuple(task))
            for seq,row in enumerate(rows,1):
                if row["task_seq"] != seq or row["prev_task_digest"] != pd: raise RuntimeUnavailable("task event chain mismatch")
                before=load_json(row["before_json"],"task event before"); after=load_json(row["after_json"],"task event after"); payload=load_json(row["payload"],"task event payload")
                if before != previous: raise RuntimeUnavailable("task event before/after discontinuity")
                if not isinstance(after,dict) or set(after) != tuple_fields: raise RuntimeUnavailable("invalid replayed task tuple")
                if (after["workflow"],after["execution"],after["review"]) not in VALID: raise RuntimeUnavailable("invalid replayed task tuple")
                integer_fields=("attempt_no","scheduler_generation","dispatch_generation","task_fence","continuation_count","repository_generation")
                if any(type(after[field]) is not int or after[field] < (1 if field=="attempt_no" else 0) for field in integer_fields): raise RuntimeUnavailable("invalid replayed task tuple")
                if any(after[field] is not None and (not isinstance(after[field],str) or not after[field]) for field in ("active_claim_id","reviewer_assignment_id")) or not isinstance(after["decision_receipt_digest"],str) or not after["decision_receipt_digest"]: raise RuntimeUnavailable("invalid replayed task tuple")
                if type(after["attempt_no"]) is not int or after["attempt_no"] < 1 or row["attempt"] != after["attempt_no"]: raise RuntimeUnavailable("task event attempt mismatch")
                if seq == 1:
                    if row["event_type"] not in {"TASK_INITIALIZED","TASK_CREATED_FROM_REMEDIATION"}: raise RuntimeUnavailable("task event origin mismatch")
                    expected_origin={"workflow":"ACTIVE","execution":"CLAIMABLE","review":"NOT_REQUIRED","attempt_no":1,"scheduler_generation":0,"dispatch_generation":0,"task_fence":0,"active_claim_id":None,"reviewer_assignment_id":None,"continuation_count":0}
                    if any(after.get(key) != value for key,value in expected_origin.items()) or type(after["repository_generation"]) is not int or after["repository_generation"] < 0 or not isinstance(after["decision_receipt_digest"],str) or not after["decision_receipt_digest"]: raise RuntimeUnavailable("task event origin tuple mismatch")
                    expected_attempts[(task_id,1)]={"task_id":task_id,"attempt":1,"predecessor_attempt":None}
                    if row["event_type"]=="TASK_INITIALIZED":
                        require(isinstance(payload,dict) and set(payload)=={"request","bundle"} and isinstance(payload["bundle"],str) and bool(payload["bundle"]),"invalid task origin payload")
                        outer=payload["request"]
                        require(isinstance(outer,dict) and set(outer)=={"operation","task_id","request"} and outer["operation"]=="INITIALIZE" and outer["task_id"]==task_id,"task origin request mismatch")
                        request=outer["request"]
                        require(isinstance(request,dict) and set(request)=={"receipt_digest","owner"} and request["receipt_digest"]==after["decision_receipt_digest"] and isinstance(request["owner"],str) and bool(request["owner"]),"task origin binding mismatch")
                        expected_metadata[task_id]={"owner":request["owner"],"reviewer":None,"predecessor_task":None,"successor_task":None}
                    else:
                        require(isinstance(payload,dict) and set(payload)=={"relationship_id","parent","parent_attempt","decision","owner","receipt_digest"},"invalid remediation child payload")
                        require(all(isinstance(payload[key],str) and bool(payload[key]) for key in ("relationship_id","parent","decision","owner","receipt_digest")) and type(payload["parent_attempt"]) is int and payload["parent_attempt"] >= 1,"invalid remediation child binding")
                        require(payload["receipt_digest"]==after["decision_receipt_digest"] and payload["parent"]!=task_id,"remediation child binding mismatch")
                        expected_metadata[task_id]={"owner":payload["owner"],"reviewer":None,"predecessor_task":payload["parent"],"successor_task":None}
                        require(payload["relationship_id"] not in remediation_children,"duplicate remediation child")
                        remediation_children[payload["relationship_id"]]={"task_id":task_id,"event_id":row["event_id"],"global_seq":row["global_seq"],**payload}
                if seq > 1 and row["event_type"] in {"TASK_INITIALIZED","TASK_CREATED_FROM_REMEDIATION"}: raise RuntimeUnavailable("task event origin mismatch")
                if seq > 1:
                    typ=row["event_type"]
                    operation_by_type={"CLAIM_ISSUED":"CLAIM","TASK_STARTED":"START","TASK_CONTINUED":"CONTINUE","TASK_YIELDD":"YIELD","TASK_FAILD":"FAIL","TASK_COMPLETED":"COMPLETE","CLAIM_RECOVERED":"RECOVER","TASK_RETRIED":"RETRY","GOVERNANCE_BLOCKED":"GOVERNANCE_BLOCK","GOVERNANCE_REVALIDATED":"REVALIDATE","REVIEW_ASSIGNED":"ASSIGN_REVIEW","REVIEW_APPROVED":"APPROVE","REVIEW_REJECTD":"REJECT","REVIEW_REMEDIATED":"REMEDIATE","DIRECTOR_ROUTED":"ROUTE"}
                    if typ=="REMEDIATION_CREATED":
                        require(triple(before) in {("ACTIVE","EXECUTION_COMPLETED","REJECTED"),("ACTIVE","EXECUTION_COMPLETED","REMEDIATION_REQUIRED")},"invalid remediation source tuple")
                        require(isinstance(payload,dict) and set(payload)=={"relationship_id","child","decision","child_owner","child_receipt_digest"},"invalid remediation source payload")
                        require(all(isinstance(payload[key],str) and bool(payload[key]) for key in payload) and payload["child"]!=task_id and is_sha256(payload["decision"]),"invalid remediation source binding")
                        require(remediation_decisions.get(task_id)==payload["decision"],"remediation decision mismatch")
                        require(after==advanced(before,scheduler_generation=before["scheduler_generation"]+1),"invalid remediation source delta")
                        require(expected_metadata[task_id]["successor_task"] is None and payload["relationship_id"] not in remediation_sources,"duplicate remediation source")
                        expected_metadata[task_id]["successor_task"]=payload["child"]
                        remediation_sources[payload["relationship_id"]]={"task_id":task_id,"attempt":before["attempt_no"],"event_id":row["event_id"],"global_seq":row["global_seq"],**payload}
                    elif typ=="REPOSITORY_GENERATION_APPLIED":
                        require(isinstance(payload,dict) and set(payload)=={"old","new","task_old","bundle","source_commit","reason"},"invalid repository event payload")
                        require(type(payload["old"]) is int and type(payload["new"]) is int and type(payload["task_old"]) is int and payload["new"]==payload["old"]+1 and 0<=payload["task_old"]<=payload["old"] and before["repository_generation"]==payload["task_old"],"repository event generation mismatch")
                        require(all(isinstance(payload[key],str) and bool(payload[key]) for key in ("bundle","source_commit","reason")),"invalid repository event binding")
                        updates={"scheduler_generation":before["scheduler_generation"]+1,"repository_generation":payload["new"]}
                        source=triple(before)
                        if source==("ACTIVE","CLAIMABLE","NOT_REQUIRED"): pass
                        elif source in {("ACTIVE","CLAIMED","NOT_REQUIRED"),("ACTIVE","IN_PROGRESS","NOT_REQUIRED"),("ACTIVE","EXECUTION_COMPLETED","REVIEW_PENDING"),("ACTIVE","EXECUTION_COMPLETED","REVIEWING")}:
                            if before["active_claim_id"] is not None: close_claim(expected_claims,before,"GOVERNANCE_BLOCKED")
                            if before["reviewer_assignment_id"] is not None: close_review(expected_reviews,before,"GOVERNANCE_BLOCKED")
                            updates.update({"workflow":"GOVERNANCE_BLOCKED","execution":"EXECUTION_BLOCKED","review":"REVIEW_PENDING" if before["review"] in {"REVIEW_PENDING","REVIEWING"} else "NOT_REQUIRED","active_claim_id":None,"reviewer_assignment_id":None,"dispatch_generation":before["dispatch_generation"]+1,"task_fence":before["task_fence"]+1})
                        else: raise RuntimeUnavailable("invalid repository transition scope")
                        require(after==advanced(before,**updates),"invalid repository event delta")
                    else:
                        require(typ in operation_by_type,"unknown task event type")
                        operation=operation_by_type[typ]; request=normal_payload(row,payload,before,operation); source=triple(before)
                        expected: dict[str,Any]
                        if operation=="CLAIM":
                            require(source==("ACTIVE","CLAIMABLE","NOT_REQUIRED") and after["active_claim_id"] is not None and isinstance(request.get("actor"),str) and bool(request["actor"]),"invalid claim transition")
                            expected=advanced(before,execution="CLAIMED",scheduler_generation=before["scheduler_generation"]+1,dispatch_generation=before["dispatch_generation"]+1,task_fence=before["task_fence"]+1,active_claim_id=after["active_claim_id"])
                            require(after["active_claim_id"] not in expected_claims,"duplicate claim")
                            expected_claims[after["active_claim_id"]]={"claim_id":after["active_claim_id"],"task_id":task_id,"attempt":before["attempt_no"],"fence":after["task_fence"],"status":"ACTIVE","actor":request["actor"]}
                        elif operation=="START":
                            require(source==("ACTIVE","CLAIMED","NOT_REQUIRED") and isinstance(request.get("claim_id"),str) and request["claim_id"]==before["active_claim_id"] and type(request.get("fence")) is int and request["fence"]==before["task_fence"],"invalid start transition")
                            expected=advanced(before,execution="IN_PROGRESS",scheduler_generation=before["scheduler_generation"]+1)
                        elif operation=="CONTINUE":
                            require(source==("ACTIVE","IN_PROGRESS","NOT_REQUIRED") and isinstance(request.get("claim_id"),str) and request["claim_id"]==before["active_claim_id"] and type(request.get("fence")) is int and request["fence"]==before["task_fence"],"invalid continue transition")
                            expected=advanced(before,scheduler_generation=before["scheduler_generation"]+1,continuation_count=before["continuation_count"]+1)
                        elif operation in {"YIELD","FAIL","COMPLETE"}:
                            allowed=source in {("ACTIVE","CLAIMED","NOT_REQUIRED"),("ACTIVE","IN_PROGRESS","NOT_REQUIRED")} if operation!="COMPLETE" else source==("ACTIVE","IN_PROGRESS","NOT_REQUIRED")
                            require(allowed and isinstance(request.get("claim_id"),str) and request["claim_id"]==before["active_claim_id"] and type(request.get("fence")) is int and request["fence"]==before["task_fence"],"invalid worker terminal transition")
                            require(operation!="COMPLETE" or request.get("close") is None or type(request["close"]) is bool,"invalid completion mode")
                            close_claim(expected_claims,before,"CLOSED")
                            execution="CLAIMABLE" if operation=="YIELD" else "FAILED" if operation=="FAIL" else "EXECUTION_COMPLETED"
                            review="REVIEW_PENDING" if operation=="COMPLETE" and not request.get("close") else "NOT_REQUIRED"
                            workflow="CLOSED" if operation=="COMPLETE" and request.get("close") else "ACTIVE"
                            expected=advanced(before,workflow=workflow,execution=execution,review=review,scheduler_generation=before["scheduler_generation"]+1,dispatch_generation=before["dispatch_generation"]+1,task_fence=before["task_fence"]+1,active_claim_id=None)
                        elif operation=="RECOVER":
                            require(source==("ACTIVE","CLAIMED","NOT_REQUIRED") and isinstance(request.get("liveness_evidence"),str) and bool(request["liveness_evidence"]),"invalid recovery transition")
                            close_claim(expected_claims,before,"RECOVERED")
                            expected=advanced(before,execution="CLAIMABLE",scheduler_generation=before["scheduler_generation"]+1,dispatch_generation=before["dispatch_generation"]+1,task_fence=before["task_fence"]+1,active_claim_id=None)
                        elif operation=="RETRY":
                            require(source==("ACTIVE","FAILED","NOT_REQUIRED") and request.get("retryable") is True,"invalid retry transition")
                            next_attempt=before["attempt_no"]+1; expected_attempts[(task_id,next_attempt)]={"task_id":task_id,"attempt":next_attempt,"predecessor_attempt":before["attempt_no"]}
                            expected=advanced(before,attempt_no=next_attempt,execution="CLAIMABLE",scheduler_generation=before["scheduler_generation"]+1,dispatch_generation=before["dispatch_generation"]+1,task_fence=before["task_fence"]+1,active_claim_id=None)
                        elif operation=="GOVERNANCE_BLOCK":
                            require(source in {("ACTIVE","CLAIMABLE","NOT_REQUIRED"),("ACTIVE","CLAIMED","NOT_REQUIRED"),("ACTIVE","IN_PROGRESS","NOT_REQUIRED"),("ACTIVE","EXECUTION_COMPLETED","REVIEW_PENDING"),("ACTIVE","EXECUTION_COMPLETED","REVIEWING")},"invalid governance transition scope")
                            if before["active_claim_id"] is not None: close_claim(expected_claims,before,"GOVERNANCE_BLOCKED")
                            if before["reviewer_assignment_id"] is not None: close_review(expected_reviews,before,"GOVERNANCE_BLOCKED")
                            expected=advanced(before,workflow="GOVERNANCE_BLOCKED",execution="EXECUTION_BLOCKED",review="REVIEW_PENDING" if before["review"] in {"REVIEW_PENDING","REVIEWING"} else "NOT_REQUIRED",scheduler_generation=before["scheduler_generation"]+1,dispatch_generation=before["dispatch_generation"]+1,task_fence=before["task_fence"]+1,active_claim_id=None,reviewer_assignment_id=None)
                        elif operation=="REVALIDATE":
                            require(source in {("GOVERNANCE_BLOCKED","EXECUTION_BLOCKED","NOT_REQUIRED"),("GOVERNANCE_BLOCKED","EXECUTION_BLOCKED","REVIEW_PENDING")},"invalid revalidation transition")
                            expected=advanced(before,workflow="ACTIVE",execution="CLAIMABLE" if before["review"]=="NOT_REQUIRED" else "EXECUTION_COMPLETED",scheduler_generation=before["scheduler_generation"]+1)
                        elif operation=="ASSIGN_REVIEW":
                            require(source==("ACTIVE","EXECUTION_COMPLETED","REVIEW_PENDING") and isinstance(request.get("actor"),str) and bool(request["actor"]) and isinstance(request.get("role"),str) and bool(request["role"]) and request["actor"]!=expected_metadata[task_id]["owner"] and request["role"]!="owner" and isinstance(after["reviewer_assignment_id"],str),"invalid review assignment")
                            expected=advanced(before,review="REVIEWING",scheduler_generation=before["scheduler_generation"]+1,reviewer_assignment_id=after["reviewer_assignment_id"])
                            require(after["reviewer_assignment_id"] not in expected_reviews,"duplicate review assignment")
                            expected_reviews[after["reviewer_assignment_id"]]={"assignment_id":after["reviewer_assignment_id"],"task_id":task_id,"actor":request["actor"],"role":request["role"],"status":"ACTIVE"}
                        elif operation in {"APPROVE","REJECT","REMEDIATE"}:
                            require(source==("ACTIVE","EXECUTION_COMPLETED","REVIEWING") and isinstance(request.get("reviewer_id"),str) and request["reviewer_id"]==before["reviewer_assignment_id"] and is_sha256(request.get("decision_digest")),"invalid review decision")
                            review={"APPROVE":"APPROVED","REJECT":"REJECTED","REMEDIATE":"REMEDIATION_REQUIRED"}[operation]
                            close_review(expected_reviews,before,review)
                            expected=advanced(before,review=review,scheduler_generation=before["scheduler_generation"]+1,reviewer_assignment_id=None)
                            if operation in {"REJECT","REMEDIATE"}: remediation_decisions[task_id]=request["decision_digest"]
                        else:
                            require(operation=="ROUTE" and source==("ACTIVE","EXECUTION_COMPLETED","APPROVED") and isinstance(request.get("routing_evidence"),str) and bool(request["routing_evidence"]),"invalid director route")
                            expected=advanced(before,workflow="DIRECTOR_GATE_READY",scheduler_generation=before["scheduler_generation"]+1)
                        require(after==expected,"invalid task event delta")
                previous=after; pd=row["event_digest"]
            if previous != self.tuple(task): raise RuntimeUnavailable("replay/materialized tuple mismatch")
            metadata=expected_metadata[task_id]
            if task["owner"]!=metadata["owner"] or task["reviewer"] is not None or task["predecessor_task"]!=metadata["predecessor_task"] or task["successor_task"]!=metadata["successor_task"]: raise RuntimeUnavailable("task metadata replay mismatch")

        actual_attempts={(row["task_id"],row["attempt"]):dict(row) for row in c.execute("SELECT * FROM attempts")}
        if actual_attempts!=expected_attempts: raise RuntimeUnavailable("attempt replay mismatch")
        actual_claims={row["claim_id"]:dict(row) for row in c.execute("SELECT * FROM claims")}
        if actual_claims!=expected_claims: raise RuntimeUnavailable("claim replay mismatch")
        actual_reviews={row["assignment_id"]:dict(row) for row in c.execute("SELECT * FROM reviews")}
        if actual_reviews!=expected_reviews: raise RuntimeUnavailable("review replay mismatch")

        require(set(remediation_sources)==set(remediation_children),"remediation reciprocal mismatch")
        expected_links: dict[str,dict[str,Any]]={}
        for link_id,source in remediation_sources.items():
            child=remediation_children[link_id]
            require(source["child"]==child["task_id"] and child["parent"]==source["task_id"] and child["parent_attempt"]==source["attempt"] and child["decision"]==source["decision"],"remediation reciprocal mismatch")
            require(child["owner"]==source["child_owner"] and child["receipt_digest"]==source["child_receipt_digest"] and child["global_seq"]==source["global_seq"]+1,"remediation child metadata mismatch")
            material={"link_id":link_id,"source_task":source["task_id"],"child_task":child["task_id"],"source_event":source["event_id"],"child_event":child["event_id"],"decision_digest":source["decision"]}
            expected_links[link_id]={**material,"link_digest":digest(material)}
        actual_links={row["link_id"]:dict(row) for row in c.execute("SELECT * FROM remediation_links")}
        if actual_links!=expected_links: raise RuntimeUnavailable("remediation link mismatch")

        # A lineage is a set of one-way parent/child edges, never a self-link or cycle.
        for task_id in tasks:
            seen:set[str]=set(); cursor=task_id
            while cursor is not None:
                require(cursor not in seen,"remediation lineage cycle")
                seen.add(cursor)
                cursor=expected_metadata[cursor]["successor_task"] if cursor in expected_metadata else None

    def import_repository(self, affected: list[str], reason: str="IMPORT") -> None:
        if not isinstance(affected,list) or any(not isinstance(task_id,str) or not task_id for task_id in affected) or not isinstance(reason,str) or not reason: raise RuntimeUnavailable("invalid repository import binding")
        with self.locked("import"):
            b=self.bundle(); c=self.connect()
            try:
                c.execute("BEGIN IMMEDIATE"); self._verify(c); old=self._meta(c,"repository_generation"); prior=self._meta(c,"bundle_digest")
                if b.digest==prior: c.rollback(); return
                if len(affected) != len(set(affected)): raise RuntimeUnavailable("duplicate affected task")
                importable={("ACTIVE","CLAIMABLE","NOT_REQUIRED"),("ACTIVE","CLAIMED","NOT_REQUIRED"),("ACTIVE","IN_PROGRESS","NOT_REQUIRED"),("ACTIVE","EXECUTION_COMPLETED","REVIEW_PENDING"),("ACTIVE","EXECUTION_COMPLETED","REVIEWING")}
                for tid in affected:
                    candidate=c.execute("SELECT * FROM tasks WHERE task_id=?",(tid,)).fetchone()
                    if not candidate: raise RuntimeUnavailable("unknown affected task")
                    if (candidate["workflow"],candidate["execution"],candidate["review"]) not in importable: raise RuntimeUnavailable("invalid repository transition scope")
                new=old+1; self._set(c,"repository_generation",new)
                self._set(c,"bundle_digest",b.digest)
                for tid in affected:
                    row=c.execute("SELECT * FROM tasks WHERE task_id=?",(tid,)).fetchone()
                    before=self.tuple(row)
                    if (row["workflow"],row["execution"],row["review"]) in {( "ACTIVE","CLAIMABLE","NOT_REQUIRED")}:
                        c.execute("UPDATE tasks SET scheduler_generation=scheduler_generation+1,repository_generation=? WHERE task_id=?",(new,tid))
                    else:
                        if row["claim_id"] is not None: c.execute("UPDATE claims SET status='GOVERNANCE_BLOCKED' WHERE claim_id=?",(row["claim_id"],))
                        if row["reviewer_id"] is not None: c.execute("UPDATE reviews SET status='GOVERNANCE_BLOCKED' WHERE assignment_id=?",(row["reviewer_id"],))
                        c.execute("UPDATE tasks SET workflow='GOVERNANCE_BLOCKED',execution='EXECUTION_BLOCKED',review=?,claim_id=NULL,reviewer_id=NULL,scheduler_generation=scheduler_generation+1,dispatch_generation=dispatch_generation+1,task_fence=task_fence+1,repository_generation=? WHERE task_id=?",("REVIEW_PENDING" if row["review"] in {"REVIEW_PENDING","REVIEWING"} else "NOT_REQUIRED",new,tid))
                    updated=c.execute("SELECT * FROM tasks WHERE task_id=?",(tid,)).fetchone()
                    self._task_event(
                        c,
                        updated,
                        before,
                        self.tuple(updated),
                        "REPOSITORY_GENERATION_APPLIED",
                        {"old":old,"new":new,"task_old":before["repository_generation"],"bundle":b.digest,"source_commit":b.commit,"reason":reason},
                    )
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
