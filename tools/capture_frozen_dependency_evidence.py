#!/usr/bin/env python3
"""Planning-only authentic dependency capture from frozen Stage 1."""
import json,hashlib,shutil,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; F=Path('/tmp/edgelab-stage1-freeze')
def w(p,x): p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(x,separators=(',',':')))
def make(name,bad=False):
 d=ROOT/'tests/fixtures/authentic-stage1-dependency'/name;shutil.rmtree(d,ignore_errors=True);r=d/'repository';shutil.copytree(F,r,ignore=shutil.ignore_patterns('.git','__pycache__'));(r/'docs/handoffs/H-M0-038.v3.json').unlink()
 def j(p):return json.loads(p.read_text())
 b=j(r/'orchestration/tasks/T-SYNTHETIC-001.v1.json');dep=dict(b,task_id='T-DEP-001',status='COMPLETED',dependencies=[],completion_evidence=['orchestration/completions/T-DEP-001.v1.json']);pri=dict(b,task_id='T-PRIMARY-001',dependencies=['T-DEP-001']);w(r/'orchestration/tasks/T-DEP-001.v1.json',dep);w(r/'orchestration/tasks/T-PRIMARY-001.v1.json',pri)
 h=hashlib.sha256((r/'orchestration/tasks/T-DEP-001.v1.json').read_bytes()).hexdigest();c={'schema_version':1,'task_id':'T-DEP-001','attempt':1,'task_ref':'orchestration/tasks/T-DEP-001.v1.json','status':'COMPLETED','content_sha256':'0'*64 if bad else h};w(r/'orchestration/completions/T-DEP-001.v1.json',c)
 for stem in ('assignments','handoff-bindings'):
  p=r/'orchestration'/stem/'T-SYNTHETIC-001.v1.json';x=j(p);x['task_id']='T-PRIMARY-001';w(r/'orchestration'/stem/'T-PRIMARY-001.v1.json',x)
 s=j(r/'orchestration/scheduler-state.json');s['tasks']={'T-PRIMARY-001':'orchestration/tasks/T-PRIMARY-001.v1.json','T-DEP-001':'orchestration/tasks/T-DEP-001.v1.json'};s['claims']={'T-PRIMARY-001':{'role':'00 Director','attempt':1,'status':'ACTIVE','handoff_ref':'docs/handoffs/H-M0-038.v2.json','generation':1}};w(r/'orchestration/scheduler-state.json',s)
 for a in [['git','init','-q',str(r)],['git','-C',str(r),'config','user.email','capture@example.invalid'],['git','-C',str(r),'config','user.name','capture'],['git','-C',str(r),'add','.'],['git','-C',str(r),'commit','-qm','capture'],['git','-C',str(r),'remote','add','origin','https://github.com/dylanlaewe/EdgeLab.git'],['git','-C',str(r),'update-ref','refs/remotes/origin/main','HEAD']]:subprocess.run(a,check=True)
 sys.path.insert(0,str(r/'src'));[sys.modules.pop(k) for k in list(sys.modules) if k=='edgelab' or k.startswith('edgelab.')];from edgelab.orchestration import decision
 out=decision(r,{'task_id':'T-PRIMARY-001','attempt':1});(d/'capture.json').write_text(json.dumps({'freeze_commit':'bc3a40924ca580ca6eddc4c24e32ff99ddd95330','intent':{'task_id':'T-PRIMARY-001','attempt':1},'result':out,'dependency_task_sha256':h,'completion':c},indent=2));shutil.rmtree(r/'.git');[shutil.rmtree(p) for p in r.rglob('__pycache__')]
for n,b in [('satisfied',False),('content-sha-denied',True)]:make(n,b)
