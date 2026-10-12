#!/usr/bin/env python3
"""Create planning-only, authentic frozen M0.2 capture packages.

The copied repository contains unmodified bytes from the frozen commit.  Only the
bounded synthetic scheduler records are adjusted to select an actual frozen outcome.
No task is executed beyond M0.2's MOCK_ONLY preflight.
"""
from __future__ import annotations
import hashlib, importlib.metadata, json, shutil, subprocess, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
FREEZE='bc3a40924ca580ca6eddc4c24e32ff99ddd95330'
FREEZE_TREE=Path('/tmp/edgelab-stage1-freeze')
PACKAGES=('jsonschema','jsonschema-specifications','attrs','referencing','rpds-py')
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def setup(dest:Path, deny:bool):
    if dest.exists(): shutil.rmtree(dest)
    repo=dest/'repository'; shutil.copytree(FREEZE_TREE,repo,ignore=shutil.ignore_patterns('.git','__pycache__','.pytest_cache'))
    # v3 supersedes the otherwise active v2 claim. Removing it is the bounded
    # synthetic fixture state that makes v2 the exact selected frozen handoff.
    (repo/'docs/handoffs/H-M0-038.v3.json').unlink()
    if deny:
        stop=repo/'reports/stops/STOP-M0-001.v1.json'; record=json.loads(stop.read_text()); record['status']='RESOLVED'; stop.write_text(json.dumps(record,sort_keys=True,separators=(',',':'))+'\n')
        state=repo/'orchestration/scheduler-state.json'; s=json.loads(state.read_text()); s['stops'][0]['sha256']=sha(stop); state.write_text(json.dumps(s,sort_keys=True,separators=(',',':'))+'\n')
    subprocess.run(['git','init','-q',str(repo)],check=True); subprocess.run(['git','-C',str(repo),'config','user.email','fixture@example.invalid'],check=True);subprocess.run(['git','-C',str(repo),'config','user.name','fixture'],check=True);subprocess.run(['git','-C',str(repo),'add','.'],check=True);subprocess.run(['git','-C',str(repo),'commit','-qm','frozen-stage1-capture'],check=True);subprocess.run(['git','-C',str(repo),'remote','add','origin','https://github.com/dylanlaewe/EdgeLab.git'],check=True);subprocess.run(['git','-C',str(repo),'update-ref','refs/remotes/origin/main','HEAD'],check=True)
    return repo
def snapshot_packages(dest:Path):
    """Retain executable package/resource bytes, never virtualenv administration."""
    target=dest/'packages'; target.mkdir()
    roots={'jsonschema':['jsonschema'],'jsonschema-specifications':['jsonschema_specifications'],'attrs':['attr','attrs'],'referencing':['referencing'],'rpds-py':['rpds']}
    records=[]
    for name in PACKAGES:
        dist=importlib.metadata.distribution(name); d=target/name; d.mkdir()
        base=Path(dist.locate_file('.'))
        for root in roots[name]:
            src=base/root
            if src.exists():
                shutil.copytree(src,d/root,ignore=shutil.ignore_patterns('__pycache__','*.pyc','.git','.pytest_cache'))
        records.append({'name':name,'version':dist.version,'path':str(d.relative_to(dest)),'files_sha256':hashlib.sha256(b''.join(sorted((str(x.relative_to(d))+':'+sha(x)).encode() for x in d.rglob('*') if x.is_file()))).hexdigest(),'identity':'extracted-replay-tree'})
    return records
def capture(name,deny):
    dest=ROOT/'tests/fixtures/authentic-stage1'/name;repo=setup(dest,deny); packages=snapshot_packages(dest)
    sys.path.insert(0,str(repo/'src'))
    for k in list(sys.modules):
        if k=='edgelab' or k.startswith('edgelab.'): del sys.modules[k]
    from edgelab.orchestration import decision
    result=decision(repo,{'task_id':'T-SYNTHETIC-001','attempt':1})
    for cache in repo.rglob('__pycache__'): shutil.rmtree(cache)
    manifest={'format':1,'kind':'authentic-frozen-stage1-capture','freeze_commit':FREEZE,'fixture_kind':name,'repository':'repository','head':subprocess.check_output(['git','-C',str(repo),'rev-parse','HEAD'],text=True).strip(),'origin_main':subprocess.check_output(['git','-C',str(repo),'rev-parse','origin/main'],text=True).strip(),'entrypoint':'edgelab.orchestration.decision','intent':{'task_id':'T-SYNTHETIC-001','attempt':1},'result':result,'packages':packages,'repository_inventory_sha256':hashlib.sha256(b''.join(sorted((str(p.relative_to(repo))+':'+sha(p)).encode() for p in repo.rglob('*') if p.is_file() and '.git' not in p.parts and '__pycache__' not in p.parts))).hexdigest()}
    (dest/'capture.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
    shutil.rmtree(repo / '.git')
for name,deny in [('dispatch',False),('deny',True)]: capture(name,deny)
