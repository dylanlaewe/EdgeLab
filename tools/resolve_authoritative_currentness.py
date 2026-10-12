#!/usr/bin/env python3
"""Planning-only resolver. Reads authoritative JSON records under source root."""
import copy,hashlib,json
from pathlib import Path
from tools.verify_currentness_reference import verify,digest
def load(root,name):
 p=Path(root)/name
 if not p.exists():raise FileNotFoundError(name)
 return json.loads(p.read_text())
def resolve_and_verify_currentness(historical_status,binding,source_root):
 try:
  meta=load(source_root,'runtime.json'); repo=load(source_root,'repository.json')
  if meta['attachment_repository_id']!=repo['repository']['id']:return {'schema_version':3,'historical_status':historical_status,'currentness_status':'INCOMPATIBLE','runtime_compatible':False,'authorization':'DENY','reason_codes':['RUNTIME_ATTACHMENT_MISMATCH'],'changed_dimensions':[]}
  before=meta['generation']; s=copy.deepcopy(repo);s['runtime']=meta['runtime'];s['claim']=meta['claim'];s['generations'].update(meta['generations']);s['currentness_snapshot_sha256']=digest(s)
  after=load(source_root,'runtime.json')['generation']
  if before!=after:return {'schema_version':3,'historical_status':historical_status,'currentness_status':'INVALID_CURRENT_STATE','runtime_compatible':False,'authorization':'DENY','reason_codes':['GENERATION_RACE'],'changed_dimensions':[]}
  r=verify(historical_status,binding,{'snapshot':s});r.update(schema_version=3,reason_codes=r.pop('changed_dimensions',[]));r['changed_dimensions']=r['reason_codes'];return r
 except (FileNotFoundError,KeyError,ValueError) as e:return {'schema_version':3,'historical_status':historical_status,'currentness_status':'INVALID_CURRENT_STATE','runtime_compatible':False,'authorization':'DENY','reason_codes':['MISSING_OR_CONFLICTING_AUTHORITY'],'changed_dimensions':[]}
