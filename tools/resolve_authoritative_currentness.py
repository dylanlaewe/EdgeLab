#!/usr/bin/env python3
"""Planning-only resolver reading only fixture repository/runtime authority."""
import copy,json
from pathlib import Path
from tools.verify_currentness_reference import verify,digest
def load(root,name):
 p=Path(root)/name
 if not p.exists():raise FileNotFoundError(name)
 return json.loads(p.read_text())
def v3(historical,status,compatible,allow,changes):
 return {'historical_status':'VALID' if historical=='HISTORICALLY_VALID' else 'INVALID','currentness_status':{'INVALID_CURRENT_STATE':'UNKNOWN'}.get(status,status),'runtime_compatible':compatible,'verifier_status':'PASS' if allow else 'FAIL','generation_match':not any('generation' in x.lower() or 'RACE' in x for x in changes),'authorizing_use':'ALLOW' if allow else 'DENY','reason_code':'NONE' if allow else ('INCOMPATIBLE_RUNTIME' if status=='INCOMPATIBLE' else ('GENERATION_MISMATCH' if any('generation' in x.lower() or 'RACE' in x for x in changes) else ('HISTORICAL_INVALID' if historical!='HISTORICALLY_VALID' else 'STALE')))}
def resolve_with_trace(historical_status,binding,source_root):
 try:
  meta=load(source_root,'runtime.json');repo=load(source_root,'repository.json')
  if meta['attachment_repository_id']!=repo['repository']['id']:return v3(historical_status,'INCOMPATIBLE',False,False,['RUNTIME_ATTACHMENT_MISMATCH']),['RUNTIME_ATTACHMENT_MISMATCH']
  before=meta['generation'];race=Path(source_root)/'race-runtime.json'
  if race.exists():(Path(source_root)/'runtime.json').write_text(race.read_text())
  s=copy.deepcopy(repo);s['runtime']=meta['runtime'];s['claim']=meta['claim'];s['generations'].update(meta['generations']);s['currentness_snapshot_sha256']=digest(s)
  if before!=load(source_root,'runtime.json')['generation']:return v3(historical_status,'INVALID_CURRENT_STATE',False,False,['GENERATION_RACE']),['GENERATION_RACE']
  r=verify(historical_status,binding,{'snapshot':s});ch=sorted(r.get('changed_dimensions',[]));return v3(historical_status,r['currentness_status'],r.get('runtime_compatible',False),r['authorization']=='ALLOW',ch),ch
 except (FileNotFoundError,KeyError,ValueError):return v3(historical_status,'INVALID_CURRENT_STATE',False,False,['MISSING_OR_CONFLICTING_AUTHORITY']),['MISSING_OR_CONFLICTING_AUTHORITY']
def resolve_and_verify_currentness(historical_status,binding,source_root):return resolve_with_trace(historical_status,binding,source_root)[0]
