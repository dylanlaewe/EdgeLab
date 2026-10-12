#!/usr/bin/env python3
"""Planning-only closed currentness resolver; no scheduler effects."""
import copy, hashlib, json
def cj(x): return json.dumps(x,sort_keys=True,separators=(',',':'))
def digest(s):
 x=copy.deepcopy(s);x.pop('currentness_snapshot_sha256',None);return hashlib.sha256(cj(x).encode()).hexdigest()
def resolve(authority):
 if authority.get('conflict'): return None,'INVALID_CURRENT_STATE',['CONFLICTING_AUTHORITY']
 if authority.get('race'): return None,'INVALID_CURRENT_STATE',['GENERATION_RACE']
 s=copy.deepcopy(authority['snapshot'])
 if authority.get('missing'): return None,'INVALID_CURRENT_STATE',['MISSING_'+authority['missing']]
 s['currentness_snapshot_sha256']=digest(s);return s,None,[]
def verify(historical_status,binding,authority):
 if historical_status!='HISTORICALLY_VALID': return {'historical_status':historical_status,'currentness_status':'INVALID','authorization':'DENY','changed_dimensions':['HISTORICAL_INVALID']}
 s,status,changes=resolve(authority)
 if status:return {'historical_status':'HISTORICALLY_VALID','currentness_status':status,'authorization':'DENY','changed_dimensions':changes}
 if s['currentness_snapshot_sha256']!=digest(s):return {'historical_status':'HISTORICALLY_VALID','currentness_status':'INVALID_CURRENT_STATE','authorization':'DENY','changed_dimensions':['SNAPSHOT_DIGEST_INVALID']}
 changes=[]; incompatible=[]
 def walk(a,b,p=''):
  if isinstance(a,dict):
   for k in sorted(set(a)|set(b)):
    if k=='currentness_snapshot_sha256':continue
    walk(a.get(k),b.get(k),k if not p else p+'.'+k)
  elif a!=b: changes.append(p)
 walk(binding,s)
 for x in changes:
  if x.startswith(('repository.id','runtime.id')): incompatible.append(x)
 return {'historical_status':'HISTORICALLY_VALID','currentness_status':'INCOMPATIBLE' if incompatible else ('STALE' if changes else 'CURRENT'),'runtime_compatible':not bool(incompatible),'authorization':'DENY' if changes else 'ALLOW','changed_dimensions':sorted(changes),'snapshot_digest':s['currentness_snapshot_sha256']}
