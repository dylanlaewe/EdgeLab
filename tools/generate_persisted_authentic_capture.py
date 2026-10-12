#!/usr/bin/env python3
import hashlib,json
from pathlib import Path
def h(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def cj(x):return json.dumps(x,sort_keys=True,separators=(',',':'))
def generate(root):
 root=Path(root);c=json.loads((root/'authentic-capture.v1.json').read_text()); arts=[];blobs=[];dirs=[]
 for base in ['repository','packages']:
  d=root/base; members=[]
  for p in sorted(d.rglob('*')):
   if p.is_file():
    rel=str(p.relative_to(root)); dig=h(p);aid='FILE:'+rel;arts.append({'id':aid,'path':rel,'blob_id':'B:'+dig});blobs.append({'id':'B:'+dig,'sha256':dig});members.append(aid)
  dirs.append({'id':'DIRECTORY:'+base,'path':base,'members':members,'sha256':hashlib.sha256(cj(members).encode()).hexdigest()})
 g={'schema_version':1,'trusted_root_id':c['trusted_root_id'],'capture_id':c['capture_id'],'artifacts':arts,'blobs':blobs,'directories':dirs,'source_manifest':[a['id'] for a in arts if a['path'].startswith('repository/')],'packages':c['packages'],'git':{'freeze_commit':c['freeze_commit']},'raw_result':{'canonical_json':cj(c['result']),'sha256':hashlib.sha256(cj(c['result']).encode()).hexdigest()},'self_sha256':''};g['self_sha256']=hashlib.sha256(cj({k:v for k,v in g.items() if k!='self_sha256'}).encode()).hexdigest();return g
if __name__=='__main__':print(json.dumps(generate(__import__('sys').argv[1]),sort_keys=True))
