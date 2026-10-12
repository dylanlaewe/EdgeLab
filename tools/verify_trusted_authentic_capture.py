#!/usr/bin/env python3
"""Reference verifier: trusted root precedes mutable capture-local metadata."""
from pathlib import Path
import hashlib,json,sys
ROOT=Path(__file__).resolve().parents[1]
def h(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def verify(fixture):
 root=json.loads((ROOT/'docs/M0.2_STAGE1_TRUST_ROOT.v1.json').read_text()); f=Path(fixture); cap=json.loads((f/'authentic-capture.v1.json').read_text()) if (f/'authentic-capture.v1.json').exists() else json.loads((f/'capture.json').read_text())
 if cap.get('freeze_commit')!=root['freeze_commit']: return 'INVALID: trusted freeze mismatch'
 if cap.get('entrypoint',root['entrypoint'])!=root['entrypoint']: return 'INVALID: entrypoint mismatch'
 repo=f/'repository'
 for rec in root['modules']+root['schemas']:
  p=repo/rec['path']
  if not p.exists() or h(p)!=rec['sha256']: return 'INVALID: trusted root digest mismatch'
 packages=cap.get('packages')
 if not packages: return 'INVALID: missing package closure'
 seen=set()
 for rec in packages:
  k=(rec['name'],rec['version'])
  if k in seen:return 'INVALID: duplicate package identity'
  seen.add(k);p=f/rec['path']
  if not p.exists():return 'INVALID: missing package'
  dig=hashlib.sha256(b''.join(sorted((str(x.relative_to(p))+':'+h(x)).encode() for x in p.rglob('*') if x.is_file()))).hexdigest()
  if dig!=rec['files_sha256']:return 'INVALID: package digest mismatch'
 return 'HISTORICALLY_VALID'
if __name__=='__main__': print(verify(sys.argv[1]))
