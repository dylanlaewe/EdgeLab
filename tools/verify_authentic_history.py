#!/usr/bin/env python3
"""Planning reference composed historical verifier; no operational effects."""
import copy,hashlib,json,platform,sys
from pathlib import Path
from tools.generate_persisted_authentic_capture import generate,cj
from tools.verify_trusted_authentic_capture import verify as trusted
ROOT=Path(__file__).resolve().parents[1]
def result(status,reasons):return {'schema_version':3,'verification_kind':'HISTORICAL','status':status,'authorization':'ALLOW' if status=='HISTORICALLY_VALID' else 'DENY','reason_codes':sorted(reasons)}
def verify_authentic_history(capture_root,trusted_root=ROOT/'docs/M0.2_STAGE1_TRUST_ROOT.v1.json'):
 root=Path(capture_root); tr=json.loads(Path(trusted_root).read_text()); graph=generate(root)
 if graph['self_sha256']!=hashlib.sha256(cj({k:v for k,v in graph.items() if k!='self_sha256'}).encode()).hexdigest():return result('INVALID',['GRAPH_DIGEST_INVALID'])
 ids=[x['id'] for x in graph['artifacts']]
 if len(ids)!=len(set(ids)):return result('INVALID',['DUPLICATE_ARTIFACT_ID'])
 cap=json.loads((root/'authentic-capture.v1.json').read_text())
 if cap['freeze_commit']!=tr['freeze_commit'] or cap['trusted_root_id']!=tr['root_id']:return result('INVALID',['TRUST_ROOT_MISMATCH'])
 # trusted verifier anchors modules/schemas and package bytes/uniqueness
 x=trusted(root)
 if x!='HISTORICALLY_VALID':return result('INVALID',[x])
 expected={(p['name'],p['version']) for p in json.loads((ROOT/'tests/fixtures/authentic-stage1/dispatch/authentic-capture.v1.json').read_text())['packages']}
 actual={(p['name'],p['version']) for p in cap['packages']}
 if actual!=expected:return result('INVALID',['PACKAGE_CLOSURE_MISMATCH'])
 hb=tr['host_boundary']
 if platform.python_implementation()!=hb['python_implementation'] or not sys.version.startswith(hb['python_major_minor']+'.'):return result('INCOMPATIBLE',['RUNTIME_INCOMPATIBLE'])
 if cap['result']!=json.loads(graph['raw_result']['canonical_json']):return result('INVALID',['RAW_RESULT_MISMATCH'])
 return result('HISTORICALLY_VALID',[])
if __name__=='__main__':print(json.dumps(verify_authentic_history(__import__('sys').argv[1]),sort_keys=True))
