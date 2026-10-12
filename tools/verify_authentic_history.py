#!/usr/bin/env python3
"""Planning reference composed historical verifier; no operational effects."""
import copy,hashlib,json,platform,sys
from pathlib import Path
from tools.generate_persisted_authentic_capture import generate,cj
from tools.reconstruct_persisted_history import reconstruct
from tools.verify_trusted_authentic_capture import verify as trusted
ROOT=Path(__file__).resolve().parents[1]
def result(status,reasons,capture_id='UNKNOWN',root_id='M0-2-STAGE1-TRUST-ROOT-V1', evidence=None):
 hist='VALID' if status=='HISTORICALLY_VALID' else 'INVALID'; code='NONE' if status=='HISTORICALLY_VALID' else ('INCOMPATIBLE_RUNTIME' if status=='INCOMPATIBLE_RUNTIME' else 'VERIFIER_FAILURE'); return {'schema_version':1,'status':status,'capture_id':capture_id,'trusted_root_id':root_id,'reason_codes':sorted(reasons),'authorization_result':{'historical_status':hist,'currentness_status':'UNKNOWN','runtime_compatible':status!='INCOMPATIBLE_RUNTIME','verifier_status':'PASS' if status=='HISTORICALLY_VALID' else 'FAIL','generation_match':True,'authorizing_use':'DENY','reason_code':code},'replay':{'completed':status=='HISTORICALLY_VALID','raw_result_match':status=='HISTORICALLY_VALID'},'evidence':(evidence if evidence is not None else {'frozen_commit':'unknown','replay_root':'unavailable','raw_result_sha256':'','decision_id':None,'module_origins':[],'schema_origins':[],'package_origins':observed['packages'],'python':{},'git':{},'environment_sha256':''})}
def verify_authentic_history(capture_root,trusted_root=ROOT/'docs/M0.2_STAGE1_TRUST_ROOT.v1.json'):
 root=Path(capture_root); cap0=json.loads((root/'authentic-capture.v1.json').read_text()); cid=cap0['capture_id']; tr=json.loads(Path(trusted_root).read_text()); graph=generate(root)
 # every graph blob is reconstructable before authority checks
 try:
  _d,_r=reconstruct(graph); _d.cleanup()
 except Exception:return result('INVALID',['PERSISTED_BLOB_INVALID'])
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
 try:
  actual, evidence=replay_reconstructed(graph,cap['intent'])
 except Exception:return result('INVALID',['RECONSTRUCTED_REPLAY_FAILED'])
 if actual!=cap['result']:return result('INVALID',['RECONSTRUCTED_RESULT_MISMATCH'])
 return result('HISTORICALLY_VALID',[],cid,tr['root_id'],evidence)
if __name__=='__main__':print(json.dumps(verify_authentic_history(__import__('sys').argv[1]),sort_keys=True))

def replay_reconstructed(graph, intent):
 """Execute only modules reconstructed from persisted bytes."""
 import os,subprocess,sys,json
 from pathlib import Path
 d,root=reconstruct(graph)
 try:
  repo=root/'repository'; packages=[str(p) for p in (root/'packages').iterdir()]
  for cmd in (['git','init','-q',str(repo)],['git','-C',str(repo),'config','user.email','replay@example.invalid'],['git','-C',str(repo),'config','user.name','replay'],['git','-C',str(repo),'add','.'],['git','-C',str(repo),'commit','-qm','replay'],['git','-C',str(repo),'remote','add','origin','https://github.com/dylanlaewe/EdgeLab.git'],['git','-C',str(repo),'update-ref','refs/remotes/origin/main','HEAD']): subprocess.run(cmd,check=True)
  code = '''from pathlib import Path
import json
import edgelab.orchestration as orchestration
import edgelab.validate as validate
import jsonschema
SCHEMAS=[str(p.resolve()) for p in (Path('repository')/'schemas').glob('*.json')]
result = orchestration.decision(Path("repository"), json.loads(INTENT))
print(json.dumps({"result": result, "modules": {"edgelab.orchestration": orchestration.__file__, "edgelab.validate": validate.__file__}, "schemas": SCHEMAS, "packages": [str(Path(jsonschema.__file__).resolve())]}, sort_keys=True))'''.replace('INTENT', repr(json.dumps(intent)))
  env={'PYTHONDONTWRITEBYTECODE':'1','PYTHONHASHSEED':'0','LC_ALL':'C.UTF-8','TZ':'UTC','PYTHONIOENCODING':'utf-8','PYTHONPATH':os.pathsep.join([str(repo/'src'),*packages]),'PATH':os.environ.get('PATH','')}
  out=subprocess.check_output([sys.executable,'-S','-c',code],cwd=root,env=env,text=True)
  observed=json.loads(out); module_paths=observed['modules']; root_real=root.resolve();
  if any(not Path(path).resolve().is_relative_to(root_real) for path in module_paths.values()): raise RuntimeError('ambient module origin')
  evidence={'frozen_commit':graph['git']['freeze_commit'],'replay_root':str(root_real),'raw_result_sha256':hashlib.sha256(cj(observed['result']).encode()).hexdigest(),'decision_id':observed['result'].get('decision_id'),'module_origins':[f'{name}:{Path(path).resolve()}' for name,path in sorted(module_paths.items())],'schema_origins':observed['schemas'],'package_origins':observed['packages'],'python':{},'git':{},'environment_sha256':hashlib.sha256(cj(env).encode()).hexdigest()}
  return observed['result'],evidence
 finally:d.cleanup()
