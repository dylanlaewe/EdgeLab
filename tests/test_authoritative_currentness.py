import copy,json,tempfile,unittest
from pathlib import Path
from tools.resolve_authoritative_currentness import resolve_and_verify_currentness
from tests.test_currentness_reference import B
REQ={'historical_status','currentness_status','runtime_compatible','verifier_status','generation_match','authorizing_use','reason_code'}
def source():
 d=tempfile.TemporaryDirectory();p=Path(d.name);r=copy.deepcopy(B);m={'attachment_repository_id':'repo','runtime':r.pop('runtime'),'claim':r.pop('claim'),'generations':{k:r['generations'][k] for k in ['runtime','scheduler','dispatch','claim','fence']},'generation':1};(p/'repository.json').write_text(json.dumps(r));(p/'runtime.json').write_text(json.dumps(m));return d,p
def verify(p):return resolve_and_verify_currentness('HISTORICALLY_VALID',B,p)
class Currentness(unittest.TestCase):
 def check(self,kind,key=None,val=None):
  d,p=source()
  if kind=='repo':x=json.loads((p/'repository.json').read_text());o=x
  else:x=json.loads((p/'runtime.json').read_text());o=x
  for k in key[:-1]:o=o[k]
  o[key[-1]]=val;(p/('repository.json' if kind=='repo' else 'runtime.json')).write_text(json.dumps(x));r=verify(p);self.assertEqual(set(r),REQ);self.assertEqual(r['authorizing_use'],'DENY');d.cleanup();return r
 def test_current(self):d,p=source();self.assertEqual(verify(p)['authorizing_use'],'ALLOW');d.cleanup()
 def test_repo_drifts(self):
  for key,val in [(('assignment','head'),'x'),(('handoff','head'),'x'),(('project','head'),'x'),(('stops',),[{'id':'S','head':'OPEN','generation':1}]),(('capabilities',),[{'id':'C','head':'DENY','generation':1}]),(('dependencies',),[{'id':'D','head':'x','generation':1}]),(('git','head'),'1'*40),(('generations','repository'),2),(('generations','assignment'),2),(('generations','handoff'),2)]:self.check('repo',key,val)
 def test_runtime_drifts(self):
  for key,val in [(('claim','id'),'x'),(('claim','fence'),2),(('generations','runtime'),2),(('generations','scheduler'),2),(('generations','dispatch'),2),(('generations','claim'),2),(('generations','fence'),2)]:self.check('runtime',key,val)
 def test_attachment_and_missing(self):
  self.check('runtime',('attachment_repository_id',),'other');d,p=source();(p/'repository.json').unlink();self.assertEqual(verify(p)['currentness_status'],'UNKNOWN');d.cleanup()
 # edge authority cases
 def test_conflict_and_race_and_multi(self):
  d,p=source(); r=json.loads((p/'runtime.json').read_text());r['attachment_repository_id']='conflict-repository';(p/'runtime.json').write_text(json.dumps(r));self.assertEqual(verify(p)['authorizing_use'],'DENY');d.cleanup()
  d,p=source();r=json.loads((p/'runtime.json').read_text());r['generation']=2;(p/'race-runtime.json').write_text(json.dumps(r));self.assertEqual(verify(p)['authorizing_use'],'DENY');d.cleanup()
  d,p=source();r=json.loads((p/'repository.json').read_text());r['assignment']['head']='changed';r['stops']=[{'id':'S','head':'OPEN','generation':1}];(p/'repository.json').write_text(json.dumps(r));m=json.loads((p/'runtime.json').read_text());m['generations']['runtime']=2;(p/'runtime.json').write_text(json.dumps(m));a=verify(p);b=verify(p);self.assertEqual(a,b);self.assertEqual(a['authorizing_use'],'DENY');d.cleanup()
