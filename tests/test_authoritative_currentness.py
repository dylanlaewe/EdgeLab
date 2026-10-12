import copy,json,tempfile
from pathlib import Path
from tools.resolve_authoritative_currentness import resolve_and_verify_currentness
from tests.test_currentness_reference import B
def source(s=B):
 d=tempfile.TemporaryDirectory();p=Path(d.name); repo=copy.deepcopy(s); runtime={'attachment_repository_id':'repo','runtime':repo.pop('runtime'),'claim':repo.pop('claim'),'generations':{k:repo['generations'][k] for k in ['runtime','scheduler','dispatch','claim','fence']},'generation':1};(p/'repository.json').write_text(json.dumps(repo));(p/'runtime.json').write_text(json.dumps(runtime));return d,p
def v(p):return resolve_and_verify_currentness('HISTORICALLY_VALID',B,p)
def test_positive_and_drifts():
 d,p=source();assert v(p)['authorization']=='ALLOW'; r=json.loads((p/'repository.json').read_text());r['assignment']['head']='x';(p/'repository.json').write_text(json.dumps(r));assert v(p)['currentness_status']=='STALE';d.cleanup()
def test_attachment_missing_race():
 d,p=source();r=json.loads((p/'runtime.json').read_text());r['attachment_repository_id']='bad';(p/'runtime.json').write_text(json.dumps(r));assert v(p)['currentness_status']=='INCOMPATIBLE';(p/'repository.json').unlink();assert v(p)['currentness_status']=='INVALID_CURRENT_STATE';d.cleanup()
