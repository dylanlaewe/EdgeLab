import json,shutil,tempfile
from pathlib import Path
from tools.verify_authentic_history import verify_authentic_history
ROOT=Path(__file__).parents[1]; F=ROOT/'tests/fixtures/authentic-stage1/dispatch'
def clone():
 d=tempfile.TemporaryDirectory();p=Path(d.name)/'x';shutil.copytree(F,p);return d,p
def test_baselines():
 for p in [F,ROOT/'tests/fixtures/authentic-stage1/deny',ROOT/'tests/fixtures/authentic-stage1-dependency/satisfied',ROOT/'tests/fixtures/authentic-stage1-dependency/content-sha-denied']:assert verify_authentic_history(p)['status']=='HISTORICALLY_VALID'
def test_forgery_families():
 for path in ['repository/src/edgelab/orchestration.py','repository/schemas/scheduler-state.schema.json','packages/jsonschema/jsonschema/_types.py']:
  d,p=clone();q=p/path;q.write_text(q.read_text()+'\n#forge');assert verify_authentic_history(p)['authorization']=='DENY';d.cleanup()
def test_closure_and_identity():
 d,p=clone();x=json.load(open(p/'authentic-capture.v1.json'));x['freeze_commit']='0'*40;open(p/'authentic-capture.v1.json','w').write(json.dumps(x));assert verify_authentic_history(p)['authorization']=='DENY';d.cleanup()
 d,p=clone();x=json.load(open(p/'authentic-capture.v1.json'));x['packages']=x['packages'][:-1];open(p/'authentic-capture.v1.json','w').write(json.dumps(x));assert verify_authentic_history(p)['authorization']=='DENY';d.cleanup()
