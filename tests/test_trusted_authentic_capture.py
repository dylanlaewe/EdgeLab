import copy,json,shutil,tempfile
from pathlib import Path
from tools.verify_trusted_authentic_capture import verify
ROOT=Path(__file__).parents[1]
F=[ROOT/'tests/fixtures/authentic-stage1/dispatch',ROOT/'tests/fixtures/authentic-stage1/deny',ROOT/'tests/fixtures/authentic-stage1-dependency/satisfied',ROOT/'tests/fixtures/authentic-stage1-dependency/content-sha-denied']
def test_original_captures_match_trusted_root():
 for f in F: assert verify(f)=='HISTORICALLY_VALID'
def test_coordinated_forgery_fails_trusted_module_anchor():
 with tempfile.TemporaryDirectory() as d:
  f=Path(d)/'x';shutil.copytree(F[0],f); p=f/'repository/src/edgelab/orchestration.py';p.write_text(p.read_text().replace('repository-resolved','forged-resolved'))
  cap=json.loads((f/'authentic-capture.v1.json').read_text());cap['result']['reason']='forged-resolved synthetic task passed preflight';(f/'authentic-capture.v1.json').write_text(json.dumps(cap))
  assert verify(f)=='INVALID: trusted root digest mismatch'
def test_forged_freeze_identity_fails():
 with tempfile.TemporaryDirectory() as d:
  f=Path(d)/'x';shutil.copytree(F[0],f); cap=json.loads((f/'authentic-capture.v1.json').read_text());cap['freeze_commit']='0'*40;(f/'authentic-capture.v1.json').write_text(json.dumps(cap));assert verify(f)=='INVALID: trusted freeze mismatch'
def test_forged_package_fails():
 with tempfile.TemporaryDirectory() as d:
  f=Path(d)/'x';shutil.copytree(F[0],f);next((f/'packages').rglob('*.py')).write_text('x=1\n');assert verify(f)=='INVALID: package digest mismatch'
