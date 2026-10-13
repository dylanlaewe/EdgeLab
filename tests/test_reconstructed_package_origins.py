import os,tempfile,unittest
from pathlib import Path
from tools.verify_authentic_history import ROOT,verify_authentic_history
class ReconstructedPackageOrigins(unittest.TestCase):
 def test_jsonschema_origin_ignores_ambient_sentinel(self):
  with tempfile.TemporaryDirectory() as d:
   sentinel=Path(d)/'jsonschema';sentinel.mkdir();(sentinel/'__init__.py').write_text("raise RuntimeError('ambient sentinel imported')\n")
   old=os.environ.get('PYTHONPATH');os.environ['PYTHONPATH']=d
   try:r=verify_authentic_history(ROOT/'tests/fixtures/authentic-stage1/dispatch')
   finally:
    if old is None:os.environ.pop('PYTHONPATH',None)
    else:os.environ['PYTHONPATH']=old
   self.assertEqual(r['status'],'HISTORICALLY_VALID')
   origins=r['evidence']['package_origins'];self.assertTrue(origins)
   _,origin,digest=next(x for x in origins if ':packages/jsonschema/' in x).split(':',2)
   self.assertTrue(origin.startswith('packages/jsonschema/'))
   self.assertEqual(len(digest),64)
   self.assertNotIn(str(ROOT),origin);self.assertNotIn(str(Path(d)),origin)
   self.assertEqual(r['authorization_result']['authorizing_use'],'DENY')
   self.assertEqual(r['authorization_result']['currentness_status'],'UNKNOWN')
