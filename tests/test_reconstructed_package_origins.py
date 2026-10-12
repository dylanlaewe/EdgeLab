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
   origin=Path(next(x for x in origins if '/jsonschema/' in x)).resolve()
   replay_root=Path(r['evidence']['replay_root']).resolve()
   self.assertTrue(origin.is_relative_to(replay_root/'packages'))
   self.assertFalse(origin.is_relative_to(ROOT));self.assertFalse(origin.is_relative_to(Path(d)))
   self.assertEqual(r['authorization_result']['authorizing_use'],'DENY')
   self.assertEqual(r['authorization_result']['currentness_status'],'UNKNOWN')
