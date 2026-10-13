import unittest
from pathlib import Path
from tools.verify_authentic_history import verify_authentic_history,ROOT
class ReconstructedModuleOrigins(unittest.TestCase):
 def test_dispatch_origins_are_reconstructed(self):
  r=verify_authentic_history(ROOT/'tests/fixtures/authentic-stage1/dispatch')
  self.assertEqual(r['status'],'HISTORICALLY_VALID')
  origins=r['evidence']['module_origins'];self.assertTrue(origins)
  self.assertTrue(any(x.startswith('edgelab.orchestration:') for x in origins))
  for item in origins:
   _,relative,digest=item.split(':',2)
   self.assertTrue(relative.startswith('repository/src/edgelab/'))
   self.assertEqual(len(digest),64)
  self.assertTrue(r['evidence']['replay_root'].startswith('persisted-graph:'))
  self.assertEqual(r['authorization_result']['authorizing_use'],'DENY')
