"""Authentic captured frozen Stage 1 evidence: capture is real; replay is offline."""
import json, shutil, subprocess, tempfile, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
class AuthenticStage1Replay(unittest.TestCase):
 def replay(self,name,base=ROOT):
  return subprocess.run([str(ROOT/'.venv/bin/python'),str(base/'tools/replay_frozen_stage1_evidence.py'),name],cwd=base,text=True,capture_output=True)
 def test_actual_frozen_dispatch_replays_exactly(self):
  p=self.replay('dispatch');self.assertEqual(p.returncode,0,p.stderr);r=json.loads(p.stdout);self.assertEqual((r['decision'],r['operation']),('DISPATCH','SYNTHETIC_ASSERT'));self.assertRegex(r['decision_id'],r'^D-[0-9a-f]{32}$')
 def test_actual_frozen_deny_replays_exactly(self):
  p=self.replay('deny');self.assertEqual(p.returncode,0,p.stderr);r=json.loads(p.stdout);self.assertEqual(set(r),{'decision','decision_id','task_id','reason','execution_adapter'});self.assertEqual(r['decision'],'DENY')
 def test_forged_output_and_historical_mutation_fail(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d)/'copy';shutil.copytree(ROOT,root,ignore=shutil.ignore_patterns('.git','.venv','__pycache__'))
   cap=root/'tests/fixtures/authentic-stage1/dispatch/capture.json';x=json.loads(cap.read_text());x['result']['reason']='forged';cap.write_text(json.dumps(x));p=subprocess.run([str(ROOT/'.venv/bin/python'),str(root/'tools/replay_frozen_stage1_evidence.py'),'dispatch'],cwd=root,text=True,capture_output=True);self.assertNotEqual(p.returncode,0)
   # Changing an actually retained STOP record fails before any host fallback.
   cap.write_text((ROOT/'tests/fixtures/authentic-stage1/dispatch/capture.json').read_text());stop=root/'tests/fixtures/authentic-stage1/dispatch/repository/reports/stops/STOP-M0-001.v1.json';stop.write_text(stop.read_text()+' ');p=subprocess.run([str(ROOT/'.venv/bin/python'),str(root/'tools/replay_frozen_stage1_evidence.py'),'dispatch'],cwd=root,text=True,capture_output=True);self.assertNotEqual(p.returncode,0)
